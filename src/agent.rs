//! The Provider Agent loop.
//!
//! Runs inside the provider environment, holds the runtime credentials locally,
//! and reports normalized state upward. It never receives marketplace decision
//! logic and never exposes the Proxmox API outward.

/// **Generation and sequence, both process-scoped.**
///
/// `sequence` orders reports from one agent process. `generation` changes when
/// the process does, which is what stops Core reading a restart as a reordering:
/// a fresh agent starts at sequence 0 again, and comparing that against the last
/// sequence of the previous process would discard its first report.
///
/// Seeded from the clock rather than persisted: a monotonic counter on disk is a
/// file that can be lost, restored from a backup, or copied onto a second host,
/// and each of those makes two live agents claim one generation.
static GENERATION: std::sync::LazyLock<u64> = std::sync::LazyLock::new(|| {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
});
static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

use omnuv_protocol::{
    DesiredState, InstanceState, InstanceStatus, Lifecycle, StatusReport, WorkerState, WorkerStatus,
};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::audit;
use crate::config::AgentConfig;
use crate::driver::ComputeDriver;
use crate::proxmox;

/// What this agent tells Core it is.
///
/// **The crate version plus the commit it was built from**, because the crate
/// version alone does not move between iterations and two different binaries
/// then call themselves the same thing. On 12 September that stopped a fix
/// reaching either provider: the package carried the same `0.5.0` as the one
/// already installed, apt saw nothing to do, and the play reported success
/// while both hosts went on running the previous binary.
///
/// `OMNUV_BUILD` is set by `packaging/build-deb.sh` from `git describe`, so it
/// carries the commit and a `-dirty` marker when the tree was not clean. An
/// ordinary `cargo build` sets nothing and this reads as the bare crate
/// version, which is the honest answer for a binary nobody packaged.
const AGENT_VERSION: &str = match option_env!("OMNUV_BUILD") {
    Some(b) => b,
    None => env!("CARGO_PKG_VERSION"),
};

// Cloned rather than borrowed, and that is what lets the image mirror run off
// the reconcile path: `reqwest::Client` is an Arc around one connection pool,
// so a clone shares the pool instead of opening a second one.
#[derive(Clone)]
struct Core {
    http: reqwest::Client,
    base: String,
    token: omnuv_protocol::Redacted,
    /// The session Core minted at the last handshake, sent on every call
    /// (lifecycle phase 7, RC12). Shared by every clone and by the tunnel.
    session: crate::session::Session,
    /// This agent's head and restore mode (lifecycle phase 8, TD11): the
    /// evidence rides every call while Core has not named the restore back.
    restore: crate::restore::Shared,
    /// The run lease (lifecycle phase 12, A9): what each view answer said
    /// of it, and the leases held.
    lease: crate::lease::Shared,
    /// Which workers each recent full view sends as built (finding 6 for
    /// workers): Core's own JSON beside the protocol's fields.
    built: crate::worker::SharedBuilt,
    /// D35: the report period Core last said, and its poll, which the report
    /// task reads (`crate::report`).
    report: crate::report::Heard,
    /// Which machines are installing a recipe, written by each pass and read
    /// by the loop, which then looks again sooner than the poll
    /// (`crate::installwatch`, 3 October 2026).
    install_watch: std::sync::Arc<std::sync::Mutex<crate::installwatch::InstallWatch>>,
}

/// **Tell Core this provider is leaving (PROVIDER-16).** `onv-provider leave`
/// removed everything on the host — including the configuration holding the
/// only token that could say so — and never asked Core, which kept the
/// provider row and a valid token hash for a provider that had gone.
///
/// What Core answers decides what leave may do next:
///
/// ```text
/// 2xx   Core removed the provider; the host may be cleaned
/// 401   Core no longer knows this token; there is nothing left to tell it
/// 409   Core says the provider still holds something: drain it first
/// else  could not tell: the caller keeps the token so it can try again
/// ```
pub async fn leave_core(url: &str, token: &omnuv_protocol::Redacted, reason: &str) -> anyhow::Result<CoreLeft> {
    let core = Core::new(url, token)?;
    let r = core.post("/provider/v1/leave", Some(serde_json::json!({ "reason": reason }))).await?;
    let status = r.status();
    let body = r.text().await.unwrap_or_default();
    match status.as_u16() {
        200..=299 => Ok(CoreLeft::Removed(body)),
        401 => Ok(CoreLeft::AlreadyForgotten),
        409 => anyhow::bail!("Core refused: {body}"),
        _ => Err(CoreAnswered { path: "/provider/v1/leave".into(), status: status.as_u16() }.into()),
    }
}

/// How Core took a provider's leaving.
#[derive(Debug, PartialEq, Eq)]
pub enum CoreLeft {
    Removed(String),
    AlreadyForgotten,
}

/// Core answered, and the answer was not a success. Typed so a caller can
/// tell *Core is unwell* from *Core refuses this agent*, which used to be the
/// same string and therefore the same behaviour (PROVIDER-6).
#[derive(Debug)]
pub struct CoreAnswered {
    pub path: String,
    pub status: u16,
}

impl std::fmt::Display for CoreAnswered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} answered {}", self.path, self.status)
    }
}

impl std::error::Error for CoreAnswered {}

/// What a failed call to Core means for this agent.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Core could not be reached, or answered 5xx or 429: unwell, not a verdict.
    /// The copy in hand may be maintained, and nothing is decided.
    Unreachable,
    /// Core refused this agent's credential on an ordinary call. Nothing is
    /// maintained on instructions from a Core that no longer accepts us; the
    /// heartbeat re-handshakes, and that is where the verdict is final.
    Refused,
    /// Core no longer accepts the protocol version agreed at the last
    /// handshake (426 on an ordinary call). The agent speaks a *range*, so a
    /// new handshake may find a version both still speak — which is why this
    /// is not final (PROVIDER-23).
    Renegotiate,
    /// The handshake itself refused: 426, no common version at all, or 401,
    /// the enrollment token rejected. Nothing this process can do will change
    /// the answer, so it stops, and says why.
    Final,
    /// Any other answer: a request Core considered wrong. Decided nothing.
    Other,
}

pub fn refusal(e: &anyhow::Error) -> Refusal {
    match e.downcast_ref::<CoreAnswered>() {
        None => Refusal::Unreachable,
        Some(a) => match a.status {
            401 | 426 if a.path == HANDSHAKE => Refusal::Final,
            // **Superseded is final** (lifecycle phase 7, RC12): another
            // agent's handshake took this provider over after this one fell
            // silent past the takeover lease, and Core refuses this session
            // on every call. At the handshake, 409 is the other half — this
            // provider is held by an agent Core still hears — and is waited
            // out by the handshake's own loop, never final: the holder may be
            // this agent's previous process, whose session lapses in a lease.
            409 if a.path != HANDSHAKE => Refusal::Final,
            426 => Refusal::Renegotiate,
            401 | 403 => Refusal::Refused,
            429 | 500..=599 => Refusal::Unreachable,
            _ => Refusal::Other,
        },
    }
}

const HANDSHAKE: &str = "/provider/v1/handshake";

/// How often a handshake is tried again while another agent holds the
/// provider: a poll of a condition Core answers at once, so five seconds.
const HELD_RETRY: std::time::Duration = std::time::Duration::from_secs(5);

/// The one way this daemon ends on purpose: Core has said, finally, that it
/// will not work with this agent. Code 3, beside `main`'s 2 for configuration.
pub fn stop_for_good(e: &anyhow::Error) -> ! {
    eprintln!("stopping: {e:#}. Core will not accept this agent as it is; upgrade or re-enrol it.");
    std::process::exit(3)
}

impl Core {
    /// The agent's own transport to Omnuv Core.
    ///
    /// This is TLS, not the marketplace overlay. Control-plane traffic must not
    /// depend on the overlay: a gateway fault would make a healthy provider look
    /// offline and remove the very channel needed to repair it. The overlay
    /// exists to aggregate a *buyer's* resources across providers, and carries
    /// nothing of ours.
    ///
    /// Certificates are verified against the platform roots. `http://` is
    /// refused unless the operator sets `OMNUV_ALLOW_PLAINTEXT_CORE=1`, which
    /// exists for a LAN development loop and says so in the log.
    fn new(url: &str, token: &omnuv_protocol::Redacted) -> anyhow::Result<Self> {
        let base = url.trim_end_matches('/').to_string();
        if base.starts_with("http://") {
            let allowed = std::env::var("OMNUV_ALLOW_PLAINTEXT_CORE").is_ok_and(|v| v == "1");
            anyhow::ensure!(
                allowed,
                "core url {base} is plaintext; agent credentials and inventory would cross the \
                 network in the clear. Use https://, or set OMNUV_ALLOW_PLAINTEXT_CORE=1 for a \
                 development loop on a trusted LAN."
            );
            eprintln!("WARNING: talking to core at {base} over plaintext HTTP by explicit opt-in");
        }
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(!base.starts_with("http://"))
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self {
            http,
            base,
            token: token.clone(),
            session: Default::default(),
            restore: Default::default(),
            lease: Default::default(),
            built: Default::default(),
            report: Default::default(),
            install_watch: Default::default(),
        })
    }

    /// The same client, keeping its head in `path` (lifecycle phase 8).
    fn with_restore_head(mut self, path: std::path::PathBuf) -> Self {
        self.restore = crate::restore::load(path);
        self
    }

    /// The credential and, when Core minted one, the session: what every call
    /// to Core carries. A Core that minted none is sent no header, as before.
    fn authed(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let req = req.bearer_auth(self.token.expose());
        let req = match crate::session::current(&self.session) {
            Some(s) => req.header(crate::session::HEADER, s),
            None => req,
        };
        // A restore this agent detected and Core has not named back
        // (lifecycle phase 8, TD11): said on every call until it is.
        match crate::restore::to_tell(&self.restore) {
            Some(evidence) => req.header(crate::restore::DETECTED_HEADER, evidence.replace(['\r', '\n'], " ")),
            None => req,
        }
    }

    /// The view, with the restore Core names on it (lifecycle phase 8): the
    /// `onv-restore` header, while Core holds this provider.
    async fn get_view(&self, known: u64) -> anyhow::Result<(DesiredState, Option<String>)> {
        let path = format!("/provider/v1/desired-state?known={known}");
        // Before the request leaves: the lease counts from the ask
        // (lifecycle phase 12, A9), so a slow answer never lengthens it.
        let asked = crate::lease::Asked::now();
        let res = self
            .authed(self.http.get(format!("{}{path}", self.base)))
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await?;
        if !res.status().is_success() {
            return Err(CoreAnswered { path, status: res.status().as_u16() }.into());
        }
        let named = res.headers().get(crate::restore::HEADER).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let lease = res.headers().get(crate::lease::HEADER).and_then(|v| v.to_str().ok()).map(str::to_owned);
        // D35: Core's report period, on every view (D33).
        self.report.header(res.headers().get(crate::report::HEADER).and_then(|v| v.to_str().ok()));
        // **One body, read twice** (finding 6 for workers): as the protocol's
        // view, and for the `built` Core sends beside a worker's fields.
        let body = res.bytes().await?;
        let view: DesiredState = serde_json::from_slice(&body)?;
        if !view.unchanged {
            crate::poison::lock(&self.built, "workers sent as built").heard(view.version, crate::worker::built_workers(&body));
        }
        crate::lease::heard(&self.lease, asked, lease);
        Ok((view, named))
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let res = self
            .authed(self.http.get(format!("{}{path}", self.base)))
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await?;
        if !res.status().is_success() {
            return Err(CoreAnswered { path: path.to_string(), status: res.status().as_u16() }.into());
        }
        Ok(res.json().await?)
    }

    /// Streams a published image artefact to `dest`, hashing as the bytes
    /// arrive, and refusing to keep anything that does not match.
    ///
    /// **Never into memory.** These are several gigabytes and a `Vec<u8>` of
    /// one is how an agent dies on a provider's smallest node — the same
    /// reason Core streams it out rather than reading it in.
    ///
    /// The partial file is called `<id>.part` on purpose. Proxmox only treats
    /// `import/<name>.(ova|ovf|qcow2|raw|vmdk)` as a volume, so a download
    /// that is interrupted, or one whose digest is wrong, is not something the
    /// hypervisor can be asked to import even by mistake.
    async fn download_artefact(
        &self,
        a: &omnuv_protocol::ImageArtefact,
        dest: &std::path::Path,
        idle: std::time::Duration,
    ) -> anyhow::Result<()> {
        use futures_util::StreamExt as _;
        use sha2::Digest as _;
        use tokio::io::AsyncWriteExt as _;

        let part = dest.with_extension("part");
        if let Some(parent) = part.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // **What a previous attempt left, and whether it is still the right
        // bytes.** The filename is per image id, so a partial from before the
        // catalogue moved would be resumed onto a *different* artefact and
        // only caught by the digest at the end, after paying for the whole
        // transfer. A sidecar naming the digest it was being fetched for is
        // what makes resuming safe rather than merely fast.
        let stamp = dest.with_extension("part.sha256");
        let resumable = matches!(
            tokio::fs::read_to_string(&stamp).await,
            Ok(s) if s.trim() == a.sha256
        );
        let have: u64 = if resumable {
            tokio::fs::metadata(&part).await.map(|m| m.len()).unwrap_or(0)
        } else {
            // A partial for something else, or one with no provenance. Neither
            // is worth the risk of appending to.
            let _ = tokio::fs::remove_file(&part).await;
            0
        };
        // A partial at or beyond the published size is not a resume point; it
        // is a file that should already have been finished or discarded.
        let have = if have > 0 && have < a.bytes { have } else { 0 };
        if have == 0 {
            let _ = tokio::fs::remove_file(&part).await;
            tokio::fs::write(&stamp, &a.sha256).await?;
        }

        let mut req = self
            .authed(self.http.get(&a.url))
            // Deliberately long, and not the 30 seconds every other call uses:
            // a 6 GB transfer over a provider's uplink is not a hung request,
            // and killing it at 30 seconds would mean no image ever arrives.
            .timeout(std::time::Duration::from_secs(6 * 3600));
        if have > 0 {
            req = req.header(reqwest::header::RANGE, format!("bytes={have}-"));
        }
        let res = req.send().await?;
        anyhow::ensure!(res.status().is_success(), "GET {}: {}", a.url, res.status());

        // **206 means the server honoured the range; 200 means it ignored it
        // and is sending the whole file from zero.** Appending to a partial in
        // that case would produce a file that is too long and hashes to
        // nothing — so the answer decides, never the request.
        let appending = have > 0 && res.status() == reqwest::StatusCode::PARTIAL_CONTENT;
        if have > 0 && !appending {
            eprintln!(
                "image {}: asked to resume at {have} and the server sent the whole file; starting again",
                a.id
            );
        }

        let mut hasher = sha2::Sha256::new();
        let mut written: u64 = 0;
        if appending {
            // The hash is over the whole artefact, and a streaming digest
            // cannot be resumed — so the bytes already on disk are read back
            // through it first. That costs a local read of what was already
            // fetched, which is the cheap half of the transfer and is why
            // resuming is worth it at all.
            use tokio::io::AsyncReadExt as _;
            let mut existing = tokio::fs::File::open(&part).await?;
            let mut buf = vec![0u8; 1 << 20];
            loop {
                let n = existing.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                written += n as u64;
            }
            eprintln!("image {}: resuming at {written} of {}", a.id, a.bytes);
        }

        let mut f = if appending {
            tokio::fs::OpenOptions::new().append(true).open(&part).await?
        } else {
            tokio::fs::File::create(&part).await?
        };
        let mut stream = res.bytes_stream();

        // **A stall is not an error, and that is what wedged a provider for an
        // hour.** The six-hour budget above is a *whole-request* timeout,
        // chosen so a slow transfer is not killed. It says nothing about a
        // connection that stops sending without closing: `next()` then waits,
        // for up to six hours, and this runs on the task that also applies
        // desired state — so on 16 September a partial image sat at a fixed
        // byte count for fifty minutes while a teardown reported `reconciling`
        // eight times and a machine Core had already released went on holding
        // an RTX 3090.
        //
        // Each chunk gets its own deadline instead. Bytes must keep arriving;
        // a longer gap is a dead transfer, and the right thing to do with one
        // is abort so the next tick can start again. The gap is
        // `timings.imageTransferIdle`, two minutes unless the agent's file
        // says otherwise: how long a pause is on a provider's uplink is a
        // fact about that uplink.
        let outcome: anyhow::Result<()> = async {
            loop {
                match tokio::time::timeout(idle, stream.next()).await {
                    Err(_) => anyhow::bail!(
                        "no bytes for {}s after {written} of {}; the transfer is dead",
                        idle.as_secs(),
                        a.bytes
                    ),
                    Ok(None) => break,
                    Ok(Some(chunk)) => {
                        let chunk = chunk?;
                        hasher.update(&chunk);
                        written += chunk.len() as u64;
                        f.write_all(&chunk).await?;
                    }
                }
            }
            Ok(())
        }
        .await;

        // **The partial is kept on failure, which is the opposite of what this
        // did an hour ago and is right for the opposite reason.** When nothing
        // resumed, a leaked `.part` was pure cost: the next attempt truncated
        // it and started from zero, which is how a retry was seen going 6.67 GB
        // to 2.24 GB. Now that the next attempt asks for `bytes=<len>-`, those
        // same bytes are the thing that makes the retry cheap.
        //
        // What makes keeping it safe is the sidecar written above: a partial
        // is only ever resumed when it names the digest now being fetched. A
        // stale one is deleted rather than appended to.
        if let Err(e) = outcome {
            f.flush().await?;
            drop(f);
            eprintln!(
                "image {}: keeping {written} bytes at {} to resume from",
                a.id,
                part.display()
            );
            return Err(e);
        }

        f.flush().await?;
        drop(f);

        let got = crate::images::hex(&hasher.finalize());
        if got != a.sha256 || written != a.bytes {
            // Removed, not kept for inspection: a file that is nearly right is
            // the most dangerous thing in this directory. The sidecar goes
            // with it, so nothing later mistakes these bytes for a resume
            // point — a complete-but-wrong transfer is the one case where the
            // partial must not survive.
            let _ = tokio::fs::remove_file(&part).await;
            let _ = tokio::fs::remove_file(&stamp).await;
            anyhow::bail!(
                "{}: the marketplace published {} bytes sha256 {}; {written} bytes sha256 {got} \
                 arrived. Not imported.",
                a.id,
                a.bytes,
                a.sha256
            );
        }
        tokio::fs::rename(&part, dest).await?;
        let _ = tokio::fs::remove_file(&stamp).await;
        Ok(())
    }

    async fn delete(&self, path: &str) -> anyhow::Result<reqwest::Response> {
        Ok(self
            .authed(self.http.delete(format!("{}{path}", self.base)))
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await?)
    }

    async fn post(&self, path: &str, body: Option<serde_json::Value>) -> anyhow::Result<reqwest::Response> {
        let mut req = self
            .authed(self.http.post(format!("{}{path}", self.base)))
            .timeout(std::time::Duration::from_secs(30));
        if let Some(b) = body {
            req = req.json(&b);
        } else {
            req = req.header("content-length", "0");
        }
        Ok(req.send().await?)
    }
}

/// What the agent verifies about itself before it begins.
///
/// Connectivity, not configuration. "The Proxmox URL is set" is not a fact
/// worth printing; "the Proxmox API answered" is. Each returns a line rather
/// than aborting: a provider whose overlay is down should still register, still
/// heartbeat and still be repairable — which is the whole point of the control
/// plane not riding the overlay.
async fn startup_checks(
    cfg: &AgentConfig,
    driver: &Arc<crate::proxmox::Client>,
) -> Vec<String> {
    runtime_checks(cfg, driver).await.iter().map(check_line).collect()
}

/// **The handshake, then whether Core accepts this agent**, in that order.
///
/// Core, over TLS, and not the overlay: by design nothing here may depend on
/// it, and this check exists partly to keep that honest. It used to run
/// before the handshake, with the other start-up checks, so its heartbeat
/// carried no session; once a provider's agents hold sessions Core refuses
/// such a call with 426 (its capability floor, lifecycle phase 7), and every
/// start on Pluto and Titan printed "SELFCHECK FAILED ... answered 426 Upgrade
/// Required to an authenticated heartbeat" while the agent ran fine (found
/// 5 October 2026). After the handshake the heartbeat is the agent's own.
async fn handshake_then_core_check(
    core: &Core,
    driver: &impl ComputeDriver,
    url: &str,
    config_hash: &str,
    unreachable: &(dyn Fn() + Sync),
) -> anyhow::Result<(u64, String)> {
    let heartbeat_secs = handshake_telling(core, driver, unreachable).await?;
    Ok((heartbeat_secs, core_check(core, url, config_hash).await))
}

/// What every heartbeat says (`omnuv_protocol::Heartbeat`): which tunables this
/// agent runs, as the hash `check-config` printed for its file. So the play
/// that wrote the file can prove the running agent took it, and two agents
/// can be compared. **The self-check's heartbeat says it too**: a heartbeat
/// without it would tell Core this agent reports none, for the moment until
/// the next one.
fn heartbeat_body(config_hash: &str) -> serde_json::Value {
    serde_json::to_value(omnuv_protocol::Heartbeat { config_hash: Some(config_hash.to_string()) })
        .expect("a heartbeat serialises")
}

/// **What this agent can say about its own footing, on every report
/// (PROVIDER-24).** These were printed at start and never sent: every report
/// carried the survey's checks and nothing about whether the runtime answered
/// or Core was spoken to in plaintext. They are re-run each pass rather than
/// sent once, because Core expires a check nobody refreshes, and a runtime
/// that was down at start and is up now must stop saying so. Core being
/// reachable needs no check here: a report that arrives is that.
async fn runtime_checks(cfg: &AgentConfig, driver: &crate::proxmox::Client) -> Vec<omnuv_protocol::SelfCheck> {
    use omnuv_protocol::{CheckKind, CheckResult, SelfCheck};
    let runtime = match driver.get_json::<serde_json::Value>("/version").await {
        Ok(v) => SelfCheck {
            name: "runtime.api".into(),
            kind: CheckKind::Connectivity,
            result: CheckResult::Pass,
            detail: Some(format!(
                "proxmox api reachable (pve {})",
                v.get("version").and_then(|x| x.as_str()).unwrap_or("?")
            )),
            subject: None,
        },
        Err(e) => SelfCheck {
            name: "runtime.api".into(),
            kind: CheckKind::Connectivity,
            result: CheckResult::Fail,
            detail: Some(format!("proxmox api unreachable: {e}")),
            subject: None,
        },
    };
    // Plaintext to Core is never a shortcut that survives into a deployment.
    let plaintext = cfg.core.url.starts_with("http://");
    let tls = SelfCheck {
        name: "core.tls".into(),
        kind: CheckKind::Presence,
        result: if plaintext { CheckResult::Fail } else { CheckResult::Pass },
        detail: Some(if plaintext {
            format!("core url {} is plaintext; every control-plane hop must be TLS", cfg.core.url)
        } else {
            format!("core url {} is TLS", cfg.core.url)
        }),
        subject: None,
    };
    // The provider opening: on or off, and how many machines are opened. All
    // Core is told of it; no port, no address (`crate::opening`).
    vec![runtime, tls, driver.opening.check()]
}

/// A check as the start-up log prints it.
fn check_line(c: &omnuv_protocol::SelfCheck) -> String {
    let detail = c.detail.as_deref().unwrap_or("");
    match c.result {
        omnuv_protocol::CheckResult::Pass => format!("selfcheck: {detail}"),
        _ => format!("SELFCHECK FAILED: {detail}"),
    }
}

/// **Whether Core accepts this agent, not merely whether something answers
/// (PROVIDER-12).** This asked `/provider/v1/ping`, a route Core does not
/// have, and passed anything under 500 — so Core's 404, which comes before
/// any token is read, passed with a revoked token, and so did any HTTPS
/// server at all. The heartbeat is the smallest call Core authenticates: a
/// 2xx is Core accepting this token, a 401 or 403 is Core refusing it, and
/// anything else is not an answer from Core about this agent.
async fn core_check(core: &Core, url: &str, config_hash: &str) -> String {
    match core.post("/provider/v1/heartbeat", Some(heartbeat_body(config_hash))).await {
        Ok(r) if r.status().is_success() => format!("selfcheck: core reachable over tls at {url}, and accepts this agent"),
        Ok(r) if matches!(r.status().as_u16(), 401 | 403) => {
            format!("SELFCHECK FAILED: core at {url} refused this agent's token ({})", r.status())
        }
        Ok(r) => format!("SELFCHECK FAILED: {url} answered {} to an authenticated heartbeat", r.status()),
        Err(e) => format!("SELFCHECK FAILED: core unreachable at {url}: {e}"),
    }
}

/// The hypervisor client a configuration describes: the agent's, and the
/// host timer's (`run-lease-expire`), built the same way from the same files.
pub fn driver_of(cfg: &AgentConfig) -> anyhow::Result<proxmox::Client> {
    Ok(proxmox::Client::new(
        &cfg.proxmox.api_url,
        cfg.proxmox.tls_fingerprint_sha256.as_deref(),
        &cfg.proxmox.token_id,
        cfg.proxmox.token_secret.expose(),
        cfg.proxmox.node.clone(),
        cfg.proxmox.contribute.clone(),
        match (cfg.proxmox.latitude, cfg.proxmox.longitude) {
            (Some(latitude), Some(longitude)) => {
                Some(omnuv_protocol::GeoLocation { latitude, longitude })
            }
            _ => None,
        },
        cfg.proxmox.city.clone(),
        cfg.proxmox.apt_mirror.clone(),
    )?
    .with_images(cfg.proxmox.image_map())
    .with_windows_images(cfg.proxmox.windows_images.clone())
    .with_environment(cfg.environment.clone())
    .with_timings(cfg.timings.clone())
    // Read, never written here: the host timer builds its driver this way too.
    .with_opening(crate::opening::Book::load(&cfg.opening, crate::opening::file(&cfg.proxmox.snippet_dir))))
}

pub async fn run(cfg: AgentConfig) -> anyhow::Result<()> {
    // Shared with the image mirror's own task, which outlives no call here
    // but does outlive every reconcile pass.
    let cfg = Arc::new(cfg);
    let driver = Arc::new(driver_of(&cfg)?);
    // **The provider opening, settled at start** (`crate::opening`): off
    // releases every port, on drops the ports outside its range, and the file
    // is written either way so the applier converges on it. A start is how a
    // change of the setting arrives: deploy-agent.yml restarts the agent.
    if let Err(e) = driver.opening.settle() {
        eprintln!("opening: not settled at start, every pass retries what it writes: {e:#}");
    }
    let core = Core::new(&cfg.core.url, &cfg.core.token)?
        .with_restore_head(crate::restore::head_file(&cfg.proxmox.snippet_dir));
    // What every heartbeat says this agent runs, computed once: the file does
    // not change under a running agent, because a change is a restart (D34).
    let config_hash = cfg.timings.hash();

    // **The run lease's own task** (lifecycle phase 12, A9): beside the
    // reconcile loop, because it must act exactly when Core is unreachable,
    // and so before the handshake, which waits for Core as long as it takes.
    // It came after it until 27 September 2026: an agent restarted during a
    // partition held its machines' leases in nobody's hands. It resumes the
    // leases its predecessor wrote, and takes the lock the host timer
    // defers to.
    let leases = crate::lease::spawn(core.lease.clone(), driver.clone(), crate::lease::file(&cfg.proxmox.snippet_dir));

    // Worker id -> local endpoint, so a tunnelled request can be resolved
    // without Core ever learning this provider's addressing.
    //
    // A std mutex, not a tokio one: the resolver is a synchronous callback, and
    // `blocking_lock()` panics when called from a runtime thread. Critical
    // sections here are a map lookup.
    let endpoints: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

    // Before anything is trusted, say out loud what actually works.
    //
    // An agent that starts, finds its runtime unreachable, and simply retries
    // is an agent whose first useful signal is a buyer's endpoint failing an
    // hour later. These print at start, and the ones that can change are
    // re-run and reported on every pass (see `runtime_checks`), so a
    // misconfiguration is visible where it happened and stops being said
    // once it is fixed.
    for line in startup_checks(&cfg, &driver).await {
        println!("{line}");
    }

    // **The held view, maintained from while the handshake finds Core
    // unreachable** (omnuv's modular design, A6): starts only, gated by the
    // lease file, the kept restore bit and the view's age (`heldview`). It
    // ends before anything below decides, a pass in flight finished first.
    let (unreachable_tx, unreachable_rx) = tokio::sync::watch::channel(0u64);
    let boot = crate::heldview::spawn(
        crate::heldview::Gates {
            file: crate::heldview::file(&cfg.proxmox.snippet_dir),
            core_url: cfg.core.url.clone(),
            max_age: cfg.timings.held_view_max_age.std(),
            leases,
            lease: core.lease.clone(),
            restore: core.restore.clone(),
        },
        driver.clone(),
        unreachable_rx,
    );
    let tell = move || unreachable_tx.send_modify(|n| *n += 1);
    let shook = handshake_then_core_check(&core, &driver, &cfg.core.url, &cfg.timings.hash(), &tell).await;
    boot.finish().await;
    let (heartbeat_secs, accepted) = shook?;
    println!("{accepted}");

    // Woken by Core over the tunnel; the poll below is the safety net for when
    // no tunnel is up, so a push is never a correctness dependency.
    let nudge = Arc::new(tokio::sync::Notify::new());

    // The tunnel is how Core reaches this provider without an inbound path.
    {
        let url = cfg.core.url.clone();
        let token = cfg.core.token.clone();
        let session = core.session.clone();
        let map = endpoints.clone();
        let nudge_tx = nudge.clone();
        // Consoles are opened by the driver on the node it manages; the
        // tunnel only ever sees the runtime-neutral opener.
        let consoles: Arc<dyn crate::console::ConsoleOpener> = Arc::new(crate::console::DriverConsoles {
            driver: driver.clone(),
        });
        let keepalive = crate::tunnel::Keepalive::from(&cfg.timings);
        tokio::spawn(async move {
            let resolve: crate::tunnel::ResolveWorker = Arc::new(move |worker_id: &str| {
                // Blocking lock inside a sync closure: the map is tiny and
                // contended only by the reconcile loop.
                crate::poison::lock(&map, "worker endpoints").get(worker_id).cloned()
            });
            crate::tunnel::run(&url, &token, session, resolve, nudge_tx, consoles, keepalive).await;
        });
    }
    // The desired state the agent already holds. Keeping it lets the agent ask
    // Core with `?known=<version>` and be sent nothing when nothing changed,
    // and it is the copy it maintains from while Core is unreachable. It is
    // state the agent can always rebuild by asking again, which is the only
    // kind it is allowed to hold: the moment it kept something unrecoverable
    // it would need a database, and it would have become the second
    // orchestration store the architecture forbids.
    let held: Arc<Mutex<Option<DesiredState>>> = Arc::new(Mutex::new(None));

    // **The image mirror runs beside the reconcile loop, never inside it.**
    //
    // It was an `.await` in the middle of `reconcile_workers`, and that is a
    // seven-gigabyte transfer holding the task that also applies desired
    // state. Measured twice on 16 September: a teardown reported
    // `reconciling  waiting on 1 machine(s)` for ten passes while a healthy
    // download ran for twelve minutes, and then a *dead* one sat at
    // 6,672,056,096 bytes for fifty minutes while a machine Core had already
    // released went on holding an RTX 3090. The idle timeout fixed the second
    // case and could not fix the first, because a long download is not a
    // fault — it is work that simply does not belong on this path.
    //
    // **Coalesced by `Notify`, not queued.** A nudge that arrives while a
    // mirror is running leaves exactly one permit, so the next pass fetches
    // the catalogue as it is *then* rather than replaying every catalogue it
    // was told about in between. The desired list is a destination, and the
    // thousandth identical send means the same as the first.
    let mirror_wanted: Arc<Mutex<Vec<omnuv_protocol::ImageArtefact>>> = Arc::new(Mutex::new(Vec::new()));
    let mirror_kick = Arc::new(tokio::sync::Notify::new());
    {
        let core = core.clone();
        let driver = driver.clone();
        let cfg = cfg.clone();
        let wanted = mirror_wanted.clone();
        let kick = mirror_kick.clone();
        tokio::spawn(async move {
            loop {
                kick.notified().await;
                // Resolved each time rather than once: with no node configured
                // it is the first node online now, which may not be the one
                // that was online when the agent started (PROVIDER-7).
                let node = match driver.home_node(cfg.proxmox.node.as_deref()).await {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("image mirror: no node to mirror onto: {e:#}");
                        continue;
                    }
                };
                let catalogue = crate::poison::lock(&wanted, "image catalogue").clone();
                if catalogue.is_empty() {
                    continue;
                }
                // Logged, never propagated: an image that will not download is
                // a provider with fewer things it can earn from, and this task
                // exiting would mean it never tried again.
                if let Err(e) = mirror_images(&core, &driver, &cfg, &node, &catalogue).await {
                    eprintln!("image mirror: {e:#}");
                }
            }
        });
    }

    // **The card scrub runs beside the reconcile loop, never inside it**
    // (lifecycle phase 9), for the image mirror's reason: a scrub is a clone
    // and a boot with the driver, minutes each, and a buyer's machine must not
    // wait behind a card nobody can buy yet. Its own period,
    // `timings.scrubEvery`; its own failures, said and retried next period.
    {
        let core = core.clone();
        let driver = driver.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            let mut held = crate::scrub::Held::default();
            let mut tick = tokio::time::interval(cfg.timings.scrub_every.std());
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if let Err(e) = scrub_once(&core, &driver, &cfg, &mut held).await {
                    eprintln!("scrub: {e:#}");
                }
            }
        });
    }

    // Runtime tasks can take minutes. Their progress must not suppress the
    // liveness channel or make Core mark a working provider offline.
    let mut heartbeat = spawn_heartbeat(
        core.clone(),
        driver.clone(),
        std::time::Duration::from_secs(heartbeat_secs),
        config_hash,
    );
    // Reconciliation is push-driven; this interval is only the fallback for a
    // provider with no live tunnel.
    //
    // **Its period is Core's** (D33): Core builds how fresh a report must be,
    // and how long a check nobody repeats stays a fact, on this number, so it
    // is sent with every view (`poll_interval_secs`) and this agent keeps what
    // the last answer said. Until one says anything, and from a Core that
    // predates the field, the 120 s this always was.
    let mut core_poll: Option<u64> = None;
    let mut reconcile = tokio::time::interval(crate::timings::poll(core_poll));
    // **The report is its own task** (D35): at Core's period, and never
    // behind a reconcile pass, which can take minutes on a clone or a start.
    // Core judges this provider's silence by its reports, so a report waiting
    // on a pass would read a busy host as a silent one. It was a branch of
    // the loop below until 27 September 2026.
    let mut reports = spawn_reports(
        core.clone(),
        driver.clone(),
        cfg.proxmox.offered_images(),
        cfg.timings.inventory_every.std(),
    );
    // Push for latency, pull for truth (CLAUDE.md, *The Three Tiers*): Core
    // pushes a nudge when something changes, this interval is what makes a
    // lost nudge cost latency rather than correctness.

    // **Stopped on purpose, it lets go** (lifecycle phase 7): a deploy's
    // restart or an operator's stop releases this agent's session, so its
    // successor is not made to wait out the takeover lease. Between passes
    // only: a pass in flight finishes first.
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    // **A destroy that owes its proof asks for the next pass soon**
    // (`teardown::ProofFollowUp`), so a deleted machine's claim does not wait
    // a whole poll for the listing that proves it gone.
    let mut proofs = crate::teardown::ProofFollowUp::default();
    let mut follow_up_at: Option<tokio::time::Instant> = None;
    loop {
        tokio::select! {
            _ = terminate.recv() => {
                release_session(&core).await;
                return Ok(());
            }
            _ = tokio::signal::ctrl_c() => {
                release_session(&core).await;
                return Ok(());
            }
            ended = &mut heartbeat => {
                anyhow::bail!("heartbeat task ended unexpectedly: {ended:?}");
            }
            _ = async {
                tokio::select! {
                    _ = nudge.notified() => {}
                    _ = async {
                        match follow_up_at {
                            Some(at) => tokio::time::sleep_until(at).await,
                            None => std::future::pending().await,
                        }
                    } => {}
                }
            } => {
                if let Err(e) = reconcile_workers(&core, &driver, &cfg, &endpoints, &held, &mirror_wanted, &mirror_kick, &mut core_poll).await {
                    match refusal(&e) {
                        Refusal::Final => stop_for_good(&e),
                        Refusal::Renegotiate => {
                            eprintln!("reconcile (pushed) failed: {e:#}; re-running handshake");
                            if let Err(h) = handshake(&core, &driver).await {
                                if refusal(&h) == Refusal::Final {
                                    stop_for_good(&h);
                                }
                                eprintln!("handshake failed: {h}");
                            }
                        }
                        _ => eprintln!("reconcile (pushed) failed: {e:#}"),
                    }
                }
            }
            _ = reconcile.tick() => {
                if let Err(e) = reconcile_workers(&core, &driver, &cfg, &endpoints, &held, &mirror_wanted, &mirror_kick, &mut core_poll).await {
                    match refusal(&e) {
                        Refusal::Final => stop_for_good(&e),
                        Refusal::Renegotiate => {
                            eprintln!("reconcile failed: {e:#}; re-running handshake");
                            if let Err(h) = handshake(&core, &driver).await {
                                if refusal(&h) == Refusal::Final {
                                    stop_for_good(&h);
                                }
                                eprintln!("handshake failed: {h}");
                            }
                        }
                        _ => eprintln!("reconcile failed: {e:#}"),
                    }
                }
            }
            ended = &mut reports => {
                anyhow::bail!("report task ended unexpectedly: {ended:?}");
            }
        }
        follow_up_at = proofs
            .after_pass(crate::teardown::ProofFollowUp::owed(&crate::teardown::tombstones(&cfg.proxmox.snippet_dir)))
            .map(|wait| tokio::time::Instant::now() + wait);
        // And sooner while a recipe installs: whichever is owed first.
        let install = crate::poison::lock(&core.install_watch, "the install watch").due(tokio::time::Instant::now());
        follow_up_at = match (follow_up_at, install) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        // Re-armed, not restarted, when Core's poll moved: the first look at
        // the new period is one period away, so a change costs no extra pass.
        if let Some(period) = repoll(reconcile.period(), core_poll) {
            println!("poll: every {}s, as Core asks (was {}s)", period.as_secs(), reconcile.period().as_secs());
            reconcile = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        }
        // The report task's fallback, for a Core that says no report period,
        // is derived from the poll (`report::fallback`).
        core.report.poll(core_poll);
    }
}

/// **One look at the cards Core holds for a scrub** (lifecycle phase 9): ask
/// which, run or look at each, and report what finished. Nothing while this
/// agent is in restore mode (TD11), and nothing from a Core that predates the
/// route (404): its cards are never held for a scrub.
async fn scrub_once(
    core: &Core,
    driver: &proxmox::Client,
    cfg: &AgentConfig,
    held: &mut crate::scrub::Held,
) -> anyhow::Result<()> {
    if crate::restore::active(&core.restore) {
        return Ok(());
    }
    let wants: crate::scrub::Wants = match core.get_json(crate::scrub::PATH).await {
        Ok(w) => w,
        Err(e) if e.downcast_ref::<CoreAnswered>().is_some_and(|a| a.status == 404) => return Ok(()),
        Err(e) => return Err(e),
    };
    let storage = cfg.proxmox.contribute.storage.first().map(String::as_str).unwrap_or("local");
    let template_for = |image: &str| cfg.proxmox.template_for(image);
    let setup = crate::scrub::Setup { storage, snippet_dir: &cfg.proxmox.snippet_dir, template_for: &template_for };
    let said = driver.scrub_pass(&wants.scrubs, held, &setup).await;
    if said.is_empty() {
        return Ok(());
    }
    let res = core
        .post(crate::scrub::PATH, Some(serde_json::to_value(crate::scrub::Report { scrubs: &said })?))
        .await?;
    if !res.status().is_success() {
        return Err(CoreAnswered { path: crate::scrub::PATH.into(), status: res.status().as_u16() }.into());
    }
    let answer: crate::scrub::Answer = res.json().await?;
    for r in &answer.results {
        println!("scrub {} attempt {}: Core recorded {}", r.id, r.attempt, r.result);
    }
    held.answered(&answer.results);
    Ok(())
}

/// **The report task** (D35): the inventory, at the period Core last said
/// (`report::Heard::period`), re-armed when that moves. A survey that fails
/// or is incomplete sends nothing (`report_inventory`), and so does a Core
/// that cannot be asked: silence is the honest reading of a host that could
/// not be surveyed. Never exits on a failure: the agent is a daemon, and a
/// task that gave up would read exactly as a wedged host does.
///
/// Missed ticks are skipped, not burst: a survey slower than the period
/// reports at the next tick after it, never several back to back.
fn spawn_reports<D: ComputeDriver + Send + Sync + 'static>(
    core: Core,
    driver: Arc<D>,
    offered_images: Vec<String>,
    inventory_every: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let arm = |period: std::time::Duration, first: tokio::time::Instant| {
            let mut tick = tokio::time::interval_at(first, period);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            tick
        };
        let mut tick = arm(core.report.period(inventory_every), tokio::time::Instant::now());
        loop {
            tick.tick().await;
            if let Err(e) = report_inventory(&core, driver.as_ref(), offered_images.clone()).await {
                eprintln!("inventory report not sent: {e:#}");
            }
            let every = core.report.period(inventory_every);
            if every != tick.period() {
                let whose = if core.report.said() { "as Core asks" } else { "Core says no period: this agent's own" };
                println!("inventory: every {}s, {whose} (was {}s)", every.as_secs(), tick.period().as_secs());
                tick = arm(every, tokio::time::Instant::now() + every);
            }
        }
    })
}

/// The reconcile interval to keep, given what Core's last answer said; `None`
/// when the one running is already it.
fn repoll(current: std::time::Duration, said: Option<u64>) -> Option<std::time::Duration> {
    let wanted = crate::timings::poll(said);
    (wanted != current).then_some(wanted)
}

/// The heartbeat period Core asked for, in seconds.
///
/// **Zero is "not said", like absent (24 September 2026).** `tokio::time::interval`
/// panics on a zero period, and the heartbeat task took Core's number with only
/// a default for its absence, so a Core answering 0 killed the task and the
/// agent with it. A value this agent cannot use is not a reason to stop.
fn heartbeat_secs(handshake: &serde_json::Value) -> u64 {
    handshake
        .get("heartbeat_interval_secs")
        .and_then(|x| x.as_u64())
        .filter(|s| *s > 0)
        .unwrap_or(30)
}

fn spawn_heartbeat<D: ComputeDriver + Send + Sync + 'static>(
    core: Core,
    driver: Arc<D>,
    period: std::time::Duration,
    config_hash: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let body = heartbeat_body(&config_hash);
        loop {
            tick.tick().await;
            match core.post("/provider/v1/heartbeat", Some(body.clone())).await {
                // **426 is renegotiated, not obeyed (PROVIDER-23).** Core's
                // floor rose past the version agreed last time; a new
                // handshake finds the highest version both still speak, and
                // only a refusal *there* is final.
                Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED
                    || r.status() == reqwest::StatusCode::UPGRADE_REQUIRED =>
                {
                    eprintln!("heartbeat refused ({}); re-running handshake", r.status());
                    if let Err(e) = handshake(&core, &driver).await {
                        if refusal(&e) == Refusal::Final {
                            stop_for_good(&e);
                        }
                        eprintln!("heartbeat handshake failed: {e:#}");
                    }
                }
                // Superseded (RC12): another agent holds this provider now.
                // Final, as on any other call.
                Ok(r) if r.status() == reqwest::StatusCode::CONFLICT => {
                    stop_for_good(&anyhow::Error::from(CoreAnswered {
                        path: "/provider/v1/heartbeat".into(),
                        status: 409,
                    }).context("another agent's handshake superseded this agent's session"));
                }
                Ok(r) if !r.status().is_success() => eprintln!("heartbeat: {}", r.status()),
                Err(e) => eprintln!("heartbeat failed: {e:#}"),
                _ => {}
            }
        }
    })
}

/// **Core's view, read again just before a start** of a machine or worker
/// already built (the phase 7 follow-up; G_reread for a start, beside the
/// build's `still_wanted` and the destroy's `still_absent`). Only a fresh view
/// that still names the id Running starts it: Stopped, Absent, gone from the
/// view, a view older than the one held, a restore, or a Core that could not
/// be asked all start nothing. Awaited only when a start is about to be asked.
async fn still_running(core: &Core, held: &Arc<Mutex<Option<DesiredState>>>, id: &str) -> anyhow::Result<bool> {
    Ok(intent_now(core, held, id).await? == Some(Lifecycle::Running))
}

/// Why a pass's observation does not cover everything it was asked about:
/// one line per kind that had items the agent could not read or act on.
fn incompleteness(
    unobserved_instances: usize,
    instances: usize,
    unobserved_workers: usize,
    workers: usize,
) -> Vec<String> {
    let mut out = Vec::new();
    if unobserved_instances > 0 {
        out.push(format!("{unobserved_instances} of {instances} desired instances could not be observed"));
    }
    if unobserved_workers > 0 {
        out.push(format!("{unobserved_workers} of {workers} desired workers could not be observed"));
    }
    out
}

/// Whether this agent can act on a payload stamped with protocol `v`.
///
/// **A range, the one the handshake negotiates in, not one number.** This
/// demanded exactly `PROTOCOL_VERSION`, while Core stamped its own; so an agent
/// and a Core one version apart agreed a version at the handshake and then
/// disagreed on every desired state. Core now stamps the agreed version, and
/// this accepts anything the handshake could have agreed.
fn speaks(v: u32) -> bool {
    (omnuv_protocol::MINIMUM_PROTOCOL_VERSION..=omnuv_protocol::PROTOCOL_VERSION).contains(&v)
}

#[cfg(test)]
mod handshake_tests {

    /// **PROVIDER-16: what Core answers decides whether leave may go on.**
    /// Real exchanges: the request is a POST to the leave route carrying the
    /// operator's reason; removed and already-forgotten let leave continue; a
    /// refusal carries Core's own sentence; anything else is "could not tell",
    /// which keeps the token.
    #[tokio::test]
    async fn leaving_asks_core_first_and_reads_its_answer() {
        // SAFETY: as in the test above — set once, to the same value.
        unsafe { std::env::set_var("OMNUV_ALLOW_PLAINTEXT_CORE", "1") };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ask = |status: u16, body: serde_json::Value| async move {
            let mock = crate::pvemock::Mock::start(move |_, _, _| (status, body.clone())).await;
            let token = omnuv_protocol::Redacted::from("t".to_string());
            let said = leave_core(&format!("{}/api2/json", mock.base), &token, "going").await;
            let calls = mock.calls.lock().unwrap().clone();
            (said, calls)
        };

        let (said, calls) = ask(200, serde_json::json!({"archived": 3})).await;
        assert!(matches!(said, Ok(CoreLeft::Removed(_))), "{said:?}");
        assert_eq!(calls.len(), 1);
        assert_eq!((calls[0].method.as_str(), calls[0].path.as_str()), ("POST", "/provider/v1/leave"));
        assert!(calls[0].body.contains("\"reason\":\"going\""), "the reason was not sent: {}", calls[0].body);

        let (said, _) = ask(401, serde_json::Value::Null).await;
        assert_eq!(said.unwrap(), CoreLeft::AlreadyForgotten);

        let (said, _) = ask(409, serde_json::json!("this provider still holds 1 machine(s)")).await;
        let e = said.expect_err("a refusal").to_string();
        assert!(e.contains("still holds 1 machine"), "Core's own sentence was lost: {e}");

        let (said, _) = ask(503, serde_json::Value::Null).await;
        assert!(said.is_err(), "an unwell Core was taken as having been told");
    }
    /// **PROVIDER-6: an outage is not a verdict.** Each answer, as `get_json`
    /// actually returns it from a real HTTP exchange, classified — and a
    /// connection nobody accepts, which is the one real outage. Only the
    /// outage lets the agent maintain on its stale copy; only the two final
    /// answers stop it.
    #[tokio::test]
    async fn only_an_outage_is_maintained_through_and_only_a_final_answer_stops() {
        // SAFETY: set once, before any client is built, and only ever to the
        // same value; no test here asserts plaintext is refused.
        unsafe { std::env::set_var("OMNUV_ALLOW_PLAINTEXT_CORE", "1") };
        // What `main` does at startup, for the same reason the mock's client does.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let token = omnuv_protocol::Redacted::from("t".to_string());
        for (status, path, want) in [
            (503u16, "/provider/v1/desired-state", Refusal::Unreachable),
            (429, "/provider/v1/desired-state", Refusal::Unreachable),
            (401, "/provider/v1/desired-state", Refusal::Refused),
            (403, "/provider/v1/desired-state", Refusal::Refused),
            (426, "/provider/v1/desired-state", Refusal::Renegotiate),
            (426, HANDSHAKE, Refusal::Final),
            (404, "/provider/v1/desired-state", Refusal::Other),
            (401, HANDSHAKE, Refusal::Final),
            // Lifecycle phase 7 (RC12): superseded is final; a provider held
            // by another agent at the handshake is waited out, never final.
            (409, "/provider/v1/desired-state", Refusal::Final),
            (409, HANDSHAKE, Refusal::Other),
        ] {
            let mock = crate::pvemock::Mock::start(move |_, _, _| (status, serde_json::Value::Null)).await;
            // The mock serves under /api2/json; Core's paths are asked of its root.
            let core = Core::new(&format!("{}/api2/json", mock.base), &token).expect("a client");
            let e = core.get_json::<serde_json::Value>(path).await.expect_err("a refusal");
            assert_eq!(refusal(&e), want, "{status} on {path}: {e}");
        }
        // Nothing listening: the one genuine outage.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let core = Core::new(&format!("http://{closed}"), &token).expect("a client");
        let e = core.get_json::<serde_json::Value>("/provider/v1/desired-state").await.expect_err("refused");
        assert_eq!(refusal(&e), Refusal::Unreachable, "{e}");
    }

    #[test]
    fn an_error_result_makes_the_observation_incomplete() {
        assert!(super::incompleteness(0, 3, 0, 1).is_empty(), "every item observed");
        let why = super::incompleteness(1, 3, 0, 1);
        assert_eq!(why, vec!["1 of 3 desired instances could not be observed".to_string()]);
        assert_eq!(super::incompleteness(0, 0, 2, 2).len(), 1);
    }

    #[test]
    fn a_payload_in_the_negotiated_range_is_accepted() {
        use super::speaks;
        assert!(speaks(omnuv_protocol::PROTOCOL_VERSION));
        assert!(speaks(omnuv_protocol::MINIMUM_PROTOCOL_VERSION));
        assert!(!speaks(omnuv_protocol::MINIMUM_PROTOCOL_VERSION - 1));
        assert!(!speaks(omnuv_protocol::PROTOCOL_VERSION + 1));
    }

    use super::*;

    struct HeartbeatDriver;

    impl ComputeDriver for HeartbeatDriver {
        fn kind(&self) -> omnuv_protocol::RuntimeKind {
            omnuv_protocol::RuntimeKind::Proxmox
        }

        async fn inventory(&self, _: &DesiredState) -> anyhow::Result<omnuv_protocol::InventoryReport> {
            anyhow::bail!("heartbeat must not wait for runtime inventory")
        }
    }

    /// **PROVIDER-24: the checks a report carries.** The runtime answering
    /// and not answering, and a Core URL in plaintext and not: each is a
    /// named check with its result, so Core can show it and see it change.
    #[tokio::test]
    async fn every_report_says_whether_the_runtime_answers_and_core_is_tls() {
        use omnuv_protocol::CheckResult;
        let config = |url: &str| -> crate::config::AgentConfig {
            serde_yaml_ng::from_str(&format!(
                "core:\n  url: {url}\n  token: t\nproxmox:\n  apiUrl: https://127.0.0.1:8006\n  tokenId: onv@pve!agent\n  tokenSecret: s\n"
            ))
            .expect("config")
        };
        let up = crate::pvemock::Mock::start(|_, path, _| match path {
            "/version" => (200, serde_json::json!({"version": "9.2.20"})),
            _ => (404, serde_json::Value::Null),
        })
        .await;
        let down = crate::pvemock::Mock::start(|_, _, _| (500, serde_json::Value::Null)).await;
        let find = |checks: &[omnuv_protocol::SelfCheck], name: &str| {
            checks.iter().find(|c| c.name == name).map(|c| c.result).unwrap_or_else(|| panic!("no {name} in {checks:?}"))
        };

        let good = runtime_checks(&config("https://api.test.omnuv.com"), &up.client()).await;
        assert_eq!(find(&good, "runtime.api"), CheckResult::Pass);
        assert_eq!(find(&good, "core.tls"), CheckResult::Pass);

        let bad = runtime_checks(&config("http://api.test.omnuv.com"), &down.client()).await;
        assert_eq!(find(&bad, "runtime.api"), CheckResult::Fail, "an unreachable runtime was reported as working");
        assert_eq!(find(&bad, "core.tls"), CheckResult::Fail, "a plaintext Core url passed");
    }

    /// **The lease task runs while the handshake waits for Core** (lifecycle
    /// phase 12): an agent restarted during a partition holds the lock the
    /// host timer defers to, and its first pass writes back the lease its
    /// predecessor left, rather than nothing. It was spawned after the
    /// handshake until 27 September 2026, which waits as long as Core is
    /// unreachable: a restart handed the leases to nobody.
    #[tokio::test]
    async fn the_lease_task_runs_while_the_handshake_waits_for_core() {
        use std::time::Duration;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pve = crate::pvemock::Mock::start(|_, path, _| match path {
            "/version" => (200, serde_json::json!({"version": "9.2.20"})),
            _ => (404, serde_json::Value::Null),
        })
        .await;
        // A port nothing listens on: every call to Core is refused.
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let dir = tempfile::tempdir().expect("a directory");
        let file = dir.path().join("run-lease.json");
        let until = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 600;
        std::fs::write(&file, serde_json::json!({"leases": [{"id": "m1", "until_unix": until}]}).to_string()).unwrap();
        let before = std::time::SystemTime::now() - Duration::from_secs(600);
        std::fs::File::options().write(true).open(&file).unwrap().set_modified(before).unwrap();
        let cfg: AgentConfig = serde_yaml_ng::from_str(&format!(
            "core:\n  url: https://127.0.0.1:{port}\n  token: t\nproxmox:\n  apiUrl: {}\n  tokenId: onv@pve!agent\n  \
             tokenSecret: s\n  tlsFingerprintSha256: \"{}\"\n  snippetDir: {}\n",
            pve.base,
            "AB".repeat(32),
            dir.path().join("snippets").display()
        ))
        .expect("config");
        let agent = tokio::spawn(run(cfg));

        let probe = crate::lease::open_lock(&crate::lease::lock_file(&file)).unwrap();
        let (mut held, mut rewritten) = (false, false);
        for _ in 0..500 {
            if !held {
                match probe.try_lock() {
                    Err(std::fs::TryLockError::WouldBlock) => held = true,
                    Ok(()) => probe.unlock().unwrap(),
                    Err(std::fs::TryLockError::Error(e)) => panic!("the lock could not be tried: {e}"),
                }
            }
            rewritten = std::fs::metadata(&file).unwrap().modified().unwrap() > before + Duration::from_secs(60);
            if held && rewritten {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!agent.is_finished(), "the agent ended instead of waiting for Core");
        agent.abort();
        assert!(held, "no lease task held the lock while the handshake waited for Core");
        assert!(rewritten, "no lease task wrote the file while the handshake waited for Core");
        let leases = crate::lease::read_body(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(leases, [crate::lease::Written { id: "m1".into(), until_unix: until }], "the lease was not resumed");
    }

    /// **A restarted agent that cannot reach Core maintains from the held
    /// view it kept** (omnuv's modular design, A6). Core is a port nothing
    /// listens on, so the handshake never succeeds. The host holds a
    /// run-lease file and a held view a minute old naming five stopped
    /// machines: Running under a lease, Running with its lease run out,
    /// Running with none, Stopped, Absent. The two Running within their lease
    /// are started; nothing else on the hypervisor is touched: no stop, no
    /// delete, no create. Before A6 the view was in memory only, and this
    /// agent started nothing until Core answered.
    #[tokio::test]
    async fn a_restart_that_cannot_reach_core_starts_its_held_machines_and_nothing_else() {
        use crate::names::{TAG_INSTANCE as TAG, description, short_tag};
        use std::time::Duration;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ids = [
            ("aaaaaaaa-1111-4111-8111-111111111111", Lifecycle::Running), // under a lease
            ("aaaaaaaa-2222-4222-8222-222222222222", Lifecycle::Running), // its lease run out
            ("aaaaaaaa-3333-4333-8333-333333333333", Lifecycle::Running), // no lease
            ("aaaaaaaa-4444-4444-8444-444444444444", Lifecycle::Stopped),
            ("aaaaaaaa-5555-4555-8555-555555555555", Lifecycle::Absent),
        ];
        let guests: Vec<(u32, String, String)> =
            ids.iter().enumerate().map(|(n, (id, _))| (800 + n as u32, short_tag(id), description(TAG, id))).collect();
        let pve = crate::pvemock::Mock::start(move |method, path, _| {
            if let Some(r) = crate::pvemock::task_ok(path) {
                return r;
            }
            if (method, path) == ("GET", "/version") {
                return (200, serde_json::json!({"version": "9.2.20"}));
            }
            if (method, path) == ("GET", "/cluster/resources?type=vm") {
                let list: Vec<_> = guests
                    .iter()
                    .map(|(vmid, tag, _)| serde_json::json!({"node": "n1", "vmid": vmid, "status": "stopped", "tags": format!("{TAG};{tag}")}))
                    .collect();
                return (200, serde_json::Value::Array(list));
            }
            for (vmid, _, stamp) in &guests {
                if path == format!("/nodes/n1/qemu/{vmid}/status/current") {
                    return (200, serde_json::json!({"status": "stopped"}));
                }
                if method == "GET" && path == format!("/nodes/n1/qemu/{vmid}/config") {
                    return (200, serde_json::json!({"description": stamp}));
                }
                if method == "POST" && path == format!("/nodes/n1/qemu/{vmid}/status/start") {
                    return (200, serde_json::json!(format!("UPID:n1:start:{vmid}")));
                }
            }
            crate::pvemock::gate_clear(method, path).unwrap_or((404, serde_json::Value::Null))
        })
        .await;
        // A port nothing listens on: every call to Core is refused.
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let core_url = format!("https://127.0.0.1:{port}");
        let dir = tempfile::tempdir().expect("a directory");
        let now = std::time::SystemTime::now();
        let unix = now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        std::fs::write(
            dir.path().join("run-lease.json"),
            serde_json::json!({"leases": [{"id": ids[0].0, "until_unix": unix + 600}, {"id": ids[1].0, "until_unix": unix - 10}]})
                .to_string(),
        )
        .unwrap();
        let view = DesiredState {
            protocol_version: omnuv_protocol::PROTOCOL_VERSION,
            version: 7,
            unchanged: false,
            inference_workers: vec![],
            instances: ids
                .iter()
                .map(|(id, intent)| omnuv_protocol::InstanceSpec { id: id.to_string(), intent: *intent, ..Default::default() })
                .collect(),
            images: vec![],
            poll_interval_secs: None,
        };
        crate::heldview::write(&dir.path().join("held-view.json"), &crate::heldview::of(&core_url, &view, now - Duration::from_secs(60)));
        let cfg: AgentConfig = serde_yaml_ng::from_str(&format!(
            "core:\n  url: {core_url}\n  token: t\nproxmox:\n  apiUrl: {}\n  tokenId: onv@pve!agent\n  \
             tokenSecret: s\n  tlsFingerprintSha256: \"{}\"\n  snippetDir: {}\n",
            pve.base,
            "AB".repeat(32),
            dir.path().join("snippets").display()
        ))
        .expect("config");
        let agent = tokio::spawn(run(cfg));

        let start = |n: u32| format!("POST /nodes/n1/qemu/{}/status/start", 800 + n);
        let acts = || -> Vec<String> {
            let calls = pve.calls.lock().unwrap();
            let mut a: Vec<String> = calls.iter().filter(|c| c.method != "GET").map(|c| format!("{} {}", c.method, c.path)).collect();
            a.sort();
            a
        };
        // Bounded: the first handshake fails at once, and the pass is a few
        // loopback reads. Ten seconds is padding over that, never a wait.
        let mut started = false;
        for _ in 0..500 {
            let a = acts();
            if a.contains(&start(0)) && a.contains(&start(2)) {
                started = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!agent.is_finished(), "the agent ended instead of waiting for Core");
        agent.abort();
        assert!(started, "the held machines were not started while Core was unreachable: {:?}", acts());
        // The pass looks at its machines in the view's order and the last one
        // started is the last Running one, so nothing is still to come; and
        // every later pass meets the same machines, which a start does not
        // move in this mock, so a second start of them is allowed and nothing
        // else is.
        let others: Vec<String> = acts().into_iter().filter(|a| *a != start(0) && *a != start(2)).collect();
        assert_eq!(others, Vec::<String>::new(), "the boot path did more than start the held machines");
    }

    /// **PROVIDER-12: the self-check is Core accepting this token.** A 204
    /// passes; a 401 says the token was refused; a 404 — a server that does
    /// not know the route, which is what every answer to the old ping was —
    /// fails. And the request is the authenticated heartbeat.
    /// One HTTP request off a socket, head and body. **The body too**, since
    /// the heartbeat carries one: a server that answers and closes with bytes
    /// still unread makes the kernel reset the connection, and the client
    /// then reads the reset instead of the answer.
    async fn read_request(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
        let mut request = Vec::new();
        loop {
            let mut bytes = [0; 4096];
            let n = socket.read(&mut bytes).await.unwrap();
            assert!(n > 0 && request.len() + n < 65_536, "the client closed or sent too much");
            request.extend_from_slice(&bytes[..n]);
            if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&request[..end]).to_lowercase();
                let length = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if request.len() >= end + 4 + length {
                    return request;
                }
            }
        }
    }

    /// A Core that answers each call from `answer(line, handshakes so far)`
    /// and hands every request's head and body to the test.
    async fn session_stub(
        answer: impl Fn(&str, usize) -> (&'static str, String) + Send + Sync + 'static,
    ) -> (String, tokio::sync::mpsc::UnboundedReceiver<(String, String)>) {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let answer = Arc::new(answer);
        let handshakes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let (answer, tx, handshakes) = (answer.clone(), tx.clone(), handshakes.clone());
                tokio::spawn(async move {
                    let request = read_request(&mut socket).await;
                    let text = String::from_utf8_lossy(&request).to_string();
                    let head = text.split("\r\n\r\n").next().unwrap_or_default().to_lowercase();
                    let line = text.lines().next().unwrap_or_default().to_string();
                    let n = if line.starts_with("POST /provider/v1/handshake") {
                        handshakes.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    } else {
                        handshakes.load(std::sync::atomic::Ordering::SeqCst)
                    };
                    let (status, body) = answer(&line, n);
                    let response = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = tx.send((head, body_of(&request)));
                });
            }
        });
        (base, rx)
    }

    /// A survey that completes, or one that does not (D35).
    struct Survey {
        complete: bool,
    }

    impl ComputeDriver for Survey {
        fn kind(&self) -> omnuv_protocol::RuntimeKind {
            omnuv_protocol::RuntimeKind::Proxmox
        }

        async fn inventory(&self, _: &DesiredState) -> anyhow::Result<omnuv_protocol::InventoryReport> {
            anyhow::ensure!(self.complete, "the survey is incomplete, so nothing is reported (D35): a listing failed");
            Ok(serde_json::from_value(serde_json::json!({
                "protocol_version": omnuv_protocol::PROTOCOL_VERSION,
                "runtime": omnuv_protocol::RuntimeKind::Proxmox,
                "capabilities": omnuv_protocol::ComputeCapabilities::default(),
                "nodes": [],
            }))?)
        }
    }

    /// **D35: a report goes only from a completed survey, from its own task.**
    /// Against a Core that says no period (the fallback, here 200 ms), with no
    /// reconcile loop running at all: a host whose survey completes is
    /// reported every period, each report after a full view; one whose survey
    /// never completes asks for the view every period and reports nothing,
    /// so Core hears it only through its heartbeats and, judging by reports,
    /// finds it silent.
    #[tokio::test]
    async fn a_report_goes_only_from_a_completed_survey_from_its_own_task() {
        // SAFETY: set once, to the same value every test here sets.
        unsafe { std::env::set_var("OMNUV_ALLOW_PLAINTEXT_CORE", "1") };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let view = format!(r#"{{"protocol_version":{},"version":3,"unchanged":false,"instances":[]}}"#, omnuv_protocol::PROTOCOL_VERSION);
        for complete in [true, false] {
            let view = view.clone();
            let (base, mut rx) = session_stub(move |line, _| {
                if line.starts_with("GET /provider/v1/desired-state") {
                    return ("200 OK", view.clone());
                }
                ("200 OK", "{}".into())
            })
            .await;
            let core = Core::new(&base, &omnuv_protocol::Redacted::from("t".to_string())).unwrap();
            assert!(!core.report.said(), "the stub Core said a period");
            let task = spawn_reports(core, Arc::new(Survey { complete }), vec![], std::time::Duration::from_millis(200));
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await; // wait: counting ticks of a 200 ms period
            task.abort();
            let (mut views, mut reports) = (0, 0);
            while let Ok((head, _)) = rx.try_recv() {
                views += usize::from(head.starts_with("get /provider/v1/desired-state"));
                reports += usize::from(head.starts_with("post /provider/v1/inventory"));
            }
            assert!(views >= 4, "complete={complete}: the survey was asked for {views} times in 1.1 s at 200 ms");
            if complete {
                assert_eq!(reports, views, "a completed survey went unreported");
            } else {
                assert_eq!(reports, 0, "an incomplete survey was reported");
            }
        }
    }

    /// **The period is Core's, from the handshake**, before any view: the
    /// agent advertises the capability and keeps what the answer said.
    #[tokio::test]
    async fn the_handshake_s_report_period_is_kept() {
        // SAFETY: as above.
        unsafe { std::env::set_var("OMNUV_ALLOW_PLAINTEXT_CORE", "1") };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (base, mut rx) = session_stub(|_, _| {
            ("200 OK", r#"{"provider_id":"p","protocol_version":6,"heartbeat_interval_secs":30,"report_interval_secs":45}"#.into())
        })
        .await;
        let core = Core::new(&base, &omnuv_protocol::Redacted::from("t".to_string())).unwrap();
        handshake(&core, &HeartbeatDriver).await.expect("the handshake");
        let (_, body) = rx.recv().await.unwrap();
        let said: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(said["capabilities"].as_array().unwrap().contains(&serde_json::json!("report-interval")), "{body}");
        assert_eq!(core.report.period(std::time::Duration::from_secs(300)), std::time::Duration::from_secs(45));
    }

    /// **The start-up check asks Core after the handshake**, so its heartbeat
    /// carries the session: a Core that refuses a call without one (426, a
    /// provider whose agents hold sessions) accepts this agent, and the check
    /// says so (5 October 2026).
    #[tokio::test]
    async fn the_core_check_follows_the_handshake() {
        use tokio::io::AsyncWriteExt;
        // SAFETY: set once, to the same value every test here sets.
        unsafe { std::env::set_var("OMNUV_ALLOW_PLAINTEXT_CORE", "1") };
        let _ = rustls::crypto::ring::default_provider().install_default();
        // Core as production answers with sessions on: a heartbeat without
        // the session header is 426.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                tokio::spawn(async move {
                    let request = String::from_utf8_lossy(&read_request(&mut socket).await).to_string();
                    let head = request.split("\r\n\r\n").next().unwrap_or_default().to_lowercase();
                    let (status, body) = if head.starts_with("post /provider/v1/handshake") {
                        ("200 OK", r#"{"provider_id":"p","protocol_version":6,"heartbeat_interval_secs":30,"session":"s-1"}"#)
                    } else if head.contains(&format!("{}:", crate::session::HEADER.to_lowercase())) {
                        ("200 OK", "{}")
                    } else {
                        ("426 Upgrade Required", "\"this call carries no session\"")
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
        let core = Core::new(&base, &omnuv_protocol::Redacted::from("t".to_string())).unwrap();
        // Before the handshake, the check is refused, as every start was.
        assert!(core_check(&core, &base, "0123456789ab").await.contains("426"));
        let (_, said) = handshake_then_core_check(&core, &HeartbeatDriver, &base, "0123456789ab", &|| {}).await.expect("the handshake");
        assert!(said.contains("accepts this agent"), "{said}");
    }

    /// **A held provider is waited for, and the session rides every call**
    /// (lifecycle phase 7, RC12). The first handshake meets a provider held
    /// by another agent (409) and is tried again rather than given up; the
    /// second is answered with a session, and every later call — a view, a
    /// heartbeat — carries it. The handshake advertised what this agent can do.
    #[tokio::test]
    async fn a_held_provider_is_waited_for_and_the_session_rides_every_call() {
        // SAFETY: set once, to the same value every test here sets.
        unsafe { std::env::set_var("OMNUV_ALLOW_PLAINTEXT_CORE", "1") };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (base, mut rx) = session_stub(|line, handshakes| {
            if line.starts_with("POST /provider/v1/handshake") {
                if handshakes == 0 {
                    return ("409 Conflict", "\"another agent holds this provider\"".into());
                }
                return ("200 OK", r#"{"provider_id":"p","protocol_version":6,"heartbeat_interval_secs":30,"session":"s-1"}"#.into());
            }
            ("200 OK", "{}".into())
        })
        .await;
        let core = Core::new(&base, &omnuv_protocol::Redacted::from("t".to_string())).unwrap();
        handshake(&core, &HeartbeatDriver).await.expect("the second handshake is accepted");
        let (first, body) = rx.recv().await.unwrap();
        assert!(!first.contains("onv-session"), "a session was sent before Core minted one: {first}");
        let said: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(said["capabilities"], serde_json::json!(crate::session::CAPABILITIES), "{body}");
        assert!(crate::session::CAPABILITIES.contains(&"session"));
        let (second, _) = rx.recv().await.unwrap();
        assert!(second.starts_with("post /provider/v1/handshake"), "the held provider was not waited for: {second}");

        core.get_json::<serde_json::Value>("/provider/v1/desired-state").await.expect("a view");
        let (view, _) = rx.recv().await.unwrap();
        assert!(view.contains("\r\nonv-session: s-1"), "the view was asked without the session: {view}");
        core.post("/provider/v1/heartbeat", Some(heartbeat_body("abcdefabcdef"))).await.expect("a heartbeat");
        let (beat, _) = rx.recv().await.unwrap();
        assert!(beat.contains("\r\nonv-session: s-1"), "the heartbeat went without the session: {beat}");
    }

    /// **The view read again before an act** (G_reread, G_viewMonotone). A
    /// fresh full view decides; an unchanged one leaves the view held; a full
    /// answer older than the view held decides nothing, whatever it says.
    #[tokio::test]
    async fn an_act_waits_on_a_fresh_view_and_never_an_older_one() {
        // SAFETY: as above.
        unsafe { std::env::set_var("OMNUV_ALLOW_PLAINTEXT_CORE", "1") };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let view = |version: u64, intent: &str| {
            format!(
                r#"{{"protocol_version":6,"version":{version},"unchanged":false,"instances":[{{"id":"m","lifecycle":"{intent}","name":"m","vcpus":1,"memory_mib":512,"disk_gib":8}}]}}"#
            )
        };
        let held_at = |version: u64, intent: Lifecycle| {
            let mut spec = omnuv_protocol::InstanceSpec { id: "m".into(), name: "m".into(), vcpus: 1, memory_mib: 512, disk_gib: 8, ..Default::default() };
            spec.intent = intent;
            Arc::new(Mutex::new(Some(DesiredState {
                protocol_version: 6,
                version,
                unchanged: false,
                inference_workers: vec![],
                instances: vec![spec],
                images: vec![],
                poll_interval_secs: None,
            })))
        };
        for (answer, held, want_absent, want_wanted, why) in [
            (view(8, "deleted"), held_at(7, Lifecycle::Running), true, false, "a newer view saying Absent"),
            (view(8, "running"), held_at(7, Lifecycle::Absent), false, true, "a newer view wanting it again"),
            (view(6, "deleted"), held_at(7, Lifecycle::Running), false, false, "an older view (G_viewMonotone)"),
            (r#"{"protocol_version":6,"version":7,"unchanged":true}"#.to_string(), held_at(7, Lifecycle::Running), false, true, "unchanged: the view held"),
            (view(8, "running").replace(r#""disk_gib":8"#, r#""disk_gib":8,"built":true"#), held_at(7, Lifecycle::Running), false, false,
             "a newer view saying built (finding 7, G_rereadBuilt)"),
        ] {
            let (base, _rx) = session_stub(move |_, _| ("200 OK", answer.clone())).await;
            let core = Core::new(&base, &omnuv_protocol::Redacted::from("t".to_string())).unwrap();
            assert_eq!(still_absent(&core, &held, "m").await.unwrap(), want_absent, "{why}: still_absent");
            assert_eq!(still_wanted(&core, &held, "m").await.unwrap(), want_wanted, "{why}: still_wanted");
        }
    }

    /// **An agent that stops lets go** (lifecycle phase 7): with a session,
    /// the release is a DELETE carrying it; without one, nothing is sent.
    #[tokio::test]
    async fn an_agent_that_stops_releases_its_session_and_only_its_own() {
        // SAFETY: as above.
        unsafe { std::env::set_var("OMNUV_ALLOW_PLAINTEXT_CORE", "1") };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (base, mut rx) = session_stub(|line, _| {
            if line.starts_with("POST /provider/v1/handshake") {
                return ("200 OK", r#"{"provider_id":"p","protocol_version":6,"heartbeat_interval_secs":30,"session":"s-9"}"#.into());
            }
            ("204 No Content", String::new())
        })
        .await;
        let core = Core::new(&base, &omnuv_protocol::Redacted::from("t".to_string())).unwrap();
        release_session(&core).await;
        handshake(&core, &HeartbeatDriver).await.expect("accepted");
        let (first, _) = rx.recv().await.unwrap();
        assert!(first.starts_with("post /provider/v1/handshake"), "something was sent before the handshake: {first}");
        release_session(&core).await;
        let (release, _) = rx.recv().await.unwrap();
        assert!(release.starts_with("delete /provider/v1/session"), "{release}");
        assert!(release.contains("\r\nonv-session: s-9"), "the release did not name the session: {release}");
    }

    /// **Against an old Core, no session is sent** (mixed versions). A Core
    /// that predates sessions, or runs them switched off, answers the
    /// handshake without one: this agent then calls exactly as it did before.
    #[tokio::test]
    async fn against_a_core_that_mints_no_session_none_is_sent() {
        // SAFETY: as above.
        unsafe { std::env::set_var("OMNUV_ALLOW_PLAINTEXT_CORE", "1") };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (base, mut rx) = session_stub(|line, _| {
            if line.starts_with("POST /provider/v1/handshake") {
                return ("200 OK", r#"{"provider_id":"p","protocol_version":6,"heartbeat_interval_secs":30}"#.into());
            }
            ("200 OK", "{}".into())
        })
        .await;
        let core = Core::new(&base, &omnuv_protocol::Redacted::from("t".to_string())).unwrap();
        handshake(&core, &HeartbeatDriver).await.expect("accepted");
        let _ = rx.recv().await.unwrap();
        core.get_json::<serde_json::Value>("/provider/v1/desired-state").await.expect("a view");
        let (view, _) = rx.recv().await.unwrap();
        assert!(!view.contains("onv-session"), "a session nobody minted was sent: {view}");
    }

    /// The body of a request `read_request` returned.
    fn body_of(request: &[u8]) -> String {
        let text = String::from_utf8_lossy(request);
        text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default()
    }

    #[tokio::test]
    async fn the_self_check_passes_only_when_core_accepts_the_token() {
        use tokio::io::AsyncWriteExt;
        let _ = rustls::crypto::ring::default_provider().install_default();
        for (status, verdict) in [
            ("204 No Content", "accepts this agent"),
            ("401 Unauthorized", "refused this agent's token"),
            ("404 Not Found", "SELFCHECK FAILED"),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_request(&mut socket).await;
                let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                socket.write_all(response.as_bytes()).await.unwrap();
                String::from_utf8_lossy(&request).into_owned()
            });
            let core = Core { http: reqwest::Client::new(), base: base.clone(), token: "fixture".into(), session: Default::default(), restore: Default::default(), lease: Default::default(), built: Default::default(), report: Default::default(), install_watch: Default::default() };
            let said = core_check(&core, &base, "0123456789ab").await;
            let request = server.await.unwrap();
            assert!(request.starts_with("POST /provider/v1/heartbeat "), "{request}");
            assert!(request.to_lowercase().contains("authorization: bearer fixture"), "the check sent no token");
            assert!(said.contains(verdict), "{status}: {said}");
            if status.starts_with("404") {
                assert!(!said.contains("reachable"), "a server without the route passed: {said}");
            }
        }
    }

    /// A runtime operation remains pending while several heartbeats arrive.
    /// Even a rejected request does not end the task or wait for reconciliation.
    #[tokio::test]
    async fn heartbeat_progresses_during_a_pending_runtime_operation() {
        use tokio::io::AsyncWriteExt;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let core = Core {
            http: reqwest::Client::new(),
            base: format!("http://{}", listener.local_addr().unwrap()),
            token: "heartbeat-fixture".into(),
            session: Default::default(),
            restore: Default::default(),
            lease: Default::default(),
            built: Default::default(),
            report: Default::default(),
            install_watch: Default::default(),
        };
        let (seen_tx, mut seen_rx) = tokio::sync::mpsc::channel(3);
        let server = tokio::spawn(async move {
            for i in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_request(&mut socket).await;
                assert!(request.starts_with(b"POST /provider/v1/heartbeat HTTP/1.1\r\n"));
                let status = if i == 0 { "500 Internal Server Error" } else { "204 No Content" };
                let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.shutdown().await.unwrap();
                seen_tx.send(i).await.unwrap();
            }
        });
        let heartbeat = spawn_heartbeat(
            core,
            Arc::new(HeartbeatDriver),
            std::time::Duration::from_millis(20),
            "0123456789ab".into(),
        );
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel::<()>();
        let mut runtime_operation = tokio::spawn(async move { finish_rx.await.unwrap() });

        let result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            for expected in 0..3 {
                tokio::select! {
                    _ = &mut runtime_operation => panic!("runtime operation finished prematurely"),
                    seen = seen_rx.recv() => assert_eq!(seen, Some(expected)),
                }
            }
        })
        .await;
        heartbeat.abort();
        let _ = heartbeat.await;
        server.abort();
        let _ = server.await;
        finish_tx.send(()).unwrap();
        runtime_operation.await.unwrap();
        assert!(result.is_ok(), "heartbeats stopped behind runtime work");
    }

    /// A Core that answers the view with `view` and everything else with 204,
    /// on as many connections as it is asked on, handing each request's
    /// first line and body to the test.
    async fn core_stub(view: serde_json::Value) -> (String, tokio::sync::mpsc::UnboundedReceiver<(String, String)>) {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let (view, tx) = (view.clone(), tx.clone());
                tokio::spawn(async move {
                    let request = read_request(&mut socket).await;
                    let line = String::from_utf8_lossy(&request).lines().next().unwrap_or_default().to_string();
                    let (status, body) = if line.starts_with("GET /provider/v1/desired-state") {
                        ("200 OK", view.to_string())
                    } else {
                        ("204 No Content", String::new())
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = tx.send((line, body_of(&request)));
                });
            }
        });
        (base, rx)
    }

    /// **Every heartbeat says which tunables this agent runs**, the self-check's
    /// included: the hash `check-config` printed, as `Heartbeat::config_hash`.
    /// Before 26 September 2026 the heartbeat had no body at all.
    #[tokio::test]
    async fn every_heartbeat_says_which_tunables_it_runs() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (base, mut heard) = core_stub(serde_json::Value::Null).await;
        let core = Core { http: reqwest::Client::new(), base: base.clone(), token: "t".into(), session: Default::default(), restore: Default::default(), lease: Default::default(), built: Default::default(), report: Default::default(), install_watch: Default::default() };
        let said = |(line, body): (String, String)| -> Option<String> {
            assert!(line.starts_with("POST /provider/v1/heartbeat "), "{line}");
            serde_json::from_str::<omnuv_protocol::Heartbeat>(&body).expect("a heartbeat body").config_hash
        };

        assert!(core_check(&core, &base, "0123456789ab").await.contains("accepts this agent"));
        assert_eq!(said(heard.recv().await.unwrap()), Some("0123456789ab".into()), "the self-check");

        let beating = spawn_heartbeat(core, Arc::new(HeartbeatDriver), std::time::Duration::from_millis(20), "0123456789ab".into());
        for n in 0..2 {
            let got = tokio::time::timeout(std::time::Duration::from_secs(3), heard.recv()).await.expect("a heartbeat").unwrap();
            assert_eq!(said(got), Some("0123456789ab".into()), "heartbeat {n}");
        }
        beating.abort();
    }

    /// **The poll Core sends is the one kept** (D33), from a real pass: Core's
    /// view says 45 s, and the loop is re-armed to it. Before 26 September
    /// 2026 the agent polled every 120 s whatever Core wanted.
    #[tokio::test]
    async fn the_poll_core_sends_is_the_one_kept() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let view = serde_json::json!({
            "protocol_version": omnuv_protocol::PROTOCOL_VERSION,
            "version": 1,
            "poll_interval_secs": 45,
        });
        let (base, _heard) = core_stub(view).await;
        let core = Core { http: reqwest::Client::new(), base: base.clone(), token: "t".into(), session: Default::default(), restore: Default::default(), lease: Default::default(), built: Default::default(), report: Default::default(), install_watch: Default::default() };
        let pve = crate::pvemock::Mock::start(|method, path, _| match (method, path) {
            ("GET", "/nodes/n1/qemu") => (200, serde_json::json!([])),
            _ => (404, serde_json::Value::Null),
        })
        .await;
        let snippets = tempfile::tempdir().unwrap();
        let cfg: AgentConfig = serde_yaml_ng::from_str(&format!(
            "core:\n  url: {base}\n  token: t\nproxmox:\n  apiUrl: {}\n  node: n1\n  tokenId: onv@pve!agent\n  tokenSecret: s\n  snippetDir: {}\n",
            pve.base,
            snippets.path().display()
        ))
        .expect("config");
        let endpoints: Arc<Mutex<HashMap<String, String>>> = Default::default();
        let held: Arc<Mutex<Option<DesiredState>>> = Default::default();
        let wanted: Arc<Mutex<Vec<omnuv_protocol::ImageArtefact>>> = Default::default();
        let kick = Arc::new(tokio::sync::Notify::new());
        let mut core_poll = None;
        // Whether the rest of the pass succeeds against a mock that knows one
        // route is not the question: the poll is kept from the answer first.
        let _ = reconcile_workers(&core, &pve.client(), &cfg, &endpoints, &held, &wanted, &kick, &mut core_poll).await;
        assert_eq!(core_poll, Some(45), "the view's poll was not kept");
        assert_eq!(repoll(std::time::Duration::from_secs(120), core_poll), Some(std::time::Duration::from_secs(45)));
    }

    /// **A pass that finds a recipe installing owes a sooner look** (3 October
    /// 2026). On production every step fell between two 120 s passes: the
    /// hypervisor's log shows VM 101's status file read twice in its whole
    /// install. A pass whose machine says `step=1/3` now leaves the loop a
    /// follow-up `installwatch::EVERY` away; one that says it finished leaves
    /// none.
    #[tokio::test]
    async fn a_pass_that_finds_an_install_running_owes_a_sooner_look() {
        // SAFETY: as above.
        unsafe { std::env::set_var("OMNUV_ALLOW_PLAINTEXT_CORE", "1") };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let desired: serde_json::Value =
            serde_json::from_str(include_str!("../tests/from-core/desired-state.json")).unwrap();
        let mut spec = desired["instances"][0].clone();
        spec["lifecycle"] = "running".into();
        spec["network"] = serde_json::Value::Null;
        spec["reboot_token"] = serde_json::Value::Null;
        spec["recipe"] = serde_json::json!({"id": "ollama-openwebui", "compose": "services: {}", "post_up": []});
        let id = spec["id"].as_str().unwrap().to_string();
        let key = crate::names::short_tag(&id);
        let stamp = crate::names::description(crate::instance::TAG, &id);
        let view = serde_json::json!({
            "protocol_version": omnuv_protocol::PROTOCOL_VERSION,
            "version": 1,
            "instances": [spec],
        });
        let file = Arc::new(Mutex::new("step=1/3\nlabel=Getting ready\n".to_string()));
        let said = file.clone();
        let (base, _heard) = core_stub(view).await;
        let core = Core { http: reqwest::Client::new(), base: base.clone(), token: "t".into(), session: Default::default(), restore: Default::default(), lease: Default::default(), built: Default::default(), report: Default::default(), install_watch: Default::default() };
        let pve = crate::pvemock::Mock::start(move |method, path, _| {
            if let Some(ok) = crate::pvemock::task_ok(path) {
                return ok;
            }
            match (method, path) {
                ("GET", "/cluster/resources?type=vm") => (200, serde_json::json!([
                    {"node": "n1", "vmid": 700, "status": "running", "tags": format!("{};{key}", crate::instance::TAG)}
                ])),
                ("GET", "/nodes/n1/qemu/700/status/current") => (200, serde_json::json!({"status": "running", "uptime": 60})),
                ("GET", p) if p.starts_with("/nodes/n1/qemu/700/agent/file-read") && p.contains("recipe-status") => {
                    (200, serde_json::json!({"content": said.lock().unwrap().clone()}))
                }
                ("GET", p) if p.contains("/agent/") => (500, serde_json::Value::Null),
                ("GET", "/nodes/n1/qemu/700/config") => (200, serde_json::json!({"description": stamp.clone()})),
                ("GET", _) => (200, serde_json::json!({})),
                _ => (200, serde_json::Value::Null),
            }
        })
        .await;
        let snippets = tempfile::tempdir().unwrap();
        let cfg: AgentConfig = serde_yaml_ng::from_str(&format!(
            "core:\n  url: {base}\n  token: t\nproxmox:\n  apiUrl: {}\n  node: n1\n  tokenId: onv@pve!agent\n  tokenSecret: s\n  snippetDir: {}\n",
            pve.base,
            snippets.path().display()
        ))
        .expect("config");
        let endpoints: Arc<Mutex<HashMap<String, String>>> = Default::default();
        let held: Arc<Mutex<Option<DesiredState>>> = Default::default();
        let wanted: Arc<Mutex<Vec<omnuv_protocol::ImageArtefact>>> = Default::default();
        let kick = Arc::new(tokio::sync::Notify::new());
        let mut core_poll = None;

        let _ = reconcile_workers(&core, &pve.client(), &cfg, &endpoints, &held, &wanted, &kick, &mut core_poll).await;
        let now = tokio::time::Instant::now();
        let due = core.install_watch.lock().unwrap().due(now);
        assert!(due.is_some_and(|at| at <= now + crate::installwatch::EVERY),
                "a pass that read step 1 of 3 left the next look to the poll");

        *file.lock().unwrap() = "step=finished\nlabel=\nrc=0\n".to_string();
        let _ = reconcile_workers(&core, &pve.client(), &cfg, &endpoints, &held, &wanted, &kick, &mut core_poll).await;
        assert_eq!(core.install_watch.lock().unwrap().due(tokio::time::Instant::now()), None,
                   "a finished install is still followed closely");
    }

    /// One pass against a Core serving `view`, with this agent's head at
    /// `head` against a Core that holds restores. What the pass sent Core
    /// (each request's head and body), and what it asked of Proxmox.
    async fn a_pass_with_the_head_at(head: u64, view: serde_json::Value) -> (Vec<(String, String)>, Vec<crate::pvemock::Call>) {
        // SAFETY: as above.
        unsafe { std::env::set_var("OMNUV_ALLOW_PLAINTEXT_CORE", "1") };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let body = view.to_string();
        let (base, mut rx) = session_stub(move |line, _| {
            if line.starts_with("GET /provider/v1/desired-state") {
                ("200 OK", body.clone())
            } else {
                ("204 No Content", String::new())
            }
        })
        .await;
        let pve = crate::pvemock::Mock::start(|method, path, _| match (method, path) {
            ("GET", "/nodes") => (200, serde_json::json!([{"node": "n1", "status": "online"}])),
            ("GET", "/nodes/n1/qemu") => (200, serde_json::json!([])),
            ("GET", p) if p.starts_with("/cluster/resources") => (200, serde_json::json!([])),
            _ => (404, serde_json::Value::Null),
        })
        .await;
        let snippets = tempfile::tempdir().unwrap();
        let snippet_dir = snippets.path().join("snippets");
        std::fs::create_dir_all(&snippet_dir).unwrap();
        let cfg: AgentConfig = serde_yaml_ng::from_str(&format!(
            "core:\n  url: {base}\n  token: t\nproxmox:\n  apiUrl: {}\n  node: n1\n  tokenId: onv@pve!agent\n  tokenSecret: s\n  snippetDir: {}\n",
            pve.base,
            snippet_dir.display()
        ))
        .expect("config");
        let core = Core::new(&base, &omnuv_protocol::Redacted::from("t".to_string()))
            .unwrap()
            .with_restore_head(crate::restore::head_file(&cfg.proxmox.snippet_dir));
        crate::restore::arm(&core.restore, &serde_json::json!({"provider_id": "p", "restore_mode": true}));
        let mut at_head: DesiredState = serde_json::from_value(view.clone()).unwrap();
        at_head.version = head;
        at_head.instances.clear();
        crate::restore::observe(&core.restore, &at_head, None, |_| false);
        let endpoints: Arc<Mutex<HashMap<String, String>>> = Default::default();
        let held: Arc<Mutex<Option<DesiredState>>> = Default::default();
        let wanted: Arc<Mutex<Vec<omnuv_protocol::ImageArtefact>>> = Default::default();
        let kick = Arc::new(tokio::sync::Notify::new());
        let mut core_poll = None;
        let _ = reconcile_workers(&core, &pve.client(), &cfg, &endpoints, &held, &wanted, &kick, &mut core_poll).await;
        // One more call, to see what every call carries after the pass.
        let _ = core.post("/provider/v1/heartbeat", None).await;
        let mut sent = Vec::new();
        while let Ok(r) = rx.try_recv() {
            sent.push(r);
        }
        let calls = pve.calls.lock().unwrap().clone();
        (sent, calls)
    }

    /// One pass against a Core serving `views` in turn to each view request
    /// (the last one repeated), with no restore armed, and a Proxmox that
    /// answers `pve`. What the pass sent Core, and what it asked of Proxmox.
    pub(super) async fn a_pass_serving(
        views: Vec<serde_json::Value>,
        pve: impl Fn(&str, &str, &str) -> (u16, serde_json::Value) + Send + Sync + 'static,
    ) -> (Vec<(String, String)>, Vec<crate::pvemock::Call>) {
        // SAFETY: as above.
        unsafe { std::env::set_var("OMNUV_ALLOW_PLAINTEXT_CORE", "1") };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let bodies: Vec<String> = views.iter().map(|v| v.to_string()).collect();
        let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (base, mut rx) = session_stub(move |line, _| {
            if line.starts_with("GET /provider/v1/desired-state") {
                let n = asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                ("200 OK", bodies[n.min(bodies.len() - 1)].clone())
            } else {
                ("204 No Content", String::new())
            }
        })
        .await;
        let pve = crate::pvemock::Mock::start(pve).await;
        let snippets = tempfile::tempdir().unwrap();
        let snippet_dir = snippets.path().join("snippets");
        std::fs::create_dir_all(&snippet_dir).unwrap();
        let cfg: AgentConfig = serde_yaml_ng::from_str(&format!(
            "core:\n  url: {base}\n  token: t\nproxmox:\n  apiUrl: {}\n  node: n1\n  tokenId: onv@pve!agent\n  tokenSecret: s\n  snippetDir: {}\n",
            pve.base,
            snippet_dir.display()
        ))
        .expect("config");
        let core = Core::new(&base, &omnuv_protocol::Redacted::from("t".to_string())).unwrap();
        let endpoints: Arc<Mutex<HashMap<String, String>>> = Default::default();
        let held: Arc<Mutex<Option<DesiredState>>> = Default::default();
        let wanted: Arc<Mutex<Vec<omnuv_protocol::ImageArtefact>>> = Default::default();
        let kick = Arc::new(tokio::sync::Notify::new());
        let mut core_poll = None;
        let _ = reconcile_workers(&core, &pve.client(), &cfg, &endpoints, &held, &wanted, &kick, &mut core_poll).await;
        let mut sent = Vec::new();
        while let Ok(r) = rx.try_recv() {
            sent.push(r);
        }
        let calls = pve.calls.lock().unwrap().clone();
        (sent, calls)
    }

    /// A Proxmox with one empty node, on which a clone can be asked for (the
    /// clone itself is refused: what is asserted is whether it was asked).
    pub(super) fn an_empty_node(method: &str, path: &str, _: &str) -> (u16, serde_json::Value) {
        match (method, path) {
            ("GET", "/nodes") => (200, serde_json::json!([{"node": "n1", "status": "online"}])),
            ("GET", "/nodes/n1/qemu") => (200, serde_json::json!([])),
            ("GET", p) if p.starts_with("/cluster/resources") => (200, serde_json::json!([])),
            ("GET", "/cluster/nextid") => (200, serde_json::json!("123")),
            _ => (404, serde_json::Value::Null),
        }
    }

    /// A view of one worker being created and nothing else, at `version`,
    /// with Core's `built` beside the protocol's fields when `built` is set.
    fn a_worker_view(version: u64, built: Option<bool>) -> serde_json::Value {
        let mut view: serde_json::Value =
            serde_json::from_str(include_str!("../tests/from-core/desired-state.json")).unwrap();
        view["version"] = serde_json::json!(version);
        view["protocol_version"] = serde_json::json!(omnuv_protocol::PROTOCOL_VERSION);
        view["instances"] = serde_json::json!([]);
        let mut worker = serde_json::json!({
            "id": "5f0a6b1e-0000-4000-8000-00000000f6f6", "lifecycle": "running",
            "image": "vllm/vllm-openai:latest", "model_repo": "org/model", "vllm_args": [],
            "vcpus": 4, "memory_mib": 4096, "disk_gib": 20, "gpu_local_ids": [], "port": 8000
        });
        if let Some(b) = built {
            worker["built"] = serde_json::json!(b);
        }
        view["inference_workers"] = serde_json::json!([worker]);
        view
    }

    /// An empty node a worker can be cloned onto: [`an_empty_node`], and what
    /// a worker's placement asks besides.
    fn an_empty_node_for_a_worker(method: &str, path: &str, body: &str) -> (u16, serde_json::Value) {
        match (method, path) {
            ("GET", "/cluster/status") => (200, serde_json::json!([{"type": "node", "name": "n1", "local": 1, "online": 1}])),
            ("GET", p) if p.ends_with("/storage/onv-snippets/status") => {
                (200, serde_json::json!({"shared": 1, "type": "dir", "active": 1}))
            }
            _ => an_empty_node(method, path, body),
        }
    }

    fn clones(calls: &[crate::pvemock::Call]) -> Vec<String> {
        calls.iter().filter(|c| c.method == "POST" && c.path.ends_with("/clone")).map(|c| c.path.clone()).collect()
    }

    fn the_report(sent: &[(String, String)]) -> serde_json::Value {
        let (_, report) = sent.iter().find(|(h, _)| h.starts_with("post /provider/v1/status")).expect("a report");
        serde_json::from_str(report).unwrap()
    }

    /// **A worker Core sends as built, that nothing here carries, is reported
    /// lost and never cloned** (finding 6 for workers; H6 for a worker). The
    /// view is Core's JSON with `"built": true` beside the worker's fields:
    /// its create ran past its horizon. Nothing carries its claim or stamp and
    /// nothing is owed, so the pass says it is lost, in the words Core's clock
    /// concludes on, and asks Proxmox for nothing. The control: the same view
    /// without `built`, as a Core that predates it sends it, is cloned as it
    /// always was, so the harness can see a clone. Before this, the built
    /// worker was cloned too.
    #[tokio::test]
    async fn a_worker_sent_built_that_nothing_carries_is_lost_not_cloned() {
        let (_, calls) = a_pass_serving(vec![a_worker_view(5, None)], an_empty_node_for_a_worker).await;
        assert!(!clones(&calls).is_empty(), "the control asked for no clone, so this test could not see one: {calls:?}");

        let (sent, calls) = a_pass_serving(vec![a_worker_view(5, Some(true))], an_empty_node_for_a_worker).await;
        assert!(clones(&calls).is_empty(), "a worker Core sends as built was cloned again (H6): {:?}", clones(&calls));
        let writes: Vec<_> = calls.iter().filter(|c| c.method != "GET").map(|c| format!("{} {}", c.method, c.path)).collect();
        assert!(writes.is_empty(), "a lost worker asked Proxmox to change something: {writes:?}");
        let report = the_report(&sent);
        let w = &report["workers"][0];
        assert_eq!(
            (w["state"].as_str(), w["retryable"].as_bool(), w["local_id"].is_null(), w["waiting_on"].is_null()),
            (Some("ERROR"), Some(false), true, true),
            "{report}"
        );
        assert_eq!(w["message"].as_str(), Some(crate::worker::LOST_WORKER), "{report}");
        assert!(crate::worker::LOST_WORKER.starts_with("this worker is no longer on its provider"),
            "Core parses this start: {}", crate::worker::LOST_WORKER);
    }

    /// **A worker create a fresh view says was built is not cloned** (finding
    /// 7's C4b, for a worker). The pass's view is revision 5, from before the
    /// worker's horizon: Running, not built. Core has since passed the
    /// horizon, and its view, revision 6, sends it as built. The re-read
    /// before the build reads revision 6; it must refuse, and the pass clone
    /// nothing, report nothing of the worker, and say it did not look. Before
    /// this a worker's build had no re-read at all.
    #[tokio::test]
    async fn a_worker_a_fresh_view_says_was_built_is_not_cloned() {
        let (sent, calls) =
            a_pass_serving(vec![a_worker_view(5, None), a_worker_view(6, Some(true))], an_empty_node_for_a_worker).await;
        assert!(clones(&calls).is_empty(), "a worker create the fresh view says was built was cloned (C4b): {:?}", clones(&calls));
        let report = the_report(&sent);
        assert_eq!(report["workers"], serde_json::json!([]), "the worker was reported on a pass that did not look: {report}");
        assert_eq!(report["observation"]["complete"], serde_json::json!(false));
    }

    /// **A create a fresh view says was built is not cloned** (finding 7 of
    /// the lifecycle model, C4b; the model's G_rereadBuilt). The pass's view
    /// is revision 5, from before the machine's horizon: Running, not built.
    /// Core has since passed the horizon, and its view, revision 6, sends the
    /// machine as built — "never cloned again". The re-read before the build
    /// reads revision 6; it must refuse, and the pass clone nothing.
    #[tokio::test]
    async fn a_create_a_fresh_view_says_was_built_is_not_cloned() {
        let mut before: serde_json::Value =
            serde_json::from_str(include_str!("../tests/from-core/desired-state.json")).unwrap();
        before["version"] = serde_json::json!(5);
        before["protocol_version"] = serde_json::json!(omnuv_protocol::PROTOCOL_VERSION);
        let mut after = before.clone();
        after["version"] = serde_json::json!(6);
        after["instances"][0]["built"] = serde_json::json!(true);

        // The control: the same pass with a fresh view that still wants it
        // unbuilt does ask for the clone, so the harness can see one.
        let (_, calls) = a_pass_serving(vec![before.clone(), before.clone()], an_empty_node).await;
        assert!(calls.iter().any(|c| c.method == "POST" && c.path.ends_with("/clone")),
            "the control asked for no clone, so this test could not see one: {calls:?}");

        let (sent, calls) = a_pass_serving(vec![before, after], an_empty_node).await;
        let clones: Vec<_> = calls.iter().filter(|c| c.method == "POST" && c.path.ends_with("/clone")).collect();
        assert!(clones.is_empty(), "a create the fresh view says was built was cloned (C4b): {clones:?}");
        let (_, report) = sent.iter().find(|(h, _)| h.starts_with("post /provider/v1/status")).expect("a report");
        let report: serde_json::Value = serde_json::from_str(report).unwrap();
        assert_eq!(report["instances"], serde_json::json!([]), "the machine was reported on a pass that did not look: {report}");
        assert_eq!(report["observation"]["complete"], serde_json::json!(false));
    }

    /// **In a restore this agent lists and acts on nothing** (lifecycle phase
    /// 8, TD11; the model's G_restoreMode). Core's view is revision 3, and this
    /// agent acted on revision 9: the ledger went back. The pass lists the
    /// guests and reports them, asks Proxmox nothing but reads, reports no
    /// machine, and says so to Core on the calls that follow. The same view
    /// against a head it extends is converged as ever: a status per machine.
    #[tokio::test]
    async fn restore_mode_lists_and_acts_on_nothing() {
        let mut view: serde_json::Value =
            serde_json::from_str(include_str!("../tests/from-core/desired-state.json")).unwrap();
        view["version"] = serde_json::json!(3);
        view["protocol_version"] = serde_json::json!(omnuv_protocol::PROTOCOL_VERSION);

        let (sent, calls) = a_pass_with_the_head_at(9, view.clone()).await;
        let writes: Vec<_> = calls.iter().filter(|c| c.method != "GET").map(|c| format!("{} {}", c.method, c.path)).collect();
        assert!(writes.is_empty(), "an agent in a restore asked Proxmox to change something: {writes:?}");
        let (_, report) = sent.iter().find(|(h, _)| h.starts_with("post /provider/v1/status")).expect("a report");
        let report: serde_json::Value = serde_json::from_str(report).unwrap();
        assert_eq!(report["instances"], serde_json::json!([]), "a machine was acted on or reported in a restore");
        assert_eq!(report["observation"]["complete"], serde_json::json!(false));
        assert!(report["checks"].as_array().unwrap().iter().any(|c| c["name"] == "guests.surveyed"),
            "the listing Core ends a restore on was not sent: {report}");
        let (beat, _) = sent.iter().find(|(h, _)| h.starts_with("post /provider/v1/heartbeat")).expect("a heartbeat");
        assert!(beat.contains("onv-restore-detected: core sent view revision 3, below revision 9"),
            "the agent did not tell Core: {beat}");

        let (sent, _) = a_pass_with_the_head_at(2, view).await;
        let (_, report) = sent.iter().find(|(h, _)| h.starts_with("post /provider/v1/status")).expect("a report");
        let report: serde_json::Value = serde_json::from_str(report).unwrap();
        assert_eq!(report["instances"].as_array().map(Vec::len), Some(1), "a head the view extends was held: {report}");
        assert!(!sent.iter().any(|(h, _)| h.contains("onv-restore-detected")), "a restore was reported with none");
    }

    /// **A built machine is started only on a view read again** (the phase 7
    /// follow-up; G_reread for a start, as the build and the destroy have it).
    /// The pass's view wants machine 900, built and stopped, running. Just
    /// before the start the view is asked again: when it still says running,
    /// the machine is started; when the buyer has stopped it since, nothing
    /// is started and the machine is reported as it was seen, stopped.
    #[tokio::test]
    async fn a_built_machine_is_started_only_on_a_view_read_again() {
        // SAFETY: set once, to the same value every test here sets.
        unsafe { std::env::set_var("OMNUV_ALLOW_PLAINTEXT_CORE", "1") };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut view: serde_json::Value =
            serde_json::from_str(include_str!("../tests/from-core/desired-state.json")).unwrap();
        view["version"] = serde_json::json!(5);
        view["protocol_version"] = serde_json::json!(omnuv_protocol::PROTOCOL_VERSION);
        view["instances"][0]["built"] = serde_json::json!(true);
        view["instances"][0]["lifecycle"] = serde_json::json!("running");
        let id = view["instances"][0]["id"].as_str().unwrap().to_string();
        let claim = format!("{};{}", crate::instance::TAG, crate::names::short_tag(&id));
        let stamp = crate::names::description(crate::instance::TAG, &id);
        for (again, started) in [("stopped", false), ("running", true)] {
            let mut later = view.clone();
            later["version"] = serde_json::json!(6);
            later["instances"][0]["lifecycle"] = serde_json::json!(again);
            let (first, later) = (view.to_string(), later.to_string());
            let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let (base, mut rx) = session_stub(move |line, _| {
                if line.starts_with("GET /provider/v1/desired-state") {
                    match asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                        0 => ("200 OK", first.clone()),
                        _ => ("200 OK", later.clone()),
                    }
                } else {
                    ("204 No Content", String::new())
                }
            })
            .await;
            let (claim, stamp) = (claim.clone(), stamp.clone());
            let pve = crate::pvemock::Mock::start(move |method, path, _| {
                if let Some(r) = crate::pvemock::task_ok(path) {
                    return r;
                }
                match (method, path) {
                    ("GET", "/nodes") => (200, serde_json::json!([{"node": "n1", "status": "online"}])),
                    ("GET", "/cluster/resources?type=vm") => (200, serde_json::json!([
                        {"node": "n1", "vmid": 900, "status": "stopped", "tags": claim}])),
                    ("GET", "/nodes/n1/qemu") => (200, serde_json::json!([{"vmid": 900, "status": "stopped", "tags": claim}])),
                    ("GET", "/nodes/n1/qemu/900/status/current") => (200, serde_json::json!({"status": "stopped"})),
                    ("GET", "/nodes/n1/qemu/900/config") => (200, serde_json::json!({"description": stamp.clone()})),
                    ("POST", "/nodes/n1/qemu/900/status/start") => (200, serde_json::json!("UPID:n1:start")),
                    _ => crate::pvemock::gate_clear(method, path).unwrap_or((404, serde_json::Value::Null)),
                }
            })
            .await;
            let snippets = tempfile::tempdir().unwrap();
            let snippet_dir = snippets.path().join("snippets");
            std::fs::create_dir_all(&snippet_dir).unwrap();
            let cfg: AgentConfig = serde_yaml_ng::from_str(&format!(
                "core:\n  url: {base}\n  token: t\nproxmox:\n  apiUrl: {}\n  node: n1\n  tokenId: onv@pve!agent\n  tokenSecret: s\n  snippetDir: {}\n",
                pve.base,
                snippet_dir.display()
            ))
            .expect("config");
            let core = Core::new(&base, &omnuv_protocol::Redacted::from("t".to_string())).unwrap();
            let endpoints: Arc<Mutex<HashMap<String, String>>> = Default::default();
            let held: Arc<Mutex<Option<DesiredState>>> = Default::default();
            let wanted: Arc<Mutex<Vec<omnuv_protocol::ImageArtefact>>> = Default::default();
            let kick = Arc::new(tokio::sync::Notify::new());
            let mut core_poll = None;
            let _ = reconcile_workers(&core, &pve.client(), &cfg, &endpoints, &held, &wanted, &kick, &mut core_poll).await;
            assert_eq!(
                pve.called("POST", "/nodes/n1/qemu/900/status/start"),
                started,
                "the view read again said {again}"
            );
            let mut sent = Vec::new();
            while let Ok(r) = rx.try_recv() {
                sent.push(r);
            }
            let reads = sent.iter().filter(|(h, _)| h.starts_with("get /provider/v1/desired-state")).count();
            assert!(reads >= 2, "the view was not read again before the start ({reads} read)");
            if !started {
                let (_, report) = sent.iter().find(|(h, _)| h.starts_with("post /provider/v1/status")).expect("a report");
                let report: serde_json::Value = serde_json::from_str(report).unwrap();
                let machine = &report["instances"][0];
                assert_eq!(machine["state"], serde_json::json!("STOPPED"), "{report}");
                assert!(machine["waiting_on"].as_str().unwrap_or_default().contains("read again"), "{report}");
            }
        }
    }

    /// **The mirror's host-timer proof, replayed on this side** (27
    /// September 2026; fixtures, not hardware). A leased machine the host
    /// timer stopped, its lease resumed expired by a restarted agent; the
    /// first view names it Running and leases it, and it is started; the
    /// buyer deletes it; the next pass destroys it, and every pass after
    /// proves it gone. What each pass tells Core about it: `deleted`, the one
    /// word Core ends the claim on (and it does: omnuv's
    /// `moves::tests::a_leased_machine_deleted_after_its_agent_came_back_ends_its_claim`).
    /// And the lease ends with the machine: it outlived the proof until 27
    /// September 2026, and was "stopped" at T with nothing left to stop.
    #[tokio::test]
    async fn a_leased_machine_deleted_after_a_restart_is_reported_deleted() {
        // SAFETY: set once, to the same value every test here sets.
        unsafe { std::env::set_var("OMNUV_ALLOW_PLAINTEXT_CORE", "1") };
        let _ = rustls::crypto::ring::default_provider().install_default();
        const M: &str = "f35783b3-0000-4000-8000-000000000001";
        const DISK: &str = "vmdata:vm-100-disk-0";
        let spec = |lifecycle: &str| {
            let mut v: serde_json::Value =
                serde_json::from_str(include_str!("../tests/from-core/desired-state.json")).unwrap();
            v["protocol_version"] = serde_json::json!(omnuv_protocol::PROTOCOL_VERSION);
            v["instances"][0]["id"] = serde_json::json!(M);
            v["instances"][0]["built"] = serde_json::json!(true);
            v["instances"][0]["lifecycle"] = serde_json::json!(lifecycle);
            v
        };
        // Core: the view in force, its lease header, and every report.
        let view = Arc::new(Mutex::new(spec("running")));
        let lease = Arc::new(Mutex::new(Some(format!("900 {M}"))));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(String, String)>();
        {
            let (view, lease) = (view.clone(), lease.clone());
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else { return };
                    let (view, lease, tx) = (view.clone(), lease.clone(), tx.clone());
                    tokio::spawn(async move {
                        let request = read_request(&mut socket).await;
                        let line = String::from_utf8_lossy(&request).lines().next().unwrap_or_default().to_string();
                        let response = if line.starts_with("GET /provider/v1/desired-state") {
                            let body = view.lock().unwrap().to_string();
                            let header = lease.lock().unwrap().clone().map(|l| format!("onv-run-lease: {l}\r\n")).unwrap_or_default();
                            format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{header}content-length: {}\r\nconnection: close\r\n\r\n{body}", body.len())
                        } else {
                            "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_string()
                        };
                        let _ = socket.write_all(response.as_bytes()).await;
                        let _ = tx.send((line, body_of(&request)));
                    });
                }
            });
        }
        // The host: vm 100 on n1, carrying the claim and stamp, stopped by
        // the host timer.
        #[derive(Default)]
        struct Host {
            present: bool,
            running: bool,
            volumes: Vec<String>,
        }
        let host = Arc::new(Mutex::new(Host { present: true, running: false, volumes: vec![DISK.into()] }));
        let claim = crate::names::tags(crate::names::TAG_INSTANCE, M, Some("test"));
        let stamp = crate::names::description(crate::names::TAG_INSTANCE, M);
        let h = host.clone();
        let pve = crate::pvemock::Mock::start(move |method, path, _| {
            if let Some(r) = crate::pvemock::task_ok(path) {
                return r;
            }
            let mut h = h.lock().unwrap();
            let status = if h.running { "running" } else { "stopped" };
            match (method, path) {
                ("GET", "/nodes") => (200, serde_json::json!([{"node": "n1", "status": "online"}])),
                ("GET", p) if p.starts_with("/cluster/resources") => (
                    200,
                    if h.present {
                        serde_json::json!([{"node": "n1", "vmid": 100, "status": status, "tags": claim, "type": "qemu"}])
                    } else {
                        serde_json::json!([])
                    },
                ),
                ("GET", "/nodes/n1/qemu") => (
                    200,
                    if h.present { serde_json::json!([{"vmid": 100, "status": status, "tags": claim}]) } else { serde_json::json!([]) },
                ),
                ("GET", "/nodes/n1/qemu/100/status/current") if h.present => (200, serde_json::json!({"status": status})),
                ("GET", "/nodes/n1/qemu/100/config") if h.present => {
                    (200, serde_json::json!({"description": stamp, "scsi0": format!("{DISK},size=20G")}))
                }
                ("POST", "/nodes/n1/qemu/100/status/start") => {
                    h.running = true;
                    (200, serde_json::json!("UPID:n1:start"))
                }
                ("POST", "/nodes/n1/qemu/100/status/stop") | ("POST", "/nodes/n1/qemu/100/status/shutdown") => {
                    h.running = false;
                    (200, serde_json::json!("UPID:n1:stop"))
                }
                ("DELETE", p) if p.starts_with("/nodes/n1/qemu/100") => {
                    h.present = false;
                    h.running = false;
                    h.volumes.clear();
                    (200, serde_json::json!("UPID:n1:destroy"))
                }
                ("GET", "/cluster/ha/resources") => (200, serde_json::json!([])),
                ("GET", "/nodes/n1/storage/vmdata/content") => {
                    (200, serde_json::json!(h.volumes.iter().map(|v| serde_json::json!({"volid": v})).collect::<Vec<_>>()))
                }
                _ => crate::pvemock::gate_clear(method, path).unwrap_or((404, serde_json::Value::Null)),
            }
        })
        .await;
        let snippets = tempfile::tempdir().unwrap();
        let snippet_dir = snippets.path().join("snippets");
        std::fs::create_dir_all(&snippet_dir).unwrap();
        let cfg: AgentConfig = serde_yaml_ng::from_str(&format!(
            "core:\n  url: {base}\n  token: t\nproxmox:\n  apiUrl: {}\n  node: n1\n  tokenId: onv@pve!agent\n  tokenSecret: s\n  snippetDir: {}\n",
            pve.base,
            snippet_dir.display()
        ))
        .expect("config");
        let core = Core::new(&base, &omnuv_protocol::Redacted::from("t".to_string())).unwrap();
        let driver = pve.client();
        // The restarted agent resumes its predecessor's lease, past its
        // deadline, and its lease task's first look stops nothing: the host
        // timer already did.
        let file = crate::lease::file(&cfg.proxmox.snippet_dir);
        let until = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - 60;
        std::fs::write(&file, serde_json::json!({"leases": [{"id": M, "until_unix": until}]}).to_string()).unwrap();
        assert_eq!(crate::lease::resumed(&core.lease, &file), Ok(1));
        crate::lease::check(&core.lease, &driver, &file).await;

        let endpoints: Arc<Mutex<HashMap<String, String>>> = Default::default();
        let held: Arc<Mutex<Option<DesiredState>>> = Default::default();
        let wanted: Arc<Mutex<Vec<omnuv_protocol::ImageArtefact>>> = Default::default();
        let kick = Arc::new(tokio::sync::Notify::new());
        let mut core_poll = None;
        let mut pass = async || {
            let done = reconcile_workers(&core, &driver, &cfg, &endpoints, &held, &wanted, &kick, &mut core_poll).await;
            crate::lease::check(&core.lease, &driver, &file).await;
            let mut sent = Vec::new();
            while let Ok(r) = rx.try_recv() {
                sent.push(r);
            }
            let report = sent
                .iter()
                .rev()
                .find(|(l, _)| l.starts_with("POST /provider/v1/status"))
                .map(|(_, b)| serde_json::from_str::<serde_json::Value>(b).unwrap());
            (done.map_err(|e| format!("{e:#}")), report)
        };
        let machine = |report: &Option<serde_json::Value>| -> serde_json::Value {
            report
                .as_ref()
                .and_then(|r| r["instances"].as_array().and_then(|a| a.iter().find(|i| i["id"] == M)).cloned())
                .unwrap_or(serde_json::Value::Null)
        };

        // 1. The view names it Running and leases it: started.
        let (done, report) = pass().await;
        assert!(host.lock().unwrap().running, "the machine the view names Running was not started: {done:?} {report:?}");
        // 2. The buyer deletes it: Absent, and no longer leased.
        {
            let mut v = spec("deleted");
            v["version"] = serde_json::json!(42);
            *view.lock().unwrap() = v;
            *lease.lock().unwrap() = Some("900".into());
        }
        let (done, report) = pass().await;
        assert!(!host.lock().unwrap().present, "the Absent machine was not destroyed: {done:?} {}", machine(&report));
        let m = machine(&report);
        assert_eq!(m["state"], serde_json::json!("STOPPED"), "{done:?} {report:?}");
        assert_ne!(m["message"], serde_json::json!("deleted"), "the destroy's own pass said deleted");
        // 3. Every pass after proves it gone, and says `deleted`.
        for n in 3..6 {
            let (done, report) = pass().await;
            let m = machine(&report);
            assert_eq!(
                (m["state"].as_str(), m["message"].as_str()),
                (Some("STOPPED"), Some("deleted")),
                "pass {n}: the machine is gone from the host and was not reported deleted: {done:?} {report:?}"
            );
            // **And its lease ended with it**: nothing is left to stop, and
            // the host timer's file names it no more. It was kept for good,
            // and "stopped" at T fifteen minutes after the proof.
            let written = crate::lease::read_body(&std::fs::read_to_string(&file).unwrap()).unwrap();
            assert!(written.iter().all(|l| l.id != M), "pass {n}: run-lease.json still names the deleted machine: {written:?}");
            let far = std::time::Instant::now() + std::time::Duration::from_secs(100_000);
            assert!(crate::lease::expired(&core.lease, far).is_empty(), "pass {n}: a lease outlived its machine's proof");
        }
    }

    /// The loop is re-armed when Core's poll moved, and only then.
    #[test]
    fn the_loop_is_re_armed_only_when_core_s_poll_moved() {
        let secs = std::time::Duration::from_secs;
        assert_eq!(repoll(secs(120), None), None, "nothing said, the default kept");
        assert_eq!(repoll(secs(120), Some(60)), Some(secs(60)));
        assert_eq!(repoll(secs(60), Some(60)), None, "the thousandth identical answer changes nothing");
        assert_eq!(repoll(secs(60), Some(0)), Some(secs(120)), "zero is not said");
        assert_eq!(repoll(secs(60), Some(1)), Some(secs(10)), "held to Core's own floor");
    }

    /// The agent offers every version it can speak, not only the newest.
    ///
    /// Advertising a point makes an upgrade order impossible in whichever
    /// direction happens to move first: an agent shipped ahead of Core finds no
    /// common version and is refused, and so does one left behind by a
    /// rollback. Core had exactly this defect from its own side and it would
    /// have disconnected every provider on deploy.
    #[test]
    fn the_agent_offers_a_range() {
        let offered: Vec<u32> =
            (omnuv_protocol::MINIMUM_PROTOCOL_VERSION..=omnuv_protocol::PROTOCOL_VERSION).collect();
        assert!(offered.len() > 1, "a single-element range is a point again");
        assert!(offered.contains(&omnuv_protocol::PROTOCOL_VERSION));
        assert!(offered.contains(&omnuv_protocol::MINIMUM_PROTOCOL_VERSION));

        // Split so the needle does not match this line itself — a source-check
        // that finds its own assertion proves nothing and fails forever.
        let needle = format!("[omnuv_protocol::{}]", "PROTOCOL_VERSION");
        assert!(
            !include_str!("agent.rs").contains(&needle),
            "the handshake must not advertise a single version"
        );
    }
}

async fn handshake(core: &Core, driver: &impl ComputeDriver) -> anyhow::Result<u64> {
    handshake_telling(core, driver, &|| {}).await
}

/// [`handshake`], telling `unreachable` each time an attempt finds Core
/// unreachable: no answer, 5xx or 429 (`Refusal::Unreachable`). Not a 409:
/// Core is up and another agent holds this provider.
async fn handshake_telling(core: &Core, driver: &impl ComputeDriver, unreachable: &(dyn Fn() + Sync)) -> anyhow::Result<u64> {
    let body = serde_json::json!({
        "agent_version": AGENT_VERSION,
        // **A range, not a point**, and the same defect Core had from the other
        // side: advertising only the current version means a Core that has not
        // been upgraded yet — or one rolled back — finds no common version and
        // refuses an agent that could have spoken its dialect perfectly well.
        // Core picks the highest both sides list.
        "protocol_versions":
            (omnuv_protocol::MINIMUM_PROTOCOL_VERSION..=omnuv_protocol::PROTOCOL_VERSION)
                .collect::<Vec<_>>(),
        "drivers": { "compute": [driver.kind().as_str()] },
        // What this agent can do that an older one could not (lifecycle phase
        // 7, S12). Core relies on none of it unless it is listed here, and a
        // Core from before it reads none of it.
        "capabilities": crate::session::CAPABILITIES,
    });

    // Core may simply not be up yet at boot; keep trying with a bounded backoff.
    let mut delay = 2u64;
    loop {
        match core.post(HANDSHAKE, Some(body.clone())).await {
            Ok(r) if r.status().is_success() => {
                let v: serde_json::Value = r.json().await?;
                let secs = heartbeat_secs(&v);
                // The session this agent now holds its provider under, or
                // none from a Core that mints none: then no header is sent.
                let session = crate::session::take(&core.session, &v);
                // Whether this Core holds restores (lifecycle phase 8): only
                // then is this agent's own detection armed.
                crate::restore::arm(&core.restore, &v);
                // D35: the period to report at, before the first view says it.
                core.report.answer(&v);
                println!(
                    "handshake ok: provider {} protocol v{} heartbeat {}s session {}",
                    v.get("provider_id").and_then(|x| x.as_str()).unwrap_or("?"),
                    v.get("protocol_version").and_then(|x| x.as_u64()).unwrap_or(0),
                    secs,
                    session.as_deref().unwrap_or("none")
                );
                return Ok(secs);
            }
            Ok(r) => {
                let status = r.status();
                let detail = r.text().await.unwrap_or_default();
                eprintln!("handshake rejected ({status}): {detail}");
                if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::UPGRADE_REQUIRED {
                    return Err(anyhow::Error::from(CoreAnswered { path: HANDSHAKE.into(), status: status.as_u16() })
                        .context(if status == reqwest::StatusCode::UNAUTHORIZED {
                            "enrollment token rejected; re-enrol this provider"
                        } else {
                            "Core requires a newer protocol than this agent speaks"
                        }));
                }
                // **Held by another agent** (lifecycle phase 7): Core is up
                // and answering, and the wait ends when the holder's lease
                // does, so it is asked again every few seconds rather than on
                // a back-off grown for an unreachable Core.
                if status == reqwest::StatusCode::CONFLICT {
                    tokio::time::sleep(HELD_RETRY).await;
                    continue;
                }
                if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    unreachable();
                }
            }
            Err(e) => {
                eprintln!("handshake failed: {e:#}");
                unreachable();
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        delay = (delay * 2).min(60);
    }
}

async fn report_inventory(core: &Core, driver: &impl ComputeDriver, offered_images: Vec<String>) -> anyhow::Result<()> {
    // A full authenticated allocation view, never an unchanged delta or a
    // remembered tag. This costs one GET per inventory pass and deliberately
    // fails the pass when ownership cannot be observed. Deletions retain GPU
    // ids here until their allocation is released, so a machine still being
    // removed cannot make its card look free.
    let desired: DesiredState = core.get_json("/provider/v1/desired-state").await
        .map_err(|e| anyhow::anyhow!("cannot account for inventory GPU claims: {e}"))?;
    anyhow::ensure!(!desired.unchanged && speaks(desired.protocol_version),
                    "inventory GPU claims require a full compatible desired state");
    let mut report = driver.inventory(&desired).await?;
    // Which marketplace images this provider can build — ids only; the
    // templates behind them are this provider's own configuration.
    report.images = offered_images;
    let res = core.post("/provider/v1/inventory", Some(serde_json::to_value(&report)?)).await?;
    if !res.status().is_success() {
        anyhow::bail!("core rejected inventory: {}", res.status());
    }
    println!(
        "reported {} node(s), {} vCPU, {} GiB, {} GiB disk, {} GPU(s)",
        report.nodes.len(),
        report.total_cpu_cores(),
        report.total_memory_mib() / 1024,
        report.total_disk_gib(),
        report.gpu_count()
    );
    Ok(())
}

/// Fetches every published image this provider offers and does not hold.
///
/// The order matters and is the whole contract: **download, verify, then
/// import**. A digest checked after the import would be a digest checked after
/// a buyer could already have been given a machine built from the wrong bytes.
///
/// Nothing here is compulsory. The catalogue is what the marketplace
/// publishes, not an instruction: an image this provider does not offer is
/// skipped, and disk and bandwidth are the provider's own operational cost —
/// fewer images simply means fewer opportunities to earn.
async fn mirror_images(
    core: &Core,
    driver: &proxmox::Client,
    cfg: &AgentConfig,
    node: &str,
    catalogue: &[omnuv_protocol::ImageArtefact],
) -> anyhow::Result<()> {
    let offered = cfg.proxmox.image_map();
    let held = crate::images::held(driver, node, &offered).await;
    for vmid in crate::images::ensure_environment_tags(driver, node, &offered).await {
        eprintln!("image mirror: template {vmid} tagged with its environment");
    }
    let wanted = crate::images::outstanding(catalogue, &offered, &held);

    let dir = std::path::Path::new(&cfg.proxmox.snippet_dir)
        .parent()
        .unwrap_or(std::path::Path::new(crate::names::VAR))
        .join("import");

    // **Before the early return**, because the partials worth removing belong
    // exactly to the passes that have nothing left to fetch.
    let keep: Vec<&str> = wanted.iter().map(|(a, _)| a.id.as_str()).collect();
    for name in crate::images::reap_stale_partials(&dir, &keep) {
        eprintln!("image mirror: removed stale partial {name}");
        crate::audit::record("image.mirror", "agent", &name, "reaped", None);
    }

    if wanted.is_empty() {
        return Ok(());
    }

    // The storage the artefact is *staged* in, which is not the storage the
    // disk ends up on. It has to be one Proxmox knows, with `import` content,
    // because the agent's token deliberately lacks `Sys.Modify` and PVE refuses
    // an arbitrary path to anyone but root@pam.
    let import_storage = crate::names::STORAGE_SNIPPETS;
    let storage = cfg.proxmox.contribute.storage.first().map(String::as_str).unwrap_or("local");

    // **Bytes that are already right are not fetched again.** Set
    // `OMNUV_FORCE_IMAGE_REFETCH=1` to download regardless — for the case
    // where the file is suspected of being wrong in a way its own digest
    // cannot show, which is rare and should cost a deliberate act.
    let force = std::env::var("OMNUV_FORCE_IMAGE_REFETCH").is_ok_and(|v| v == "1");

    for (artefact, vmid) in wanted {
        let dest = dir.join(crate::images::artefact_file(&artefact.id));

        // A staged artefact from an interrupted pass. Re-downloading six
        // gigabytes to arrive at bytes already on the disk is the most
        // expensive possible no-op, and the digest is exactly the thing that
        // can say so without trusting anything.
        let staged_ok = !force
            && dest.exists()
            && crate::images::digest_of_file(&dest)
                .is_ok_and(|d| d == artefact.sha256);

        if staged_ok {
            eprintln!("image {}: already staged and matching; not downloading again", artefact.id);
            crate::audit::record("image.mirror", "core", &artefact.id, "staged", None);
        } else {
            crate::audit::record("image.mirror", "core", &artefact.id, "fetching", None);
            if let Err(e) = core.download_artefact(artefact, &dest, cfg.timings.image_transfer_idle.std()).await {
                crate::audit::record("image.mirror", "core", &artefact.id, "failed", None);
                eprintln!("image {}: {e:#}", artefact.id);
                continue;
            }

            // Hashed again, from the file, because the check during the
            // download proves the transfer was clean and this proves the thing
            // about to be imported is still that file.
            match crate::images::digest_of_file(&dest) {
                Ok(d) if d == artefact.sha256 => {}
                Ok(d) => {
                    let _ = std::fs::remove_file(&dest);
                    eprintln!("image {}: on-disk digest {d} is not {}", artefact.id, artefact.sha256);
                    continue;
                }
                Err(e) => {
                    eprintln!("image {}: cannot read back what was written: {e:#}", artefact.id);
                    continue;
                }
            }
        }

        match crate::images::import(
            driver,
            node,
            storage,
            import_storage,
            &artefact.id,
            vmid,
            &artefact.sha256,
        )
        .await
        {
            Ok(()) => {
                crate::audit::record("image.mirror", "core", &artefact.id, "held", Some(&vmid.to_string()));
                eprintln!("image {} imported as template {vmid}", artefact.id);
                // The staged copy is several gigabytes and Proxmox has now
                // converted it onto the storage. Keeping it would cost a
                // provider its disk twice for the same image.
                let _ = std::fs::remove_file(&dest);
            }
            Err(e) => {
                crate::audit::record("image.mirror", "core", &artefact.id, "failed", None);
                eprintln!("image {}: import failed: {e:#}", artefact.id);
            }
        }
    }
    Ok(())
}

/// Converges the provider toward Core's desired state, then reports what is
/// actually true. This runs on every tick rather than on an event, so a missed
/// message or an agent restart cannot leave the two sides diverged.
// Eight, each a different piece of the loop's own state that `run` holds: a
// struct of them would be built once, at the one call site, and read here.
#[allow(clippy::too_many_arguments)]
async fn reconcile_workers(
    core: &Core,
    driver: &proxmox::Client,
    cfg: &AgentConfig,
    endpoints: &Arc<Mutex<HashMap<String, String>>>,
    held: &Arc<Mutex<Option<DesiredState>>>,
    // Where the image mirror reads its work from, and how it is woken. This
    // function only ever writes and notifies; the transfer happens in another
    // task, for the reason written where that task is spawned.
    mirror_wanted: &Arc<Mutex<Vec<omnuv_protocol::ImageArtefact>>>,
    mirror_kick: &Arc<tokio::sync::Notify>,
    // Core's poll, as its last answer said it: written here, read by `run`,
    // which re-arms its interval when it moved.
    core_poll: &mut Option<u64>,
) -> anyhow::Result<()> {
    // **A node, never an empty name (PROVIDER-7).** Unset used to become `""`,
    // and every node-scoped call below built `/nodes//…` and failed. Unset means
    // the whole cluster for placement; for the work that needs one node, it is
    // the first online node, resolved each pass.
    let node_owned = driver.home_node(cfg.proxmox.node.as_deref()).await?;
    let node = node_owned.as_str();

    // Refuse rather than guess. Machines built before the project was renamed
    // carry tags this agent no longer recognises, and to it they look like
    // machines that were never created — so converging would build a second
    // copy of each and orphan the first with its card still attached. The
    // migration is a playbook; until it has run, this agent does nothing.
    match driver.legacy_marketplace_vms(node).await {
        Ok(vms) if !vms.is_empty() => {
            anyhow::bail!(
                "refusing to converge: {} machine(s) on this node still carry pre-rename tags                  ({}). They are invisible to this agent, so converging would create duplicates.                  Run deployment/ansible/rename-provider.yml first.",
                vms.len(),
                vms.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")
            );
        }
        Ok(_) => {}
        // A hypervisor we cannot list is a separate problem; the fetch below
        // will fail too and report it in its own words.
        Err(e) => eprintln!("could not check for pre-rename machines: {e:#}"),
    }

    let known = crate::poison::lock(held, "held desired state").as_ref().map(|d| d.version).unwrap_or(0);

    // When the view was asked for, which is how old the persisted copy is (A6).
    let asked = std::time::SystemTime::now();
    let (fetched, restore_named): (DesiredState, Option<String>) =
        match core.get_view(known).await {
            Ok(d) => d,
            Err(e) => {
                // **Only an outage is maintained through (PROVIDER-6).** Every
                // failure used to read as "Core unreachable", so an agent Core
                // had refused — revoked, removed, or too old — went on starting
                // machines from its last copy indefinitely, on instructions
                // from a Core that no longer accepted it.
                if refusal(&e) != Refusal::Unreachable {
                    return Err(e.context("Core refused the desired-state request; nothing was maintained"));
                }
                // Core is unreachable. Maintain, do not decide: the copy in
                // hand is stale, so nothing is created and nothing is
                // destroyed, but a machine that was meant to be running and
                // has crashed is started again. An outage of the control plane
                // must not become an outage of somebody's machine.
                //
                // Not in a restore (lifecycle phase 8, TD11): the copy in hand
                // may be from the history the restore replaced, and a start
                // is an act.
                if crate::restore::active(&core.restore) {
                    return Err(e.context("Core unreachable during a restore; nothing was maintained"));
                }
                let specs = crate::poison::lock(held, "held desired state")
                    .as_ref()
                    .map(|d| d.instances.clone())
                    .unwrap_or_default();
                if specs.is_empty() {
                    return Err(e);
                }
                // Never a machine whose run lease ran out (lifecycle phase
                // 12, A6): its copy may be running elsewhere by now.
                let now = std::time::Instant::now();
                let specs: Vec<_> =
                    specs.into_iter().filter(|s| crate::lease::may_restart(&core.lease, &s.id, now)).collect();
                match driver.maintain(&specs).await {
                    Ok(0) => {}
                    Ok(n) => println!("core unreachable; maintained {n} machine(s), decided nothing"),
                    Err(me) => eprintln!("core unreachable and maintenance failed: {me}"),
                }
                return Err(e);
            }
        };
    if !speaks(fetched.protocol_version) {
        anyhow::bail!(
            "core sent protocol v{}, and this agent speaks v{} to v{}",
            fetched.protocol_version,
            omnuv_protocol::MINIMUM_PROTOCOL_VERSION,
            omnuv_protocol::PROTOCOL_VERSION
        );
    }
    // **From the answer, before anything below can fail**, and from this
    // answer even when it is `unchanged`: the poll describes the answer, not
    // the collections, so the copy in hand is not where it comes from.
    *core_poll = fetched.poll_interval_secs;

    // `unchanged` saves the transfer, never the work: reconciliation runs every
    // tick against the copy in hand, because drift on the hypervisor is exactly
    // what this loop exists to correct.
    let desired = if fetched.unchanged {
        // Cloned out first: a guard in the scrutinee would live to the end
        // of the match, across the fetch below.
        let in_hand = crate::poison::lock(held, "held desired state").clone();
        match in_hand {
            Some(d) => d,
            // Core says nothing changed but we hold nothing. Ask again in full
            // rather than reconciling against an empty picture, which would
            // read as "delete everything".
            None => core.get_json("/provider/v1/desired-state").await?,
        }
    } else {
        *crate::poison::lock(held, "held desired state") = Some(fetched.clone());
        fetched
    };
    // The lease this answer told of, against the view it answered, before
    // anything below can fail (lifecycle phase 12, A9).
    crate::lease::renew(&core.lease, &desired);

    // An idle provider still prepares images and completes cleanup. Empty
    // desired state is a real observation, never a reason to skip the pass.
    //
    // **Handed over rather than awaited.** This used to be the transfer
    // itself, which put seven gigabytes on the task that also applies desired
    // state — so a machine Core had released went on holding a card until the
    // download finished. Writing the catalogue and waking the mirror costs a
    // lock and a notify.
    if !desired.images.is_empty() {
        crate::poison::lock(mirror_wanted, "image catalogue").clone_from(&desired.images);
        mirror_kick.notify_one();
    }

    // **A restore of Core's ledger, read against this agent's head**
    // (lifecycle phase 8, TD11). A view below the revision this agent acted
    // on, one wanting an attempt it tore down, or Core's own word: the
    // ledger went back. The guests are listed and reported, and nothing is
    // destroyed, started, created or recovered until Core ends it.
    let torn = |id: &str| crate::teardown::built_again(&cfg.proxmox.snippet_dir, id).is_some();
    if crate::restore::observe(&core.restore, &desired, restore_named.as_deref(), torn) {
        return report_restoring(core, driver, cfg, &desired).await;
    }
    // **The view this agent may act on, kept for a restart that cannot reach
    // Core** (omnuv's modular design, A6). After the restore check, so a view
    // this agent may not act on is never the one kept.
    crate::heldview::write(
        &crate::heldview::file(&cfg.proxmox.snippet_dir),
        &crate::heldview::of(&cfg.core.url, &desired, asked),
    );

    // **The journal, settled on every pass** (26 September 2026). This ran at
    // the start of every create, and that one fact is the cause of four
    // defects: a clone left behind by a delete, a second clone started beside
    // a first, a rollback that failed and was forgotten, and a machine
    // destroyed because its own clone's record outlived the create that made
    // it. It is one place, before anything below creates or deletes anything,
    // so a create refuses to clone twice and a delete refuses to report gone
    // while either of those is still owed. See `pending`.
    driver.recover_pending(&cfg.proxmox.snippet_dir).await;

    // Segments whose last machine has gone, including when this provider has
    // no desired machines left.
    match driver.reap_unused_segments(node).await {
        Ok(0) => {}
        Ok(n) => eprintln!("removed {n} unused segment(s)"),
        Err(e) => eprintln!("segment reap: {e:#}"),
    }

    let storage = cfg.proxmox.contribute.storage.first().map(String::as_str).unwrap_or("local");

    // **No gateways.** Topology v2 makes every buyer machine an overlay peer,
    // so there is nothing per-provider to bring up, tear down, or reap — and
    // the contract no longer has a place to ask for one (protocol 3).
    //
    // What the gateway also did, as a side effect, was create and destroy the
    // project's SDN segment. Both halves moved: `ensure_segment` creates it
    // with the machine that needs it, and `reap_unused_segments` above removes
    // one no machine is attached to.
    // **The one comparison the report never made (CORE-38).** Everything below
    // iterates what Core asked about; this asks the hypervisor what it holds
    // under our claim and says which of those Core did not ask about. It
    // reports and decides nothing — see `survey`.
    let surveyed = driver.guests().await.map_err(|e| e.to_string());
    let mut checks: Vec<omnuv_protocol::SelfCheck> = crate::survey::checks(surveyed.as_deref().map_err(|e| e.clone()), &desired);
    checks.extend(runtime_checks(cfg, driver).await);
    for c in checks.iter().filter(|c| c.name == "guest.unclaimed") {
        eprintln!("  warning: {}", c.detail.as_deref().unwrap_or("a claimed guest Core did not ask about"));
    }

    // **What a delete may not take** (lifecycle phase 7, licence (a)): the id
    // tags of everything this view still wants, workers and machines alike.
    let live_tags: Vec<String> = desired
        .instances
        .iter()
        .filter(|s| s.intent != Lifecycle::Absent)
        .map(|s| s.id.as_str())
        .chain(desired.inference_workers.iter().filter(|s| s.intent != Lifecycle::Absent).map(|s| s.id.as_str()))
        .map(crate::names::short_tag)
        .collect();

    let mut statuses = Vec::new();
    let mut unobserved_workers = 0usize;
    for spec in &desired.inference_workers {
        let result = match spec.intent {
            Lifecycle::Absent => driver
                .delete_inference_worker(&spec.id, &cfg.proxmox.snippet_dir, &live_tags, still_absent(core, held, &spec.id))
                .await
                .map(|gone| WorkerStatus {
                    id: spec.id.clone(),
                    state: WorkerState::Offline,
                    retryable: None,
                    waiting_on: waiting_on(&gone),
                    local_id: None,
                    endpoint: None,
                    adapters: Vec::new(),
                    diagnostics: None,
                    message: Some(crate::teardown::said(&gone)),
                    telemetry: None,
                }),
            // **Never built again under an id this agent tore down** (the
            // model's G_agentTomb, lifecycle phase 7).
            _ if crate::teardown::built_again(&cfg.proxmox.snippet_dir, &spec.id).is_some() => {
                Err(anyhow::anyhow!(crate::teardown::built_again(&cfg.proxmox.snippet_dir, &spec.id).unwrap_or_default()))
            }
            _ => {
                // Whether the view in hand sends it as built (finding 6 for
                // workers), and, if it is to be built, a fresh view read
                // again first (G_reread, and C4b for a worker).
                let built = crate::poison::lock(&core.built, "workers sent as built").built(desired.version, &spec.id);
                driver
                    .ensure_inference_worker_gated(
                        cfg.proxmox.template_vmid,
                        storage,
                        &cfg.proxmox.snippet_dir,
                        spec,
                        &cfg.core.url,
                        built,
                        still_running(core, held, &spec.id),
                        still_wanted(core, held, &spec.id),
                    )
                    .await
            }
        };
        // **Not looked at is not an error** (PROVIDER-26, as for instances
        // below): a worker whose node would not give its power state was
        // neither acted on nor seen, so it is left out of the report and the
        // observation is incomplete, rather than painted ERROR on one blip.
        if let Err(e) = &result
            && e.downcast_ref::<crate::instance::NotLookedAt>().is_some()
        {
            unobserved_workers += 1;
            eprintln!("worker {}: {e:#}", spec.id);
            continue;
        }
        // A failure on one worker must not stop the others from converging, and
        // must be visible to the operator rather than retried in silence.
        statuses.push(result.unwrap_or_else(|e| {
            unobserved_workers += 1;
            eprintln!("worker {}: {e:#}", spec.id);
            WorkerStatus {
                id: spec.id.clone(),
                state: WorkerState::Error,
                retryable: None,
                waiting_on: None,
                local_id: None,
                endpoint: None,
                adapters: Vec::new(),
                diagnostics: None,
                message: Some(e.to_string().chars().take(400).collect()),
                telemetry: None,
            }
        }));
    }

    // **The sweep that makes the best-effort delete safe.** `delete_*` removes a
    // snippet without letting a failure stop the machine's deletion, which is
    // right — and would make a failed removal permanent if nothing looked again.
    //
    // The view is built from what this pass actually observed, and its
    // completeness decides whether anything is collected at all. `desired` is
    // every id Core wants, including a worker being created right now: that
    // machine has no VM yet and its snippet is what it will boot from, so
    // runtime absence alone must never make it disposable.
    {
        let mut known = crate::snippets::Known { complete: true, ..Default::default() };
        for spec in &desired.inference_workers {
            if spec.intent != Lifecycle::Absent {
                known.desired.insert(spec.id.clone());
            }
        }
        for spec in &desired.instances {
            if spec.intent != Lifecycle::Absent {
                known.desired.insert(spec.id.clone());
            }
        }
        // Survey actual references, including stopped/foreign machines and
        // workloads missing from desired state. A status for each desired
        // worker is not a complete runtime inventory.
        let observed = crate::snippets::observe(node, |path| async move {
            driver.get_json(&path).await
        }).await;
        match observed {
            Ok(live) => known.live = live,
            Err(e) => {
                known.complete = false;
                eprintln!("snippet ownership observation failed: {e:#}");
            }
        }
        let swept = crate::snippets::sweep(
            std::path::Path::new(&cfg.proxmox.snippet_dir),
            &known,
            |path| std::fs::remove_file(path),
        );
        if let Some(why) = &swept.refused {
            eprintln!("snippet sweep collected nothing: {why}");
        }
        if !swept.collected.is_empty() {
            eprintln!("snippet sweep collected {} file(s)", swept.collected.len());
        }
        for name in &swept.uncertain {
            eprintln!("snippet {name}: ours by prefix, claimed by nothing, left in place");
        }
        for failure in &swept.failed {
            eprintln!("snippet not collected, will retry: {failure}");
        }
    }

    {
        // Refresh the resolver's view so tunnelled requests reach the right
        // worker as soon as it is serving.
        let mut map = crate::poison::lock(endpoints, "worker endpoints");
        for s in &statuses {
            match &s.endpoint {
                Some(ep) => {
                    map.insert(s.id.clone(), ep.clone());
                }
                None => {
                    map.remove(&s.id);
                }
            }
        }
    }

    for s in &statuses {
        println!("worker {} -> {:?} {}", s.id, s.state, s.endpoint.as_deref().unwrap_or(""));
        audit::record(
            "worker.reconcile",
            "core",
            &s.id,
            &format!("{:?}", s.state).to_lowercase(),
            s.local_id.as_deref(),
        );
    }
    // Buyer instances converge on the same pass and by the same rules.
    let mut instances = Vec::new();
    let mut unobserved_instances = 0usize;
    for spec in &desired.instances {
        let result = match spec.intent {
            Lifecycle::Absent => driver
                .delete_instance(node, &spec.id, &cfg.proxmox.snippet_dir, &live_tags, still_absent(core, held, &spec.id))
                .await
                .inspect(|gone| {
                    // Proven gone, residue or not: nothing carries its claim
                    // or its stamp, so its run lease has nothing left to stop.
                    if !matches!(gone, crate::teardown::Gone::NotYet(_)) {
                        crate::lease::forget(&core.lease, &spec.id);
                        // And its port of the opening is free (released on
                        // Absent): nothing is left for it to reach.
                        if let Err(e) = driver.opening.release(&spec.id) {
                            eprintln!("instance {}: its opening port not released, will retry: {e:#}", spec.id);
                        }
                    }
                })
                .map(|gone| InstanceStatus {
                id: spec.id.clone(),
                rebooted_token: None,
                state: InstanceState::Stopped,
                retryable: None,
                waiting_on: waiting_on(&gone),
                local_id: None,
                node: None,
                console_password_generation: None,
                private_ip: None,
                adapters: Vec::new(),
                diagnostics: None,
                message: Some(crate::teardown::said(&gone)),
                recipe_progress: None,
                ready_to_start: None,
            }),
            // **Never built again under an id this agent tore down** (the
            // model's G_agentTomb, lifecycle phase 7): a view that names it
            // again — a restore by hand, a stale answer — builds nothing.
            _ if crate::teardown::built_again(&cfg.proxmox.snippet_dir, &spec.id).is_some() => Err(anyhow::Error::from(
                crate::instance::Unplaceable { waiting_on: "a machine with a new id" },
            )
            .context(crate::teardown::built_again(&cfg.proxmox.snippet_dir, &spec.id).unwrap_or_default())),
            // The image names a template this provider must have. Refusing
            // here, with the reason reported, is what keeps the scheduler's
            // provider_images honest: Core only places images we said we offer.
            // **Re-read before a build** (G_reread, S8): a machine Core has
            // not seen built is cloned only if a fresh view still wants it,
            // and still does not say built (finding 7, G_rereadBuilt).
            // Not wanted, built, or the view could not be read: nothing is built,
            // nothing is said, and the observation is incomplete.
            _ if !spec.built && !matches!(still_wanted(core, held, &spec.id).await, Ok(true)) => {
                Err(anyhow::Error::from(crate::instance::NotLookedAt(
                    "Core's view, read again just before the build, no longer wants this machine; nothing was built".into(),
                )))
            }
            _ => match cfg.proxmox.template_for(&spec.image.id) {
                Some(template) => {
                    driver
                        .ensure_instance_gated(
                            node,
                            template,
                            storage,
                            &cfg.proxmox.snippet_dir,
                            spec,
                            still_running(core, held, &spec.id),
                        )
                        .await
                }
                None => Err(anyhow::anyhow!("image {} is not offered by this provider", spec.image.id)),
            },
        };
        // **What was seen, what was not, and what failed (PROVIDER-26).**
        let result = match result {
            Err(e) if e.downcast_ref::<crate::instance::NotLookedAt>().is_some() => {
                // Nothing observed, so nothing reported: the item is left out,
                // and `complete` goes false, which is what stops Core reading
                // its absence as anything.
                unobserved_instances += 1;
                eprintln!("instance {}: {e:#}", spec.id);
                continue;
            }
            Err(e) => match e.downcast::<crate::instance::SeenThenFailed>() {
                Ok(seen) => {
                    eprintln!("instance {}: seen {:?}, then: {}", spec.id, seen.state, seen.cause);
                    Ok(InstanceStatus {
                        id: spec.id.clone(),
                        rebooted_token: None,
                        state: seen.state,
                        retryable: Some(true),
                        waiting_on: None,
                        local_id: Some(seen.local_id),
                        node: Some(seen.node),
                        console_password_generation: None,
                        private_ip: None,
                        adapters: Vec::new(),
                        diagnostics: None,
                        message: Some(seen.cause.chars().take(400).collect()),
                        recipe_progress: None,
                        ready_to_start: None,
                    })
                }
                Err(e) => Err(e),
            },
            ok => ok,
        };
        instances.push(result.unwrap_or_else(|e| {
            unobserved_instances += 1;
            eprintln!("instance {}: {e:#}", spec.id);
            let why = e.to_string();
            // Why, and whether trying again could plausibly work. Without this
            // Core has to poll to learn anything, and it will re-drive an
            // impossible request until its horizon for no reason.
            // **What cannot be retried into working.** Both of these are
            // placements that were wrong when they were made: a provider
            // without the image, and a provider whose card is already sold.
            // Retrying either re-drives an impossible request until Core's
            // horizon; the marketplace's answer is a different provider.
            //
            // **And this is the third untyped string acting as protocol on
            // this wire**, after the handshake and after `message: "deleted"`.
            // A phrase changed on one side silently changes the other's
            // behaviour, and here the change is from "place it elsewhere" to
            // "retry forever". Named rather than fixed: closing it is a tagged
            // `omnuv-protocol` release carrying a reason code, and that is
            // queued.
            // **Asked of the type, not of the words.** This matched the error
            // text and broke the same afternoon it was written: the cluster
            // walk reworded the refusal, the phrase here did not follow, and a
            // one-shot refusal was reported retryable — so Core re-drove it,
            // the retry succeeded once a card freed, and the machine took a
            // recycled VMID. Measured on Pluto, 19 September 2026.
            //
            // `Unplaceable` carries the same fact as a type, which a rename
            // cannot break. The image refusal is still a phrase and is still
            // the hazard; it is left as one deliberately rather than changed
            // blind, because it lives in a different function and deserves its
            // own change.
            let unplaceable = e.downcast_ref::<crate::instance::Unplaceable>();
            let no_image = why.contains("is not offered by this provider");
            let retryable = !(no_image || unplaceable.is_some());
            InstanceStatus {
                id: spec.id.clone(),
                rebooted_token: None,
                state: InstanceState::Error,
                retryable: Some(retryable),
                waiting_on: if no_image {
                    Some("a provider that offers this image".to_string())
                } else {
                    unplaceable.map(|u| u.waiting_on.to_string())
                },
                local_id: None,
                node: None,
                console_password_generation: None,
                private_ip: None,
                adapters: Vec::new(),
                diagnostics: None,
                message: Some(why.chars().take(400).collect()),
                recipe_progress: None,
                ready_to_start: None,
            }
        }));
    }
    for i in &instances {
        println!("instance {} -> {:?} {}", i.id, i.state, i.private_ip.as_deref().unwrap_or(""));
    }
    // **What is installing, for the loop to look again sooner** (3 October
    // 2026): a step lasts seconds and the poll two minutes.
    {
        let seen: Vec<crate::installwatch::Seen<'_>> = instances
            .iter()
            .map(|i| crate::installwatch::Seen {
                id: i.id.as_str(),
                running: i.state == InstanceState::Running,
                recipe: desired.instances.iter().any(|s| s.id == i.id && s.recipe.is_some()),
                progress: i.recipe_progress.as_ref().map(|p| p.status.as_str()),
                stream_pending: i.recipe_progress.as_ref().is_some_and(|p| p.status == "done")
                    && crate::stream_devices::pending(
                        desired.instances.iter().find(|s| s.id == i.id).and_then(|s| s.stream_devices.as_deref()),
                        i.recipe_progress.as_ref().and_then(|p| p.stream_identity.as_ref()),
                    ),
            })
            .collect();
        crate::poison::lock(&core.install_watch, "the install watch").after_pass(tokio::time::Instant::now(), &seen);
    }
    // What each existing machine's drive refresh did, which was printed and
    // nothing else until 26 September 2026 (gap 4). After the loop, because
    // that is what fills it.
    checks.extend(driver.refreshes.drain());
    // **The provider opening** (`crate::opening`): each opened machine's
    // egress address, from the host's neighbour table by its egress MAC; then
    // the port of every machine that is neither wanted by this view nor
    // listed on this host released. Only on a listing that worked: "could not
    // ask" is never "gone" (R1 rule 9), and a machine being built has no guest
    // yet, which is why the view's wanted ids are kept too. A change rewrites
    // opening.json, which wakes the applier; no change writes nothing.
    {
        let neighbours = crate::neighbours::Neighbours::read();
        if let Err(e) = driver.opening.observe(|mac| neighbours.get(mac).to_vec()) {
            eprintln!("opening: addresses not recorded, will retry: {e:#}");
        }
        if let Ok(guests) = &surveyed {
            let stamps: std::collections::HashSet<&str> = guests.iter().filter_map(|g| g.stamp.as_deref()).collect();
            let wanted: std::collections::HashSet<&str> = desired
                .instances
                .iter()
                .filter(|s| s.intent != Lifecycle::Absent)
                .map(|s| s.id.as_str())
                .collect();
            let keep = |id: &str| {
                wanted.contains(id) || stamps.contains(crate::names::stamped(crate::names::TAG_INSTANCE, id).as_str())
            };
            match driver.opening.sweep(keep) {
                Ok(gone) if !gone.is_empty() => println!("opening: {} port(s) released, their machines gone", gone.len()),
                Ok(_) => {}
                Err(e) => eprintln!("opening: ports not released, will retry: {e:#}"),
            }
        }
    }
    // **Residues, retried every pass and reported** (lifecycle phase 7, RC9):
    // volumes a deleted machine left, which Core no longer sends once it ended
    // the compute claim on them.
    checks.extend(driver.retry_residues(&cfg.proxmox.snippet_dir).await);
    let reaped = driver.reap_tombstones(&cfg.proxmox.snippet_dir, cfg.timings.tombstone_keep).await;
    if reaped > 0 {
        println!("reaped {reaped} tombstone(s) past timings.tombstoneKeep");
    }
    for c in checks.iter().filter(|c| c.name == "instance.cloud_init") {
        eprintln!("  warning: {}", c.detail.as_deref().unwrap_or("a machine's cloud-init was not refreshed"));
    }

    // **What this report covers, said honestly.**
    //
    // The loops above iterate `desired.*` — this agent reports a result for each
    // thing Core asked about, and does *not* survey the hypervisor. So the scope
    // is the desired set, not the provider: a machine Core has never heard of
    // cannot appear here, and its absence from this report is not evidence of
    // anything. That is why Core keeps an independent orphan check, and why the
    // plan says a delta cannot reveal an object omitted from both inputs.
    //
    // `complete` therefore means: every desired item produced a result on this
    // pass. It is false the moment one did not, because a report missing an
    // item it was supposed to cover must not let Core conclude that item is
    // gone.
    // **A result is not an observation.** Both loops push one result per
    // desired item, success or error, so comparing lengths could never find a
    // gap and `complete` was always true. What must count is the results that
    // came from an error: the agent could not read or act, so it does not know
    // that item's state, and its Error is a statement about itself.
    let incomplete_because = incompleteness(
        unobserved_instances,
        desired.instances.len(),
        unobserved_workers,
        desired.inference_workers.len(),
    );
    let observation = omnuv_protocol::Observation {
        generation: *GENERATION,
        sequence: SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        collected_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        // Named for what they are: the *desired* set this pass covered. Calling
        // them `instances` would invite Core to read absence into them.
        scope: vec!["desired_instances".into(), "desired_workers".into()],
        complete: incomplete_because.is_empty(),
        incomplete_because,
        desired_revision: Some(desired.version),
    };

    let report = StatusReport {
        protocol_version: omnuv_protocol::PROTOCOL_VERSION,
        // What this agent actually did since the last report, in its own
        // words. Bounded here and again at Core.
        audit: audit::drain(100),
        workers: statuses,
        instances,
        // Reported every pass, not only when something is wrong: a check that
        // is only sent on failure is indistinguishable from one that stopped
        // running.
        checks,
        observation: Some(observation),
    };
    let res = core.post("/provider/v1/status", Some(serde_json::to_value(&report)?)).await?;
    if !res.status().is_success() {
        anyhow::bail!("core rejected status report: {}", res.status());
    }
    Ok(())
}

/// **A pass in restore mode** (lifecycle phase 8, TD11): the guests listed
/// and reported, and nothing else. What Core reads to end the restore is
/// this listing — `guests.surveyed`, and a `guest.unclaimed` for each
/// claimed guest its ledger does not name — so it goes every pass. No item
/// is reported: nothing was acted on, and the observation says it is
/// incomplete, so Core reads nothing into what it lacks.
async fn report_restoring(
    core: &Core,
    driver: &proxmox::Client,
    cfg: &AgentConfig,
    desired: &DesiredState,
) -> anyhow::Result<()> {
    let surveyed = driver.guests().await.map_err(|e| e.to_string());
    let mut checks = crate::survey::checks(surveyed.as_deref().map_err(|e| e.clone()), desired);
    checks.extend(runtime_checks(cfg, driver).await);
    let observation = omnuv_protocol::Observation {
        generation: *GENERATION,
        sequence: SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        collected_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        scope: vec!["desired_instances".into(), "desired_workers".into()],
        complete: false,
        incomplete_because: vec!["restore mode: this agent listed its guests and acted on nothing".into()],
        desired_revision: Some(desired.version),
    };
    let report = StatusReport {
        protocol_version: omnuv_protocol::PROTOCOL_VERSION,
        audit: audit::drain(100),
        workers: Vec::new(),
        instances: Vec::new(),
        checks,
        observation: Some(observation),
    };
    let res = core.post("/provider/v1/status", Some(serde_json::to_value(&report)?)).await?;
    if !res.status().is_success() {
        anyhow::bail!("core rejected status report: {}", res.status());
    }
    println!("restore mode: guests listed and reported; nothing acted on");
    Ok(())
}

/// **Lets go of the provider on the way out**: the session this agent holds,
/// released, so the next agent's handshake is let in at once. Best-effort —
/// an agent that cannot say so is waited out — and nothing when no session
/// is held (a Core that mints none).
async fn release_session(core: &Core) {
    if crate::session::current(&core.session).is_none() {
        return;
    }
    match core.delete("/provider/v1/session").await {
        Ok(r) if r.status().is_success() => println!("stopping: released this agent's session"),
        Ok(r) => eprintln!("stopping: the session was not released ({}); the next agent waits out its lease", r.status()),
        Err(e) => eprintln!("stopping: the session was not released: {e:#}; the next agent waits out its lease"),
    }
}

/// What a delete's report says it is waiting on: nothing once proven; the
/// operator, for a residue; a listing, otherwise.
fn waiting_on(gone: &crate::teardown::Gone) -> Option<String> {
    match gone {
        crate::teardown::Gone::Proven => None,
        crate::teardown::Gone::Residue(_) => Some("the provider to remove the volumes it left".into()),
        crate::teardown::Gone::NotYet(_) => Some("a complete listing that proves it gone".into()),
    }
}

/// **Core's view, read again just before a destroy** (lifecycle phase 7:
/// the model's G_reread and G_viewMonotone; S8, RC4).
///
/// A pass acts on the view it fetched at its start, and a destroy late in a
/// pass acted on a view up to a pass old: the buyer's Absent could have been
/// withdrawn since, or the machine's claim ended and its row gone. So the
/// view is asked again (`?known=`, so an unchanged one costs a short answer),
/// and the destroy goes ahead only if that view still names this id Absent.
///
/// **Never on a view older than the one held.** A full answer whose revision
/// is below the one this agent holds is a reordered answer or a restore; it
/// licenses no destroy (the model's G_viewMonotone, kept beside the re-read:
/// their pair was never model-checked, TODO.md). Could not ask is not yes.
async fn still_absent(core: &Core, held: &Arc<Mutex<Option<DesiredState>>>, id: &str) -> anyhow::Result<bool> {
    Ok(intent_now(core, held, id).await? == Some(Lifecycle::Absent))
}

/// **Core's view, read again just before a build** (G_reread for creates;
/// S8: "the agent builds (k, t) only on its newest session's view, re-read
/// just before"). The model's counterexample is exactly this: the agent
/// fetched a machine Running, the buyer deleted it, and the agent cloned and
/// started it from the view it held. A machine Core has not seen built is
/// cloned only if a fresh view still wants it.
///
/// **And not built** (finding 7 of the lifecycle model, C4b; G_rereadBuilt).
/// From a create's horizon Core sends it as built, so it is never cloned
/// again (0192). A pass whose view predates the horizon read it unbuilt, and
/// its re-read asked only the intent: it cloned after Core had said nothing
/// would. A fresh view that says built is a refusal like any other; the next
/// pass reads the machine as built, and looks for it rather than cloning.
async fn still_wanted(core: &Core, held: &Arc<Mutex<Option<DesiredState>>>, id: &str) -> anyhow::Result<bool> {
    Ok(matches!(seen_now(core, held, id).await?, Some((Lifecycle::Running | Lifecycle::Stopped, false))))
}

/// What a fresh view says of `id`: its intent, or nothing — not in the view,
/// or no view this agent may act on. A full answer older than the view held
/// is never acted on (G_viewMonotone).
async fn intent_now(core: &Core, held: &Arc<Mutex<Option<DesiredState>>>, id: &str) -> anyhow::Result<Option<Lifecycle>> {
    Ok(seen_now(core, held, id).await?.map(|(intent, _)| intent))
}

/// What a fresh view says of `id`: its intent and whether Core has seen it
/// built, or nothing, as [`intent_now`]. A worker's `built` rides Core's own
/// JSON (finding 6 for workers); a view whose answer is not held reads as
/// built, so nothing is built on it.
async fn seen_now(core: &Core, held: &Arc<Mutex<Option<DesiredState>>>, id: &str) -> anyhow::Result<Option<(Lifecycle, bool)>> {
    let known = crate::poison::lock(held, "held desired state").as_ref().map(|d| d.version).unwrap_or(0);
    let (fetched, named) = core.get_view(known).await?;
    // **No act in a restore** (lifecycle phase 8, TD11): one that began
    // between the pass's read and this one is caught here. Tombstones are
    // the pass's to read; a view below the head is caught by either.
    if crate::restore::observe(&core.restore, &fetched, named.as_deref(), |_| false) {
        eprintln!("the view read again before an act names a restore; nothing is done on it");
        return Ok(None);
    }
    let view = if fetched.unchanged {
        match crate::poison::lock(held, "held desired state").clone() {
            Some(d) => d,
            None => return Ok(None),
        }
    } else if fetched.version < known {
        eprintln!(
            "the view read again before an act is revision {}, older than the {known} this agent holds; nothing is done on it",
            fetched.version
        );
        return Ok(None);
    } else {
        *crate::poison::lock(held, "held desired state") = Some(fetched.clone());
        fetched
    };
    let worker_built = |id: &str| {
        crate::poison::lock(&core.built, "workers sent as built").built(view.version, id).unwrap_or(true)
    };
    Ok(view
        .instances
        .iter()
        .find(|s| s.id == id)
        .map(|s| (s.intent, s.built))
        .or_else(|| view.inference_workers.iter().find(|s| s.id == id).map(|s| (s.intent, worker_built(&s.id)))))
}

#[cfg(test)]
mod heartbeat_tests {
    /// Zero and absent are both "not said"; anything else is Core's number.
    #[tokio::test]
    async fn a_zero_heartbeat_interval_is_not_obeyed() {
        let secs = |v: serde_json::Value| super::heartbeat_secs(&v);
        assert_eq!(secs(serde_json::json!({"heartbeat_interval_secs": 0})), 30);
        assert_eq!(secs(serde_json::json!({})), 30);
        assert_eq!(secs(serde_json::json!({"heartbeat_interval_secs": 15})), 15);
        // And the period it yields is one tokio accepts.
        let _ = tokio::time::interval(std::time::Duration::from_secs(secs(
            serde_json::json!({"heartbeat_interval_secs": 0}),
        )));
    }
}

#[cfg(test)]
mod mirror_tests {
    /// The transfer is not on the reconcile path.
    ///
    /// **Why a source check and not a behavioural one.** The property is
    /// *where* an await happens, and nothing observable distinguishes a fast
    /// mirror awaited inline from one handed to another task — the difference
    /// only appears with seven gigabytes and a teardown waiting behind it,
    /// which is exactly the run this test exists so nobody has to repeat.
    ///
    /// **Scoped to one function body**, per the rule this repository has paid
    /// for three times: a file-wide search for `mirror_images` would match the
    /// spawn in `run`, the definition, and the sentence you are reading.
    #[test]
    fn reconcile_hands_the_mirror_off_rather_than_awaiting_it() {
        let src = include_str!("agent.rs");
        let start = src
            .find("async fn reconcile_workers(")
            .expect("reconcile_workers is gone; this check has to move with it");
        // The body ends at the first closing brace in column zero after it,
        // which is how every top-level item in this file ends.
        let body = &src[start..];
        let end = body.find("\n}\n").expect("unterminated function");
        let body = &body[..end];

        assert!(
            !body.contains("mirror_images("),
            "reconcile_workers awaits the image transfer again. A 7 GB download on this path \
             holds desired state: on 16 September a machine Core had released went on holding \
             an RTX 3090 for fifty minutes. Write the catalogue to mirror_wanted and notify."
        );
        assert!(
            body.contains("mirror_kick.notify_one()"),
            "reconcile_workers no longer wakes the mirror, so images would only ever be fetched \
             when something else happened to notify it."
        );
    }
}
