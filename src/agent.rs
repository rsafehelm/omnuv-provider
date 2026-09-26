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
        Ok(Self { http, base, token: token.clone(), session: Default::default() })
    }

    /// The credential and, when Core minted one, the session: what every call
    /// to Core carries. A Core that minted none is sent no header, as before.
    fn authed(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let req = req.bearer_auth(self.token.expose());
        match crate::session::current(&self.session) {
            Some(s) => req.header(crate::session::HEADER, s),
            None => req,
        }
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
    core: &Core,
) -> Vec<String> {
    let mut out: Vec<String> = runtime_checks(cfg, driver).await.iter().map(check_line).collect();
    // Core, over TLS. Not the overlay — by design nothing here may depend on
    // it, and this check exists partly to keep that honest.
    out.insert(1, core_check(core, &cfg.core.url, &cfg.timings.hash()).await);
    out
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
    vec![runtime, tls]
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

pub async fn run(cfg: AgentConfig) -> anyhow::Result<()> {
    // Shared with the image mirror's own task, which outlives no call here
    // but does outlive every reconcile pass.
    let cfg = Arc::new(cfg);
    let driver = Arc::new(proxmox::Client::new(
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
    .with_environment(cfg.environment.clone())
    .with_timings(cfg.timings.clone()));
    let core = Core::new(&cfg.core.url, &cfg.core.token)?;
    // What every heartbeat says this agent runs, computed once: the file does
    // not change under a running agent, because a change is a restart (D34).
    let config_hash = cfg.timings.hash();

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
    for line in startup_checks(&cfg, &driver, &core).await {
        println!("{line}");
    }

    let heartbeat_secs = handshake(&core, &driver).await?;

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
                        eprintln!("image mirror: no node to mirror onto: {e}");
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
                    eprintln!("image mirror: {e}");
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
    // The inventory carries the disclosure, whose freshness is judged on
    // Core's poll too: see `inventory_period`.
    let mut inventory =
        tokio::time::interval(inventory_period(cfg.timings.inventory_every.std(), crate::timings::poll(core_poll)));
    // Push for latency, pull for truth (CLAUDE.md, *The Three Tiers*): Core
    // pushes a nudge when something changes, this interval is what makes a
    // lost nudge cost latency rather than correctness.

    loop {
        tokio::select! {
            ended = &mut heartbeat => {
                anyhow::bail!("heartbeat task ended unexpectedly: {ended:?}");
            }
            _ = nudge.notified() => {
                if let Err(e) = reconcile_workers(&core, &driver, &cfg, &endpoints, &held, &mirror_wanted, &mirror_kick, &mut core_poll).await {
                    match refusal(&e) {
                        Refusal::Final => stop_for_good(&e),
                        Refusal::Renegotiate => {
                            eprintln!("reconcile (pushed) failed: {e}; re-running handshake");
                            if let Err(h) = handshake(&core, &driver).await {
                                if refusal(&h) == Refusal::Final {
                                    stop_for_good(&h);
                                }
                                eprintln!("handshake failed: {h}");
                            }
                        }
                        _ => eprintln!("reconcile (pushed) failed: {e}"),
                    }
                }
            }
            _ = reconcile.tick() => {
                if let Err(e) = reconcile_workers(&core, &driver, &cfg, &endpoints, &held, &mirror_wanted, &mirror_kick, &mut core_poll).await {
                    match refusal(&e) {
                        Refusal::Final => stop_for_good(&e),
                        Refusal::Renegotiate => {
                            eprintln!("reconcile failed: {e}; re-running handshake");
                            if let Err(h) = handshake(&core, &driver).await {
                                if refusal(&h) == Refusal::Final {
                                    stop_for_good(&h);
                                }
                                eprintln!("handshake failed: {h}");
                            }
                        }
                        _ => eprintln!("reconcile failed: {e}"),
                    }
                }
            }
            _ = inventory.tick() => {
                if let Err(e) = report_inventory(&core, &driver, cfg.proxmox.offered_images()).await {
                    // Never exit on a transient failure: the agent is a daemon,
                    // and a provider that gives up looks identical to one that
                    // died. Missed heartbeats already mark it offline.
                    eprintln!("inventory report failed: {e}");
                }
            }
        }
        // Re-armed, not restarted, when Core's poll moved: the first look at
        // the new period is one period away, so a change costs no extra pass.
        if let Some(period) = repoll(reconcile.period(), core_poll) {
            println!("poll: every {}s, as Core asks (was {}s)", period.as_secs(), reconcile.period().as_secs());
            reconcile = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        }
        let every = inventory_period(cfg.timings.inventory_every.std(), crate::timings::poll(core_poll));
        if every != inventory.period() {
            println!("inventory: every {}s, twice per Core poll (was {}s)", every.as_secs(), inventory.period().as_secs());
            inventory = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        }
    }
}

/// How often the inventory is reported: `timings.inventoryEvery`, and never
/// less often than twice per Core poll.
///
/// **The inventory carries the node's disclosure**, and Core stops selling a
/// node whose disclosure is two of its polls old (D10; Core's
/// `inventory::disclosure_fresh_secs`). At the 300 s default against Core's
/// 120 s poll, every node was unsellable for the last minute of every five.
/// Twice per poll leaves one missed report still fresh, which is the tolerance
/// Core's window was built for. Core owns the poll (D33), so this derives from
/// it rather than keeping a second copy of the window.
fn inventory_period(configured: std::time::Duration, core_poll: std::time::Duration) -> std::time::Duration {
    configured.min(core_poll / 2)
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
                        eprintln!("heartbeat handshake failed: {e}");
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
                Err(e) => eprintln!("heartbeat failed: {e}"),
                _ => {}
            }
        }
    })
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
        ] {
            let (base, _rx) = session_stub(move |_, _| ("200 OK", answer.clone())).await;
            let core = Core::new(&base, &omnuv_protocol::Redacted::from("t".to_string())).unwrap();
            assert_eq!(still_absent(&core, &held, "m").await.unwrap(), want_absent, "{why}: still_absent");
            assert_eq!(still_wanted(&core, &held, "m").await.unwrap(), want_wanted, "{why}: still_wanted");
        }
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
            let core = Core { http: reqwest::Client::new(), base: base.clone(), token: "fixture".into(), session: Default::default() };
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
        let core = Core { http: reqwest::Client::new(), base: base.clone(), token: "t".into(), session: Default::default() };
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
        let core = Core { http: reqwest::Client::new(), base: base.clone(), token: "t".into(), session: Default::default() };
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

    /// **A disclosure is never two of Core's polls old while the agent is
    /// reporting** (D10): the inventory goes at least twice per poll, and the
    /// configured interval still wins when it is the shorter.
    #[test]
    fn the_inventory_goes_at_least_twice_per_core_poll() {
        let secs = std::time::Duration::from_secs;
        // The shipped defaults: 300 s configured, Core's 120 s poll, whose
        // window is 240 s. Five minutes between reports outlived it.
        assert_eq!(inventory_period(secs(300), crate::timings::poll(None)), secs(60));
        assert!(2 * inventory_period(secs(300), secs(120)) < 2 * secs(120), "one missed report went stale");
        assert_eq!(inventory_period(secs(30), secs(120)), secs(30), "a shorter configured interval is kept");
        assert_eq!(inventory_period(secs(300), crate::timings::poll(Some(1800))), secs(300));
        assert!(inventory_period(secs(1), crate::timings::poll(Some(1))) > std::time::Duration::ZERO,
                "a zero period panics the interval");
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
            }
            Err(e) => eprintln!("handshake failed: {e}"),
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
                eprintln!("image {}: {e}", artefact.id);
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
                    eprintln!("image {}: cannot read back what was written: {e}", artefact.id);
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
                eprintln!("image {}: import failed: {e}", artefact.id);
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
        Err(e) => eprintln!("could not check for pre-rename machines: {e}"),
    }

    let known = crate::poison::lock(held, "held desired state").as_ref().map(|d| d.version).unwrap_or(0);

    let fetched: DesiredState =
        match core.get_json(&format!("/provider/v1/desired-state?known={known}")).await {
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
                let specs = crate::poison::lock(held, "held desired state")
                    .as_ref()
                    .map(|d| d.instances.clone())
                    .unwrap_or_default();
                if specs.is_empty() {
                    return Err(e);
                }
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
        Err(e) => eprintln!("segment reap: {e}"),
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
                driver
                    .ensure_inference_worker(
                        cfg.proxmox.template_vmid,
                        storage,
                        &cfg.proxmox.snippet_dir,
                        spec,
                        &cfg.core.url,
                    )
                    .await
            }
        };
        // A failure on one worker must not stop the others from converging, and
        // must be visible to the operator rather than retried in silence.
        statuses.push(result.unwrap_or_else(|e| {
            unobserved_workers += 1;
            eprintln!("worker {}: {e}", spec.id);
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
                eprintln!("snippet ownership observation failed: {e}");
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
            // not seen built is cloned only if a fresh view still wants it.
            // Not wanted, or the view could not be read: nothing is built,
            // nothing is said, and the observation is incomplete.
            _ if !spec.built && !matches!(still_wanted(core, held, &spec.id).await, Ok(true)) => {
                Err(anyhow::Error::from(crate::instance::NotLookedAt(
                    "Core's view, read again just before the build, no longer wants this machine; nothing was built".into(),
                )))
            }
            _ => match cfg.proxmox.template_for(&spec.image.id) {
                Some(template) => {
                    driver.ensure_instance(node, template, storage, &cfg.proxmox.snippet_dir, spec).await
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
                eprintln!("instance {}: {e}", spec.id);
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
                    })
                }
                Err(e) => Err(e),
            },
            ok => ok,
        };
        instances.push(result.unwrap_or_else(|e| {
            unobserved_instances += 1;
            eprintln!("instance {}: {e}", spec.id);
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
            }
        }));
    }
    for i in &instances {
        println!("instance {} -> {:?} {}", i.id, i.state, i.private_ip.as_deref().unwrap_or(""));
    }
    // What each existing machine's drive refresh did, which was printed and
    // nothing else until 26 September 2026 (gap 4). After the loop, because
    // that is what fills it.
    checks.extend(driver.refreshes.drain());
    // **Residues, retried every pass and reported** (lifecycle phase 7, RC9):
    // volumes a deleted machine left, which Core no longer sends once it ended
    // the compute claim on them.
    checks.extend(driver.retry_residues(&cfg.proxmox.snippet_dir).await);
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
async fn still_wanted(core: &Core, held: &Arc<Mutex<Option<DesiredState>>>, id: &str) -> anyhow::Result<bool> {
    Ok(matches!(intent_now(core, held, id).await?, Some(Lifecycle::Running | Lifecycle::Stopped)))
}

/// What a fresh view says of `id`: its intent, or nothing — not in the view,
/// or no view this agent may act on. A full answer older than the view held
/// is never acted on (G_viewMonotone).
async fn intent_now(core: &Core, held: &Arc<Mutex<Option<DesiredState>>>, id: &str) -> anyhow::Result<Option<Lifecycle>> {
    let known = crate::poison::lock(held, "held desired state").as_ref().map(|d| d.version).unwrap_or(0);
    let fetched: DesiredState = core.get_json(&format!("/provider/v1/desired-state?known={known}")).await?;
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
    Ok(view
        .instances
        .iter()
        .find(|s| s.id == id)
        .map(|s| s.intent)
        .or_else(|| view.inference_workers.iter().find(|s| s.id == id).map(|s| s.intent)))
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
