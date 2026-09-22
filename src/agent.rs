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
        Ok(Self { http, base, token: token.clone() })
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let res = self
            .http
            .get(format!("{}{path}", self.base))
            .bearer_auth(self.token.expose())
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await?;
        if !res.status().is_success() {
            anyhow::bail!("GET {path}: {}", res.status());
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
            .http
            .get(&a.url)
            .bearer_auth(self.token.expose())
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
        // is abort so the next tick can start again.
        const IDLE: std::time::Duration = std::time::Duration::from_secs(120);
        let outcome: anyhow::Result<()> = async {
            loop {
                match tokio::time::timeout(IDLE, stream.next()).await {
                    Err(_) => anyhow::bail!(
                        "no bytes for {}s after {written} of {}; the transfer is dead",
                        IDLE.as_secs(),
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
            .http
            .post(format!("{}{path}", self.base))
            .bearer_auth(self.token.expose())
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
    let mut out = Vec::new();

    // The runtime this agent exists to drive.
    out.push(match driver.get_json::<serde_json::Value>("/version").await {
        Ok(v) => format!(
            "selfcheck: proxmox api reachable (pve {})",
            v.get("version").and_then(|x| x.as_str()).unwrap_or("?")
        ),
        Err(e) => format!("SELFCHECK FAILED: proxmox api unreachable: {e}"),
    });

    // Core, over TLS. Not the overlay — by design nothing here may depend on
    // it, and this check exists partly to keep that honest.
    out.push(match core.post("/provider/v1/ping", None).await {
        Ok(r) if r.status().as_u16() < 500 => {
            format!("selfcheck: core reachable over tls at {}", cfg.core.url)
        }
        Ok(r) => format!("SELFCHECK FAILED: core answered {} at {}", r.status(), cfg.core.url),
        Err(e) => format!("SELFCHECK FAILED: core unreachable at {}: {e}", cfg.core.url),
    });

    // Plaintext to Core is never a shortcut that survives into a deployment.
    if cfg.core.url.starts_with("http://") {
        out.push(format!(
            "SELFCHECK FAILED: core url {} is plaintext; every control-plane hop must be TLS",
            cfg.core.url
        ));
    }
    out
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
        cfg.proxmox.showall,
    )?
    .with_images(cfg.proxmox.image_map())
    .with_environment(cfg.environment.clone()));
    let core = Core::new(&cfg.core.url, &cfg.core.token)?;

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
    // hour later. These print at start and are reported on the first pass, so a
    // misconfiguration is visible where it happened.
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
        let map = endpoints.clone();
        let nudge_tx = nudge.clone();
        // Consoles are opened by the driver on the node it manages; the
        // tunnel only ever sees the runtime-neutral opener.
        let consoles: Arc<dyn crate::console::ConsoleOpener> = Arc::new(crate::console::DriverConsoles {
            driver: driver.clone(),
            node: cfg.proxmox.node.clone().unwrap_or_default(),
        });
        tokio::spawn(async move {
            let resolve: crate::tunnel::ResolveWorker = Arc::new(move |worker_id: &str| {
                // Blocking lock inside a sync closure: the map is tiny and
                // contended only by the reconcile loop.
                map.lock().ok()?.get(worker_id).cloned()
            });
            crate::tunnel::run(&url, &token, resolve, nudge_tx, consoles).await;
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
            let node = cfg.proxmox.node.clone().unwrap_or_default();
            loop {
                kick.notified().await;
                let catalogue = wanted.lock().map(|w| w.clone()).unwrap_or_default();
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
    );
    let mut inventory = tokio::time::interval(std::time::Duration::from_secs(cfg.inventory_every_secs));
    // Reconciliation is push-driven; this interval is only the fallback for a
    // provider with no live tunnel.
    let mut reconcile = tokio::time::interval(std::time::Duration::from_secs(120));
    // Push for latency, pull for truth (CLAUDE.md, *The Three Tiers*): Core
    // pushes a nudge when something changes, this interval is what makes a
    // lost nudge cost latency rather than correctness.

    loop {
        tokio::select! {
            ended = &mut heartbeat => {
                anyhow::bail!("heartbeat task ended unexpectedly: {ended:?}");
            }
            _ = nudge.notified() => {
                if let Err(e) = reconcile_workers(&core, &driver, &cfg, &endpoints, &held, &mirror_wanted, &mirror_kick).await {
                    eprintln!("reconcile (pushed) failed: {e}");
                }
            }
            _ = reconcile.tick() => {
                if let Err(e) = reconcile_workers(&core, &driver, &cfg, &endpoints, &held, &mirror_wanted, &mirror_kick).await {
                    eprintln!("reconcile failed: {e}");
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
    }
}

fn spawn_heartbeat<D: ComputeDriver + Send + Sync + 'static>(
    core: Core,
    driver: Arc<D>,
    period: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            match core.post("/provider/v1/heartbeat", None).await {
                Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => {
                    eprintln!("heartbeat rejected; re-running handshake");
                    if let Err(e) = handshake(&core, &driver).await {
                        eprintln!("heartbeat handshake failed: {e}");
                    }
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

    /// A runtime operation remains pending while several heartbeats arrive.
    /// Even a rejected request does not end the task or wait for reconciliation.
    #[tokio::test]
    async fn heartbeat_progresses_during_a_pending_runtime_operation() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let core = Core {
            http: reqwest::Client::new(),
            base: format!("http://{}", listener.local_addr().unwrap()),
            token: "heartbeat-fixture".into(),
        };
        let (seen_tx, mut seen_rx) = tokio::sync::mpsc::channel(3);
        let server = tokio::spawn(async move {
            for i in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let mut bytes = [0; 1024];
                    let n = socket.read(&mut bytes).await.unwrap();
                    assert!(n > 0 && request.len() + n < 8192);
                    request.extend_from_slice(&bytes[..n]);
                }
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
    });

    // Core may simply not be up yet at boot; keep trying with a bounded backoff.
    let mut delay = 2u64;
    loop {
        match core.post("/provider/v1/handshake", Some(body.clone())).await {
            Ok(r) if r.status().is_success() => {
                let v: serde_json::Value = r.json().await?;
                let secs = v.get("heartbeat_interval_secs").and_then(|x| x.as_u64()).unwrap_or(30);
                println!(
                    "handshake ok: provider {} protocol v{} heartbeat {}s",
                    v.get("provider_id").and_then(|x| x.as_str()).unwrap_or("?"),
                    v.get("protocol_version").and_then(|x| x.as_u64()).unwrap_or(0),
                    secs
                );
                return Ok(secs);
            }
            Ok(r) => {
                let status = r.status();
                let detail = r.text().await.unwrap_or_default();
                eprintln!("handshake rejected ({status}): {detail}");
                if status == reqwest::StatusCode::UNAUTHORIZED {
                    anyhow::bail!("enrollment token rejected; re-enrol this provider");
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
            if let Err(e) = core.download_artefact(artefact, &dest).await {
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
) -> anyhow::Result<()> {
    let node = cfg.proxmox.node.as_deref().unwrap_or_default();

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

    let known = held.lock().ok().and_then(|h| h.as_ref().map(|d| d.version)).unwrap_or(0);

    let fetched: DesiredState =
        match core.get_json(&format!("/provider/v1/desired-state?known={known}")).await {
            Ok(d) => d,
            Err(e) => {
                // Core is unreachable. Maintain, do not decide: the copy in
                // hand is stale, so nothing is created and nothing is
                // destroyed, but a machine that was meant to be running and
                // has crashed is started again. An outage of the control plane
                // must not become an outage of somebody's machine.
                let specs = held
                    .lock()
                    .ok()
                    .and_then(|h| h.as_ref().map(|d| d.instances.clone()))
                    .unwrap_or_default();
                if specs.is_empty() {
                    return Err(e);
                }
                match driver.maintain(node, &specs).await {
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

    // `unchanged` saves the transfer, never the work: reconciliation runs every
    // tick against the copy in hand, because drift on the hypervisor is exactly
    // what this loop exists to correct.
    let desired = if fetched.unchanged {
        match held.lock().ok().and_then(|h| h.clone()) {
            Some(d) => d,
            // Core says nothing changed but we hold nothing. Ask again in full
            // rather than reconciling against an empty picture, which would
            // read as "delete everything".
            None => core.get_json("/provider/v1/desired-state").await?,
        }
    } else {
        if let Ok(mut h) = held.lock() {
            *h = Some(fetched.clone());
        }
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
        if let Ok(mut w) = mirror_wanted.lock() {
            w.clone_from(&desired.images);
        }
        mirror_kick.notify_one();
    }

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
    let checks: Vec<omnuv_protocol::SelfCheck> = Vec::new();

    let mut statuses = Vec::new();
    let mut unobserved_workers = 0usize;
    for spec in &desired.inference_workers {
        let result = match spec.intent {
            Lifecycle::Absent => driver
                .delete_inference_worker(&spec.id, &cfg.proxmox.snippet_dir)
                .await
                .map(|_| WorkerStatus {
                    id: spec.id.clone(),
                    state: WorkerState::Offline,
                    retryable: None,
                    waiting_on: None,
                    local_id: None,
                    endpoint: None,
                    adapters: Vec::new(),
                    diagnostics: None,
                    message: Some("deleted".into()),
                    telemetry: None,
                }),
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
        let Ok(mut map) = endpoints.lock() else { return Ok(()) };
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
            Lifecycle::Absent => driver.delete_instance(node, &spec.id, &cfg.proxmox.snippet_dir).await.map(|_| InstanceStatus {
                id: spec.id.clone(),
                rebooted_token: None,
                state: InstanceState::Stopped,
                retryable: None,
                waiting_on: None,
                local_id: None,
                private_ip: None,
                adapters: Vec::new(),
                diagnostics: None,
                message: Some("deleted".into()),
                recipe_progress: None,
            }),
            // The image names a template this provider must have. Refusing
            // here, with the reason reported, is what keeps the scheduler's
            // provider_images honest: Core only places images we said we offer.
            _ => match cfg.proxmox.template_for(&spec.image.id) {
                Some(template) => {
                    driver.ensure_instance(node, template, storage, &cfg.proxmox.snippet_dir, spec).await
                }
                None => Err(anyhow::anyhow!("image {} is not offered by this provider", spec.image.id)),
            },
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
