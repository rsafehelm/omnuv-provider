//! The Provider Agent loop.
//!
//! Runs inside the provider environment, holds the runtime credentials locally,
//! and reports normalized state upward. It never receives marketplace decision
//! logic and never exposes the Proxmox API outward.

use omnuv_protocol::{
    DesiredState, InstanceState, InstanceStatus, Lifecycle, StatusReport, WorkerState, WorkerStatus,
};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::audit;
use crate::config::AgentConfig;
use crate::driver::ComputeDriver;
use crate::proxmox;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

struct Core {
    http: reqwest::Client,
    base: String,
    token: String,
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
    fn new(url: &str, token: &str) -> anyhow::Result<Self> {
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
        Ok(Self { http, base, token: token.to_string() })
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let res = self
            .http
            .get(format!("{}{path}", self.base))
            .bearer_auth(&self.token)
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
        let res = self
            .http
            .get(&a.url)
            .bearer_auth(&self.token)
            // Deliberately long, and not the 30 seconds every other call uses:
            // a 6 GB transfer over a provider's uplink is not a hung request,
            // and killing it at 30 seconds would mean no image ever arrives.
            .timeout(std::time::Duration::from_secs(6 * 3600))
            .send()
            .await?;
        anyhow::ensure!(res.status().is_success(), "GET {}: {}", a.url, res.status());

        if let Some(parent) = part.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut f = tokio::fs::File::create(&part).await?;
        let mut hasher = sha2::Sha256::new();
        let mut written: u64 = 0;
        let mut stream = res.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            hasher.update(&chunk);
            written += chunk.len() as u64;
            f.write_all(&chunk).await?;
        }
        f.flush().await?;
        drop(f);

        let got = crate::images::hex(&hasher.finalize());
        if got != a.sha256 || written != a.bytes {
            // Removed, not kept for inspection: a file that is nearly right is
            // the most dangerous thing in this directory.
            let _ = tokio::fs::remove_file(&part).await;
            anyhow::bail!(
                "{}: the marketplace published {} bytes sha256 {}; {written} bytes sha256 {got} \
                 arrived. Not imported.",
                a.id,
                a.bytes,
                a.sha256
            );
        }
        tokio::fs::rename(&part, dest).await?;
        Ok(())
    }

    async fn post(&self, path: &str, body: Option<serde_json::Value>) -> anyhow::Result<reqwest::Response> {
        let mut req = self
            .http
            .post(format!("{}{path}", self.base))
            .bearer_auth(&self.token)
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
    let driver = Arc::new(proxmox::Client::new(
        &cfg.proxmox.api_url,
        cfg.proxmox.tls_fingerprint_sha256.as_deref(),
        &cfg.proxmox.token_id,
        &cfg.proxmox.token_secret,
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
    .with_images(cfg.proxmox.image_map()));
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

    let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(heartbeat_secs));
    let mut inventory = tokio::time::interval(std::time::Duration::from_secs(cfg.inventory_every_secs));
    // Reconciliation is push-driven; this interval is only the fallback for a
    // provider with no live tunnel.
    let mut reconcile = tokio::time::interval(std::time::Duration::from_secs(120));
    // Push for latency, pull for truth (CLAUDE.md, *The Three Tiers*): Core
    // pushes a nudge when something changes, this interval is what makes a
    // lost nudge cost latency rather than correctness.

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                match core.post("/provider/v1/heartbeat", None).await {
                    // A restarted core no longer knows this agent; re-handshake
                    // rather than heartbeating into the void forever.
                    Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => {
                        eprintln!("heartbeat rejected; re-running handshake");
                        let _ = handshake(&core, &driver).await;
                    }
                    Ok(r) if !r.status().is_success() => eprintln!("heartbeat: {}", r.status()),
                    Err(e) => eprintln!("heartbeat failed: {e}"),
                    _ => {}
                }
            }
            _ = nudge.notified() => {
                if let Err(e) = reconcile_workers(&core, &driver, &cfg, &endpoints, &held).await {
                    eprintln!("reconcile (pushed) failed: {e}");
                }
            }
            _ = reconcile.tick() => {
                if let Err(e) = reconcile_workers(&core, &driver, &cfg, &endpoints, &held).await {
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

async fn handshake(core: &Core, driver: &impl ComputeDriver) -> anyhow::Result<u64> {
    let body = serde_json::json!({
        "agent_version": AGENT_VERSION,
        "protocol_versions": [omnuv_protocol::PROTOCOL_VERSION],
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
    let mut report = driver.inventory().await?;
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
    if wanted.is_empty() {
        return Ok(());
    }

    // The storage the artefact is *staged* in, which is not the storage the
    // disk ends up on. It has to be one Proxmox knows, with `import` content,
    // because the agent's token deliberately lacks `Sys.Modify` and PVE refuses
    // an arbitrary path to anyone but root@pam.
    let import_storage = crate::names::STORAGE_SNIPPETS;
    let storage = cfg.proxmox.contribute.storage.first().map(String::as_str).unwrap_or("local");
    let dir = std::path::Path::new(&cfg.proxmox.snippet_dir)
        .parent()
        .unwrap_or(std::path::Path::new(crate::names::VAR))
        .join("import");

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
    if fetched.protocol_version != omnuv_protocol::PROTOCOL_VERSION {
        anyhow::bail!(
            "core speaks protocol v{}, this agent speaks v{}",
            fetched.protocol_version,
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

    // **Before the early return below, deliberately.** A provider with nothing
    // running is precisely the provider that should be fetching images: it has
    // no work to do and everything to prepare. Put this after the "nothing to
    // reconcile" shortcut and a fresh provider would mirror nothing until its
    // first machine was placed on it — which is the one moment the download
    // needs to have already happened.
    //
    // Failures are logged, not propagated. An image that will not download is
    // a provider with fewer things it can earn from; it is not a reason to
    // stop converging the machines it already has.
    if !desired.images.is_empty()
        && let Err(e) = mirror_images(core, driver, cfg, node, &desired.images).await
    {
        eprintln!("image mirror: {e}");
    }

    if desired.inference_workers.is_empty()
        && desired.instances.is_empty()
        && desired.gateways.is_empty()
    {
        return Ok(());
    }

    let storage = cfg.proxmox.contribute.storage.first().map(String::as_str).unwrap_or("local");

    // Gateways first: each carries one buyer network's traffic and creates
    // that network's segment here, and a buyer VM that comes up before them
    // simply has nowhere to talk to yet. A failure here is reported and does
    // not stop workers or instances converging — the control plane does not
    // run on the overlay, so a broken gateway is a degraded buyer network,
    // not a degraded provider.
    let mut checks: Vec<omnuv_protocol::SelfCheck> = Vec::new();
    let mut links: Vec<omnuv_protocol::LinkReport> = Vec::new();
    let mut gateways = Vec::new();
    for spec in &desired.gateways {
        let status = if spec.lifecycle == Lifecycle::Deleted {
            match driver.delete_gateway(node, &spec.id, &spec.network_id).await {
                Ok(()) => omnuv_protocol::GatewayStatus {
                    id: spec.id.clone(),
                    state: omnuv_protocol::GatewayState::Offline,
                    retryable: None,
                    waiting_on: None,
                    local_id: None,
                    overlay_address: None,
                    adapters: Vec::new(),
                    diagnostics: None,
                    message: Some("deleted".into()),
                },
                Err(e) => {
                    eprintln!("gateway {}: {e}", spec.id);
                    continue;
                }
            }
        } else {
            driver
                .ensure_gateway(node, cfg.proxmox.template_vmid, storage, &cfg.proxmox.snippet_dir, spec)
                .await
                .unwrap_or_else(|e| {
                    eprintln!("gateway {}: {e}", spec.id);
                    omnuv_protocol::GatewayStatus {
                        id: spec.id.clone(),
                        state: omnuv_protocol::GatewayState::Error,
                        retryable: None,
                        waiting_on: None,
                        local_id: None,
                        overlay_address: None,
                        adapters: Vec::new(),
                        diagnostics: None,
                        message: Some(e.to_string().chars().take(400).collect()),
                    }
                })
        };
        // Presence is not health. The status above says the VM exists and is
        // running; these say whether it can reach anything, which is a
        // different question that fails on its own.
        if spec.lifecycle != Lifecycle::Deleted
            && let Some(vmid) = status.local_id.as_deref().and_then(|v| v.parse::<u32>().ok())
        {
            checks.extend(driver.gateway_checks(node, vmid, &spec.id).await);
            // The same status file, read for its numbers rather than its
            // yes/no answers: which peers this gateway has, whether each is
            // direct, and how far away it feels.
            links.extend(driver.gateway_links(node, vmid, &spec.id).await);
        }
        gateways.push(status);
    }
    // Anything tagged as a gateway that Core did not just ask for, running or
    // deleted, is left over from before and goes.
    match driver.reap_stale_gateways(node, &desired.gateways).await {
        Ok(0) => {}
        Ok(n) => println!("reaped {n} stale gateway(s)"),
        Err(e) => eprintln!("stale gateways: {e}"),
    }

    let mut statuses = Vec::new();
    for spec in &desired.inference_workers {
        let result = match spec.lifecycle {
            Lifecycle::Deleted => driver
                .delete_inference_worker(node, &spec.id)
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
                        node,
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
    for spec in &desired.instances {
        let result = match spec.lifecycle {
            Lifecycle::Deleted => driver.delete_instance(node, &spec.id, &cfg.proxmox.snippet_dir).await.map(|_| InstanceStatus {
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
            eprintln!("instance {}: {e}", spec.id);
            let why = e.to_string();
            // Why, and whether trying again could plausibly work. Without this
            // Core has to poll to learn anything, and it will re-drive an
            // impossible request until its horizon for no reason.
            let retryable = !why.contains("is not offered by this provider");
            InstanceStatus {
                id: spec.id.clone(),
                rebooted_token: None,
                state: InstanceState::Error,
                retryable: Some(retryable),
                waiting_on: (!retryable).then(|| "a provider that offers this image".to_string()),
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

    let report = StatusReport {
        protocol_version: omnuv_protocol::PROTOCOL_VERSION,
        // What this agent actually did since the last report, in its own
        // words. Bounded here and again at Core.
        audit: audit::drain(100),
        workers: statuses,
        instances,
        gateways,
        // Reported every pass, not only when something is wrong: a check that
        // is only sent on failure is indistinguishable from one that stopped
        // running.
        checks,
        // How each gateway actually reaches its peers, with the latency it
        // measured. Same rule: sent every pass, so an empty list means "no
        // links seen" rather than "nothing changed".
        links,
    };
    let res = core.post("/provider/v1/status", Some(serde_json::to_value(&report)?)).await?;
    if !res.status().is_success() {
        anyhow::bail!("core rejected status report: {}", res.status());
    }
    Ok(())
}
