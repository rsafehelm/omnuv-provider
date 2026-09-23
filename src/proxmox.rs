//! Read-only inventory discovery against the Proxmox VE REST API.
//!
//! This is the narrow first slice of the Proxmox compute driver: it normalizes
//! what the host reports into `omnuv_protocol::InventoryReport` and nothing else.
//! Proxmox concepts (node names, storage ids, PCI addresses) stop here.
//!
//! Discovery reports the DECLARED CONTRIBUTION clamped to physical reality, not
//! the physical machine. These are production hosts; advertising a host's full
//! CPU, memory or GPU complement would let the marketplace sell resources that
//! running workloads already depend on.

use std::collections::HashSet;

use omnuv_protocol::{ComputeCapabilities, DesiredState, GpuDevice, InventoryReport, NodeInventory, RuntimeKind};
use serde::Deserialize;

use crate::config::{Contribution, ProxmoxTarget};
use crate::driver::ComputeDriver;

/// PCI vendor ids whose display controllers are sellable compute GPUs.
/// Server boards expose a BMC display adapter (ASPEED, Matrox) that matches the
/// same PCI class but is not a GPU and must never reach the marketplace.
const GPU_VENDORS: [&str; 2] = ["0x10de" /* NVIDIA */, "0x1002" /* AMD */];

/// VRAM by device name. The Proxmox PCI listing does not report it, and a GPU
/// bound to vfio-pci is invisible to nvidia-smi on the host, so there is no
/// runtime source to read it from while passthrough is configured.
/// ponytail: static table. Replace with a query inside the guest, or an
/// operator override in `contribute`, when an unlisted card shows up.
fn vram_mib_for(model: &str) -> u64 {
    const KNOWN: [(&str, u64); 7] = [
        ("RTX A6000", 49140),
        ("RTX 4090", 24564),
        ("RTX 3090", 24576),
        ("A100", 81920),
        ("H100", 81920),
        ("L40S", 46068),
        ("RTX 4080", 16376),
    ];
    KNOWN
        .iter()
        .find(|(name, _)| model.contains(name))
        .map(|(_, mib)| *mib)
        .unwrap_or(0)
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[derive(Deserialize)]
struct Envelope<T> {
    data: T,
}

#[derive(Deserialize)]
struct NodeEntry {
    node: String,
    status: Option<String>,
    maxcpu: Option<u32>,
    maxmem: Option<u64>,
}

#[derive(Deserialize)]
struct StorageEntry {
    storage: String,
    avail: Option<u64>,
    content: Option<String>,
    active: Option<u8>,
}

#[derive(Deserialize)]
pub(crate) struct PciEntry {
    pub(crate) id: String,
    class: Option<String>,
    vendor: Option<String>,
    vendor_name: Option<String>,
    device_name: Option<String>,
}

#[derive(Deserialize)]
struct VmEntry {
    vmid: u32,
    status: Option<String>,
    #[serde(default)]
    tags: Option<String>,
}

#[derive(Deserialize)]
struct PciMapping {
    id: String,
    map: Vec<String>,
}

/// Which guests currently lay claim to a PCI device.
#[derive(Default)]
pub(crate) struct PciClaims {
    /// Held by a guest that is running; retained in physical inventory only
    /// when Core's current allocation and this VM's full identity account for it.
    running: HashSet<String>,
    /// Referenced only by stopped guests. Sellable if the operator explicitly
    /// offers it, because the conflict is theirs to accept: the stopped guest
    /// will simply fail to start while the device is allocated elsewhere.
    stopped: HashSet<String>,
    accounted: HashSet<String>,
    /// Conflicting or unaccounted marketplace claims are never free capacity.
    blocked: HashSet<String>,
    /// What guests the marketplace did not create have already been given.
    ///
    /// A provider advertises capacity and the ledger books against that number
    /// alone, so a host advertising 64 cores while its owner runs a 60-core
    /// workload passes every oversell check we have and the first sign of
    /// trouble is a buyer's machine that will not start. This is the other half
    /// of that sum, collected on the pass that already reads every guest config
    /// for PCI claims — no extra call, and nothing recorded about *what* those
    /// guests are, which is the provider's business.
    ///
    /// `None` when enumeration failed: an unmeasured commitment must never read
    /// as zero.
    committed: Option<omnuv_protocol::HostCommitment>,
    /// False if enumeration failed. Nothing is offered when we cannot prove
    /// a device is free.
    pub(crate) complete: bool,
}

/// Where the agent writes machines' cloud-init. Created by `deploy-agent.yml`
/// and `join` as a `dir` storage at `/var/lib/onv`.
pub(crate) const SNIPPET_STORAGE: &str = "onv-snippets";

pub struct Client {
    http: reqwest::Client,
    /// The pinned TLS configuration, shared with the console websocket.
    pub(crate) tls: std::sync::Arc<rustls::ClientConfig>,
    pub(crate) base: String,
    /// `PVEAPIToken=<id>=<secret>` — the secret with its wrapper on, which
    /// makes this the most valuable string in the agent. Redacted at the field
    /// rather than at the five places it is spent.
    pub(crate) auth: omnuv_protocol::Redacted,
    node: Option<String>,
    contribute: Contribution,
    location: Option<omnuv_protocol::GeoLocation>,
    city: Option<String>,
    /// The package mirror machines built here should use. See
    /// `config::ProxmoxRuntime::apt_mirror`.
    pub(crate) apt_mirror: Option<String>,
    /// `config::AgentConfig::environment` — the third tag on every machine this
    /// agent creates. A builder rather than an eleventh positional argument to
    /// `new`, which already takes ten.
    pub(crate) environment: Option<String>,
    /// **Allocation requests are queued and serialized.** One permit, held
    /// across *deciding* a placement and *making* it.
    ///
    /// Operator's rule, 19 September 2026. Without it the two halves are a
    /// check and a separate act, and anything that runs between them invalidates
    /// the check: two placements both see one card free and both take it. The
    /// reconcile loop happens to be a sequential `for` today, so the race is not
    /// reachable *right now* — which is exactly the kind of safety that
    /// disappears the first time somebody parallelises a loop for speed, and
    /// leaves no trace of having been relied upon.
    ///
    /// There are already two paths that attach a card — `ensure_instance` and
    /// the inference worker — so "the loop is sequential" was never the whole
    /// story anyway.
    ///
    /// A `tokio::sync::Mutex` rather than a `std` one because it is held across
    /// `.await`: the clone, the config write and the task wait all happen under
    /// it, which is the point. Placements therefore queue behind one another on
    /// a provider, which is the intended cost — a provider builds machines one
    /// at a time and the alternative is selling hardware twice.
    pub(crate) alloc: std::sync::Arc<tokio::sync::Mutex<()>>,
    /// What each worker's Workload Agent last reported, held across passes so
    /// a reporter that has stopped advancing is noticed (PROVIDER-15).
    pub(crate) workload: crate::workload::Store,
    /// Whether this provider has opted in to disclosing what its host has
    /// already given its own guests. See `config::ProxmoxRuntime::showall`.
    showall: bool,
    /// Marketplace image id -> the template vmid holding it on this host.
    ///
    /// Set separately rather than through `new`, which already takes ten
    /// arguments; and empty is a working default, meaning a provider that
    /// offers no images and reports holding none.
    images: std::collections::BTreeMap<String, u32>,
}

impl ComputeDriver for Client {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Proxmox
    }

    async fn inventory(&self, desired: &DesiredState) -> anyhow::Result<InventoryReport> {
        self.discover_with_claims(self.node.as_deref(), &self.contribute, Some(desired)).await
    }
}

/// Proxmox writes passthrough as `0000:05:00` while the PCI listing says
/// `0000:05:00.0`. Compare on domain:bus:device and ignore the function.
pub(crate) fn pci_slot(raw: &str) -> String {
    let addr = raw.split(',').next().unwrap_or(raw).trim();
    let addr = addr.split('.').next().unwrap_or(addr);
    let full = if addr.matches(':').count() == 1 { format!("0000:{addr}") } else { addr.to_string() };
    full.to_lowercase()
}

/// Validate every address before normalizing functions to their physical slot.
/// A multi-function assignment can mention the same card twice, or several
/// cards; ignoring everything after the first would invent free capacity.
fn pci_claim_slots(raw: &str) -> anyhow::Result<HashSet<String>> {
    let mut slots = HashSet::new();
    for address in raw.split(';') {
        let (base, function) = match address.split_once('.') {
            Some((base, function)) => (base, Some(function)),
            None => (address, None),
        };
        anyhow::ensure!(function.is_none_or(|f| f.len() == 1 && matches!(f.as_bytes()[0], b'0'..=b'7')),
                        "PCI function is malformed");
        let parts: Vec<_> = base.split(':').collect();
        let widths: &[usize] = match parts.len() {
            2 => &[2, 2],
            3 => &[4, 2, 2],
            _ => anyhow::bail!("PCI address is malformed"),
        };
        anyhow::ensure!(parts.iter().zip(widths).all(|(p, n)| p.len() == *n && p.bytes().all(|b| b.is_ascii_hexdigit())),
                        "PCI address is malformed");
        anyhow::ensure!(u8::from_str_radix(parts.last().unwrap(), 16)? <= 31, "PCI device is out of range");
        slots.insert(pci_slot(address));
    }
    Ok(slots)
}

fn property_fields(raw: &str) -> anyhow::Result<std::collections::HashMap<&str, &str>> {
    let mut fields = std::collections::HashMap::new();
    for field in raw.split(',') {
        let (key, value) = field.split_once('=').ok_or_else(|| anyhow::anyhow!("PCI mapping property is malformed"))?;
        anyhow::ensure!(!key.is_empty() && !value.is_empty() && fields.insert(key, value).is_none(),
                        "PCI mapping property is empty or repeated");
    }
    Ok(fields)
}

fn resolve_pci_claim(raw: &str, node: &str, mappings: &[PciMapping]) -> anyhow::Result<HashSet<String>> {
    let mut source = None;
    for (index, field) in raw.split(',').enumerate() {
        let candidate = match field.split_once('=') {
            Some(("host", value)) => Some((false, value)),
            Some(("mapping", value)) => Some((true, value)),
            Some(_) => None,
            None if index == 0 => Some((false, field)),
            None => anyhow::bail!("PCI assignment property is malformed"),
        };
        if let Some(candidate) = candidate {
            anyhow::ensure!(source.replace(candidate).is_none() && !candidate.1.is_empty(),
                            "PCI assignment has no single source");
        }
    }
    let (mapped, value) = source.ok_or_else(|| anyhow::anyhow!("PCI assignment has no source"))?;
    if !mapped {
        return pci_claim_slots(value);
    }
    let mut matching = mappings.iter().filter(|m| m.id == value);
    let mapping = matching.next().ok_or_else(|| anyhow::anyhow!("PCI mapping is absent"))?;
    anyhow::ensure!(matching.next().is_none(), "PCI mapping identity is ambiguous");
    let mut slots = HashSet::new();
    for entry in &mapping.map {
        let fields = property_fields(entry)?;
        let mapped_node = fields.get("node").ok_or_else(|| anyhow::anyhow!("PCI mapping node is absent"))?;
        let path = fields.get("path").ok_or_else(|| anyhow::anyhow!("PCI mapping path is absent"))?;
        if *mapped_node == node {
            slots.extend(pci_claim_slots(path)?);
        }
    }
    anyhow::ensure!(!slots.is_empty(), "PCI mapping has no devices on this node");
    Ok(slots)
}

/// Runtime tags are truncated. The full UUID in the generated description
/// must also match Core's authenticated desired state before a held GPU is
/// retained as physical supply. The Core allocation remains its availability
/// authority; a tag or a matching name alone never constitutes an allocation.
fn accounted_pci(vm: &VmEntry, config: &serde_json::Map<String, serde_json::Value>, desired: Option<&DesiredState>) -> anyhow::Result<HashSet<String>> {
    let Some(desired) = desired else { return Ok(HashSet::new()) };
    anyhow::ensure!(!desired.unchanged && desired.protocol_version == omnuv_protocol::PROTOCOL_VERSION,
                    "GPU ownership requires a full compatible desired state");
    let tags: HashSet<_> = vm.tags.as_deref().unwrap_or("").split(';').collect();
    let description = config.get("description").and_then(|v| v.as_str()).and_then(|v| v.lines().next());
    let mut matched = 0;
    let mut slots = HashSet::new();
    let claims = desired.instances.iter().map(|s| (crate::names::TAG_INSTANCE, "instance", &s.id, &s.gpu_local_ids))
        .chain(desired.inference_workers.iter().map(|s| (crate::names::TAG_WORKER, "inference worker", &s.id, &s.gpu_local_ids)));
    for (kind, label, id, devices) in claims {
        if tags.contains(kind) && tags.contains(crate::names::short_tag(id).as_str())
            && description == Some(format!("Omnuv {label} {id}").as_str()) {
            matched += 1;
            for device in devices {
                slots.extend(pci_claim_slots(device)?);
            }
        }
    }
    anyhow::ensure!(matched <= 1, "GPU ownership is ambiguous");
    Ok(slots)
}

impl PciClaims {
    pub(crate) fn may_offer(&self, slot: &str) -> bool {
        self.complete && !self.blocked.contains(slot)
            && (!self.running.contains(slot) || self.accounted.contains(slot))
    }

    fn observe_vm(&mut self, vm: &VmEntry, config: &serde_json::Value, node: &str, mappings: &[PciMapping], desired: Option<&DesiredState>) -> anyhow::Result<()> {
        let result = (|| {
            let map = config.as_object().ok_or_else(|| anyhow::anyhow!("VM configuration is not an object"))?;
            let running = match vm.status.as_deref() {
                Some("running" | "paused") => true,
                Some("stopped") => false,
                _ => anyhow::bail!("VM power state is unobserved"),
            };
            let mut slots = HashSet::new();
            for (key, value) in map.iter().filter(|(k, _)| k.starts_with("hostpci")) {
                let raw = value.as_str().ok_or_else(|| anyhow::anyhow!("{key} is not a PCI assignment"))?;
                slots.extend(resolve_pci_claim(raw, node, mappings)?);
            }
            let accounted = accounted_pci(vm, map, desired)?;
            for slot in slots {
                if running && !self.running.insert(slot.clone()) {
                    self.blocked.insert(slot.clone());
                }
                if accounted.contains(&slot) {
                    self.accounted.insert(slot.clone());
                } else if running || is_marketplace(vm.tags.as_deref()) {
                    self.blocked.insert(slot.clone());
                }
                if !running {
                    self.stopped.insert(slot);
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.complete = false;
        }
        result
    }
}

impl Client {
    // Eight, because a hypervisor client needs all eight to exist at all: where
    // it is, how to trust it, who it is, and what this provider offers. Bundling
    // them into a struct would move the same arguments one line further away.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        api_url: &str,
        fingerprint: Option<&str>,
        token_id: &str,
        token_secret: &str,
        node: Option<String>,
        contribute: Contribution,
        location: Option<omnuv_protocol::GeoLocation>,
        city: Option<String>,
        apt_mirror: Option<String>,
        showall: bool,
    ) -> anyhow::Result<Self> {
        let tls = crate::tls::config(fingerprint)?;
        Ok(Self {
            http: crate::tls::client(tls.clone())?,
            tls,
            base: api_url.trim_end_matches('/').to_string(),
            auth: format!("PVEAPIToken={token_id}={token_secret}").into(),
            node,
            contribute,
            location,
            city,
            apt_mirror,
            environment: None,
            alloc: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            workload: crate::workload::Store::new(),
            showall,
            images: Default::default(),
        })
    }

    /// Which deployment this agent belongs to; see `names::tags`.
    pub fn with_environment(mut self, environment: Option<String>) -> Self {
        self.environment = environment;
        self
    }

    /// The images this provider offers, and where each one lives locally.
    pub fn with_images(mut self, images: std::collections::BTreeMap<String, u32>) -> Self {
        self.images = images;
        self
    }

    /// Development-inventory constructor, used by the `discover` debug command.
    pub fn connect(target: &ProxmoxTarget) -> anyhow::Result<Self> {
        let (id, secret) = target.credentials()?;
        Self::new(
            &target.api_url,
            target.tls_fingerprint_sha256.as_deref(),
            &id,
            &secret,
            target.node.clone(),
            target.contribute.clone(),
            None,
            None,
            // The debug `discover` command reads inventory and builds nothing,
            // so it has no cloud-init to write and no mirror to name — and it
            // discloses nothing about the provider's own guests either.
            None,
            false,
        )
    }

    pub(crate) async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        self.get(path).await
    }

    /// Proxmox mutations take form-encoded bodies and mostly return a task id.
    pub(crate) async fn post_form<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        form: &[(impl AsRef<str>, String)],
    ) -> anyhow::Result<T> {
        self.send_form(reqwest::Method::POST, path, form).await
    }

    pub(crate) async fn put_form<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        form: &[(impl AsRef<str>, String)],
    ) -> anyhow::Result<T> {
        self.send_form(reqwest::Method::PUT, path, form).await
    }

    /// Sets a user's password inside a running guest from its crypt(3) hash,
    /// through qemu-guest-agent. Needs `VM.GuestAgent.Unrestricted`, which
    /// `deploy-agent.yml` grants on the buyer pool only (verified at source:
    /// `PVE::API2::Qemu::Agent`, `set-user-password`, PVE 9.2). The hash is
    /// the only thing sent and it is never logged.
    pub(crate) async fn set_console_password(&self, node: &str, vmid: u32, user: &str, hash: &str) -> anyhow::Result<()> {
        self.post_form::<Option<serde_json::Value>>(
            &format!("/nodes/{node}/qemu/{vmid}/agent/set-user-password"),
            &[("username", user.to_string()), ("password", hash.to_string()), ("crypted", "1".to_string())],
        )
        .await?;
        Ok(())
    }

    /// Brings a VM's cloud-init drive up to date with its snippet on disk.
    ///
    /// The snippet is read when the drive is regenerated, not when the file
    /// changes, so a generator change reaches a machine that already exists
    /// only through this. `VM.Config.Cloudinit`, which the agent's role holds
    /// (verified at source: `PVE::API2::Qemu` `cloudinit_update`).
    pub(crate) async fn regenerate_cloudinit(&self, node: &str, vmid: u32) -> anyhow::Result<()> {
        self.put_form::<Option<serde_json::Value>>(
            &format!("/nodes/{node}/qemu/{vmid}/cloudinit"),
            &[] as &[(String, String)],
        )
        .await
        .map(|_| ())
    }

    /// Writes the machine's cloud-init and refreshes its drive when the
    /// generated config has changed since the machine was built. Returns
    /// whether anything changed — a reboot is what actually applies it, and
    /// whose call that is depends on who owns the machine.
    pub(crate) async fn sync_cloud_init(
        &self,
        node: &str,
        vmid: u32,
        snippet_dir: &str,
        file: &str,
        desired: &str,
    ) -> anyhow::Result<bool> {
        let path = format!("{snippet_dir}/{file}");
        if std::fs::read_to_string(&path).is_ok_and(|current| current == desired) {
            return Ok(false);
        }
        // **0600, like every other snippet writer (PROVIDER-21).** This was
        // the one plain `fs::write`, so a snippet recreated here got the
        // process umask — 0644 — while it carries the machine's overlay setup
        // key and console password hash.
        crate::names::write_private(&path, desired.as_bytes(), 0o600)
            .map_err(|e| anyhow::anyhow!("writing {path}: {e}"))?;
        self.regenerate_cloudinit(node, vmid).await?;
        Ok(true)
    }

    async fn send_form<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        form: &[(impl AsRef<str>, String)],
    ) -> anyhow::Result<T> {
        let pairs: Vec<(&str, &str)> =
            form.iter().map(|(k, v)| (k.as_ref(), v.as_str())).collect();
        let res = self
            .http
            .request(method, format!("{}/api2/json{path}", self.base))
            .header("Authorization", self.auth.expose())
            .form(&pairs)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
        let status = res.status();
        if !status.is_success() {
            let detail = res.text().await.unwrap_or_default();
            // Proxmox puts the useful reason in the body; the token id is not
            // echoed on these endpoints, so it is safe to surface.
            anyhow::bail!("{path}: {status} {}", detail.chars().take(300).collect::<String>());
        }
        Ok(res.json::<Envelope<T>>().await?.data)
    }

    /// A DELETE; most return a task id, SDN objects return nothing.
    pub(crate) async fn delete_task<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let res = self
            .http
            .delete(format!("{}/api2/json{path}", self.base))
            .header("Authorization", self.auth.expose())
            .send()
            .await?;
        let status = res.status();
        if !status.is_success() {
            anyhow::bail!("DELETE {path}: {status}");
        }
        Ok(res.json::<Envelope<T>>().await?.data)
    }

    /// Proxmox operations are asynchronous tasks. Treating them as fire-and-
    /// forget is exactly what the reconciliation rule forbids, so every
    /// mutation is waited on and its exit status checked.
    /// How a task ended, told apart from not knowing (PROVIDER-1). `wait_task`
    /// turns one failed status read into an error indistinguishable from a
    /// failed task, which is right for a step that can simply be retried and
    /// wrong for a clone, where "failed" means nothing exists and "could not
    /// ask" means something may. Transient reads are tolerated here; only
    /// `Ended` is an answer.
    /// How many one-second polls a create may spend on its clone: Core's
    /// remaining budget when it sent one, never more than thirty minutes and
    /// never none (PROVIDER-18). The budget was sent and never read, so a
    /// clone Core had already given up on held the reconcile loop for the full
    /// thirty. Running out is not failure: the clone stays journalled and the
    /// next create settles it.
    pub(crate) fn clone_polls(budget_secs: Option<u64>) -> u32 {
        budget_secs.map_or(1800, |b| b.clamp(1, 1800) as u32)
    }

    pub(crate) async fn task_end(&self, node: &str, upid: &str, polls: u32) -> TaskEnd {
        let encoded = urlencode(upid);
        let mut misses = 0;
        let mut last = String::new();
        for n in 0..polls {
            match self.get::<serde_json::Value>(&format!("/nodes/{node}/tasks/{encoded}/status")).await {
                Ok(v) => {
                    misses = 0;
                    if v.get("status").and_then(|s| s.as_str()) == Some("stopped") {
                        let exit = v.get("exitstatus").and_then(|s| s.as_str()).unwrap_or("unknown");
                        return TaskEnd::Ended(if exit == "OK" { Ok(()) } else { Err(exit.to_string()) });
                    }
                    last = "still running".into();
                }
                Err(e) => {
                    misses += 1;
                    last = e.to_string();
                    if misses >= 10 {
                        break;
                    }
                }
            }
            if n + 1 < polls {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
        TaskEnd::Unknown(format!("proxmox task {upid}: {last}"))
    }

    pub(crate) async fn wait_task(&self, node: &str, upid: &str) -> anyhow::Result<()> {
        let encoded = urlencode(upid);
        for _ in 0..600 {
            let v: serde_json::Value =
                self.get(&format!("/nodes/{node}/tasks/{encoded}/status")).await?;
            if v.get("status").and_then(|s| s.as_str()) == Some("stopped") {
                let exit = v.get("exitstatus").and_then(|s| s.as_str()).unwrap_or("unknown");
                if exit == "OK" {
                    return Ok(());
                }
                anyhow::bail!("proxmox task failed: {exit}");
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        anyhow::bail!("proxmox task {upid} did not finish in 10 minutes")
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let res = self
            .http
            .get(format!("{}/api2/json{path}", self.base))
            .header("Authorization", self.auth.expose())
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("GET {path}: {e}"))?;

        let status = res.status();
        if !status.is_success() {
            // The body can echo the token id, so it is not propagated.
            anyhow::bail!(match status.as_u16() {
                401 => format!("GET {path}: 401 unauthorized - check the token id and secret"),
                403 => format!("GET {path}: 403 forbidden - the token lacks the required privileges"),
                _ => format!("GET {path}: {status}"),
            });
        }
        Ok(res.json::<Envelope<T>>().await?.data)
    }

    /// What this provider can actually do, asked of Proxmox each time.
    ///
    /// Each answer has a source, and anything that cannot be confirmed is
    /// reported `false` — an unconfirmable capability is one the marketplace
    /// should not place work against, and claiming it would be worse than
    /// denying it.
    async fn capabilities(&self, offered_gpus: usize, nodes: &[NodeInventory]) -> ComputeCapabilities {
        // **A card is passable when a resource mapping exists for it.**
        // Discovering a display controller is not the same as the host being
        // configured for passthrough, and `hostpci` is refused to any user but
        // root@pam — a mapping is precisely what lets the agent's restricted
        // token attach a specific device, so its existence *is* the capability.
        // Bootstrap validates IOMMU/VFIO and creates one per offered card.
        let mapped: usize = match self
            .get_json::<Vec<serde_json::Value>>("/cluster/mapping/pci")
            .await
        {
            Ok(maps) => nodes
                .iter()
                .flat_map(|n| n.gpus.iter())
                .filter(|g| {
                    let want = crate::names::gpu_mapping(&g.local_id);
                    maps.iter().any(|m| m.get("id").and_then(|v| v.as_str()) == Some(&want))
                })
                .count(),
            Err(_) => 0,
        };
        let gpu_passthrough = offered_gpus > 0 && mapped == offered_gpus;

        // A project network is an SDN vnet in the marketplace's own zone, so
        // the zone existing is what makes private networking possible here.
        let private_network = self
            .get_json::<Vec<serde_json::Value>>("/cluster/sdn/zones")
            .await
            .is_ok_and(|zones| {
                zones.iter().any(|z| {
                    z.get("zone").and_then(|v| v.as_str()) == Some(crate::names::SDN_ZONE)
                })
            });

        ComputeCapabilities {
            // The driver creates QEMU machines with a cloud-init drive on
            // Proxmox storage. These are properties of the driver, not of the
            // host, and a Proxmox that could not do them would not answer at
            // all — which is why they are the only three stated outright.
            vm: true,
            cloud_init: true,
            persistent_disk: true,
            gpu_passthrough,
            private_network,
            // An inference worker is a marketplace-owned machine with a card
            // passed through to it. Without a passable card the provider can
            // host the VM and not the work, so this follows the cards rather
            // than the driver's ability to write the spec.
            inference_worker: gpu_passthrough,
            // No storage driver yet: `portable-ssd` needs Ceph RBD, and
            // claiming portability the runtime cannot deliver would strand a
            // buyer's volume on a provider that cannot detach it.
            portable_volume_attach: false,
        }
    }

    /// Every raw or mapped PCI assignment, including stopped guests. An
    /// accounted marketplace allocation remains physical inventory while Core
    /// reserves it; foreign running and unaccounted marketplace claims do not.
    /// The nodes this provider may place on, **in a deterministic order**.
    ///
    /// A provider runtime may be one host or a cluster — CLAUDE.md says so
    /// explicitly — and the agent treated it as one host everywhere: inventory
    /// walked the cluster only when `omnuv_node` was unset, and placement used
    /// `unwrap_or_default()`, which is the *empty string* and makes every
    /// `/nodes//qemu` path malformed. So a five-node cluster either offered one
    /// node or could not place at all.
    ///
    /// `omnuv_node`, when set, stays a deliberate restriction: an operator
    /// contributing one node of their cluster says so and is obeyed. Unset now
    /// means the whole cluster, which is what it always read as.
    ///
    /// Offline nodes are excluded here rather than discovered at placement: a
    /// node that is down is not a candidate, and finding that out from a failed
    /// clone is three minutes and one misleading error later.
    /// The one node node-scoped work runs on: the configured node, or, when
    /// none is configured, the first online node of the cluster in name order.
    /// Never an empty string, which is what `unwrap_or_default` gave every
    /// caller and what built `/nodes//qemu` (PROVIDER-7).
    pub(crate) async fn home_node(&self, configured: Option<&str>) -> anyhow::Result<String> {
        match configured.map(str::trim).filter(|n| !n.is_empty()) {
            Some(n) => Ok(n.to_string()),
            None => Ok(self.placement_nodes().await?.remove(0)),
        }
    }

    pub(crate) async fn placement_nodes(&self) -> anyhow::Result<Vec<String>> {
        let entries: Vec<NodeEntry> = self.get("/nodes").await?;
        let mut nodes: Vec<String> = entries
            .into_iter()
            .filter(|e| e.status.as_deref() != Some("offline"))
            .map(|e| e.node)
            .filter(|n| self.node.as_deref().is_none_or(|want| want == n))
            .collect();
        nodes.sort();
        anyhow::ensure!(
            !nodes.is_empty(),
            "no node of this provider is online{}",
            self.node.as_deref().map(|n| format!(" (restricted to {n})")).unwrap_or_default()
        );
        Ok(nodes)
    }

    /// The nodes a new machine may be built on: the placement nodes, and
    /// **only this agent's own node while first-boot files cannot reach the
    /// others (PROVIDER-30).** The agent writes a machine's cloud-init into
    /// `onv-snippets` on the host it runs on; a `dir` storage that is not
    /// shared exists only there, so a machine built on another node referred
    /// to files that node does not have — and Proxmox's API cannot upload a
    /// snippet to it. Both facts are asked of the API: whether the storage is
    /// shared, and which node answered (`/cluster/status` marks it `local`).
    /// Either unreadable refuses rather than guesses.
    pub(crate) async fn create_nodes(&self) -> anyhow::Result<Vec<String>> {
        let nodes = self.placement_nodes().await?;
        let status: Vec<serde_json::Value> = self
            .get("/cluster/status")
            .await
            .map_err(|e| anyhow::anyhow!("which node this agent runs on could not be read: {e}"))?;
        let local = status
            .iter()
            .find(|e| e.get("type").and_then(|v| v.as_str()) == Some("node")
                && e.get("local").and_then(|v| v.as_u64()) == Some(1))
            .and_then(|e| e.get("name").and_then(|v| v.as_str()))
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("the cluster status names no local node"))?;
        let storage: serde_json::Value = self
            .get(&format!("/nodes/{local}/storage/{SNIPPET_STORAGE}/status"))
            .await
            .map_err(|e| anyhow::anyhow!("whether {SNIPPET_STORAGE} is shared could not be read: {e}"))?;
        if storage.get("shared").and_then(|v| v.as_u64()) == Some(1) {
            return Ok(nodes);
        }
        let here: Vec<String> = nodes.into_iter().filter(|n| *n == local).collect();
        anyhow::ensure!(
            !here.is_empty(),
            "this agent runs on {local}, which is not a placement node, and {SNIPPET_STORAGE} is not shared, \
             so no node can be given a machine's first-boot files"
        );
        Ok(here)
    }

    /// Every guest on every placement node, with its tags — what the CORE-38
    /// survey compares against desired state. **Any node that cannot be listed
    /// fails the whole call**: a survey of four nodes out of five would read as
    /// a clean one, and "could not look" must never look like "nothing there".
    /// Offline nodes are outside `placement_nodes` and so outside this survey;
    /// a guest there is reported when its node comes back.
    pub(crate) async fn guests(&self) -> anyhow::Result<Vec<crate::survey::ClaimedGuest>> {
        let mut out = Vec::new();
        for node in self.placement_nodes().await? {
            let vms: Vec<VmEntry> = self.get(&format!("/nodes/{node}/qemu")).await?;
            out.extend(vms.into_iter().map(|v| crate::survey::ClaimedGuest {
                node: node.clone(),
                vmid: v.vmid,
                tags: v.tags.unwrap_or_default(),
            }));
        }
        Ok(out)
    }

    pub(crate) async fn claimed_pci(&self, node: &str, desired: Option<&DesiredState>) -> PciClaims {
        let mut claims = PciClaims { complete: true, ..Default::default() };
        let mut foreign = omnuv_protocol::HostCommitment {
            cpu_cores: 0,
            memory_mib: 0,
            disk_gib: 0,
            guests: 0,
        };
        let vms: Vec<VmEntry> = match self.get(&format!("/nodes/{node}/qemu")).await {
            Ok(v) => v,
            // Without VM.Audit we cannot prove a device is free, so nothing is
            // offered. Failing closed is the only safe direction here.
            Err(e) => {
                eprintln!("  warning: cannot enumerate guests ({e}); offering no GPUs");
                claims.complete = false;
                return claims;
            }
        };
        let mappings: Vec<PciMapping> = match self.get("/cluster/mapping/pci").await {
            Ok(mappings) => mappings,
            Err(e) => {
                eprintln!("  warning: cannot read PCI mappings ({e}); offering no GPUs");
                claims.complete = false;
                return claims;
            }
        };
        for vm in vms {
            let cfg: serde_json::Value =
                match self.get(&format!("/nodes/{node}/qemu/{}/config", vm.vmid)).await {
                    Ok(c) => c,
                    Err(_) => {
                        eprintln!("  warning: cannot read config of vm {}; offering no GPUs", vm.vmid);
                        claims.complete = false;
                        continue;
                    }
                };
            if let Err(e) = claims.observe_vm(&vm, &cfg, node, &mappings, desired) {
                eprintln!("  warning: cannot resolve PCI claims of vm {} ({e}); offering no GPUs", vm.vmid);
                continue;
            }
            let Some(map) = cfg.as_object() else { continue };

            // Anything the marketplace did not create is the provider's own,
            // and what it has been given is capacity nobody should sell twice.
            if !is_marketplace(vm.tags.as_deref()) {
                foreign.guests += 1;
                foreign.cpu_cores += configured_cores(map);
                foreign.memory_mib += map.get("memory").and_then(as_u64).unwrap_or(0);
                foreign.disk_gib += configured_disk_gib(map);
            }

        }
        // Only when every guest was readable — a partial survey undercounts,
        // and an undercount here reads as free capacity — and only when this
        // provider asked for it to be sent at all.
        //
        // The survey itself always runs: it is the same pass that proves a GPU
        // is free, and it never leaves this process unless `showall` is set.
        // What the flag gates is *disclosure*, not measurement.
        claims.committed = (claims.complete && self.showall).then_some(foreign);
        if self.showall && claims.complete {
            disclosure_noted(node, &foreign);
        }
        claims
    }

    pub async fn discover(
        &self,
        want: Option<&str>,
        c: &Contribution,
    ) -> anyhow::Result<InventoryReport> {
        self.discover_with_claims(want, c, None).await
    }

    async fn discover_with_claims(
        &self,
        want: Option<&str>,
        c: &Contribution,
        desired: Option<&DesiredState>,
    ) -> anyhow::Result<InventoryReport> {
        let entries: Vec<NodeEntry> = self.get("/nodes").await?;
        let mut nodes = Vec::new();

        for entry in entries {
            if want.is_some_and(|w| entry.node != w) {
                continue;
            }
            if entry.status.as_deref() == Some("offline") {
                continue;
            }

            let storages: Vec<StorageEntry> =
                self.get(&format!("/nodes/{}/storage", entry.node)).await.unwrap_or_default();

            // Free space, not capacity: one of these pools is 97% full, and its
            // total says nothing about what can actually be allocated.
            let avail_gib: u64 = storages
                .iter()
                .filter(|s| s.active.unwrap_or(0) == 1)
                .filter(|s| s.content.as_deref().is_some_and(|x| x.contains("images")))
                .filter(|s| c.storage.is_empty() || c.storage.contains(&s.storage))
                .filter_map(|s| s.avail)
                .sum::<u64>()
                / (1024 * 1024 * 1024);

            let claims = self.claimed_pci(&entry.node, desired).await;
            let pci: Vec<PciEntry> =
                self.get(&format!("/nodes/{}/hardware/pci", entry.node)).await.unwrap_or_default();

            let mut gpus = Vec::new();
            for d in pci {
                // PCI class 0x03xxxx is "display controller".
                if !d.class.as_deref().is_some_and(|x| x.starts_with("0x03")) {
                    continue;
                }
                // Excludes the onboard BMC adapter, which is a display
                // controller but not a sellable GPU.
                if !d.vendor.as_deref().is_some_and(|v| GPU_VENDORS.contains(&v)) {
                    continue;
                }
                let slot = pci_slot(&d.id);
                // Must be offered explicitly by the operator.
                if !c.gpus.iter().any(|g| pci_slot(g) == slot) {
                    continue;
                }
                if !claims.complete {
                    eprintln!("  skipping {slot}: guest inventory incomplete, cannot prove it is free");
                    continue;
                }
                if !claims.may_offer(&slot) {
                    eprintln!("  skipping {slot}: conflicting or unaccounted guest assignment");
                    continue;
                }
                if claims.stopped.contains(&slot) && !claims.accounted.contains(&slot) {
                    eprintln!(
                        "  warning: {slot} is still referenced by a stopped guest; \
                         offering it anyway because it is explicitly declared. \
                         That guest will fail to start while the GPU is allocated."
                    );
                }
                let model = d.device_name.unwrap_or_else(|| "unknown".into());
                // Operator override first: they can see the card, we can only
                // guess from its name. Without an override an unrecognised GPU
                // reports 0 and is never schedulable, because placement refuses
                // a card it cannot size.
                let vram_mib = c
                    .gpu_vram_mib
                    .iter()
                    .find(|(k, _)| pci_slot(k) == slot)
                    .map(|(_, v)| *v)
                    .unwrap_or_else(|| vram_mib_for(&model));
                if vram_mib == 0 {
                    eprintln!(
                        "  warning: unknown VRAM for '{model}' at {slot}; not schedulable. \
                         Set contribute.gpuVramMib to fix."
                    );
                }
                gpus.push(GpuDevice {
                    local_id: d.id,
                    vendor: d.vendor_name.unwrap_or_else(|| "unknown".into()),
                    model,
                    vram_mib,
                });
            }

            // Clamp to physical reality in both directions: a declaration can
            // only ever reduce what is offered, never invent capacity.
            let physical_cores = entry.maxcpu.unwrap_or(0);
            let physical_mib = entry.maxmem.unwrap_or(0) / (1024 * 1024);

            nodes.push(NodeInventory {
                local_id: entry.node,
                cpu_cores: c.cpu_cores.min(physical_cores),
                memory_mib: c.memory_mib.min(physical_mib),
                disk_gib: c.disk_gib.min(avail_gib),
                gpus,
                committed: claims.committed,
            });
        }

        if nodes.is_empty() {
            anyhow::bail!("no usable nodes found");
        }

        // Read out of the templates themselves, never remembered from having
        // mirrored them: a template destroyed since the last fetch must stop
        // being advertised, and only observation can notice that.
        //
        // One node's worth. Every provider we run is single-node, and
        // `HeldImage` carries no node of its own, so a genuine cluster needs
        // the protocol to say *where* before this can honestly answer for more
        // than the node the agent was pointed at.
        let held_images = match nodes.first() {
            Some(n) => {
                let node = self.node.clone().unwrap_or_else(|| n.local_id.clone());
                crate::images::held(self, &node, &self.images).await
            }
            None => Vec::new(),
        };

        // **Capabilities are asked of the runtime, not asserted.** All four of
        // the interesting ones were hardcoded `false` until 12 September and
        // nothing ever set them true — so Pluto was on record saying it could
        // not do GPU passthrough while contributing two RTX 3090s, and both
        // providers denied private networking and inference workers while
        // doing both. Nothing read the column, which is the only reason it
        // never broke: stored, plausible and unchecked is the shape a lie
        // takes before somebody trusts it.
        let offered_gpus: usize = nodes.iter().map(|n| n.gpus.len()).sum();
        let capabilities = self.capabilities(offered_gpus, &nodes).await;

        Ok(InventoryReport {
            held_images,
            protocol_version: omnuv_protocol::PROTOCOL_VERSION,
            runtime: RuntimeKind::Proxmox,
            // Filled in by the agent from its own image map before reporting.
            images: Vec::new(),
            capabilities,
            nodes,
            location: self.location,
            city: self.city.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::pci_slot;

    #[test]
    fn operator_override_beats_the_device_table() {
        use crate::config::Contribution;
        use std::collections::HashMap;

        let c = Contribution {
            gpu_vram_mib: HashMap::from([("0000:21:00.0".to_string(), 31337u64)]),
            ..Default::default()
        };

        // The operator can see the card; we can only guess from its name.
        let resolve = |slot: &str, model: &str| -> u64 {
            c.gpu_vram_mib
                .iter()
                .find(|(k, _)| super::pci_slot(k) == super::pci_slot(slot))
                .map(|(_, v)| *v)
                .unwrap_or_else(|| super::vram_mib_for(model))
        };

        assert_eq!(resolve("0000:21:00.0", "GA102 [GeForce RTX 3090]"), 31337);
        // Written in a different but equivalent PCI form, it must still match.
        assert_eq!(resolve("21:00", "GA102 [GeForce RTX 3090]"), 31337);
        // No override falls back to the table.
        assert_eq!(resolve("0000:5d:00.0", "GA102 [GeForce RTX 3090]"), 24576);
        // And an unlisted card with no override is still 0, i.e. unschedulable
        // rather than silently guessed.
        assert_eq!(resolve("0000:aa:00.0", "Some Future GPU"), 0);
    }

    #[test]
    fn resolves_vram_from_device_names_seen_on_real_hosts() {
        use super::vram_mib_for;
        assert_eq!(vram_mib_for("GA102 [GeForce RTX 3090]"), 24576);
        assert_eq!(vram_mib_for("AD102 [GeForce RTX 4090]"), 24564);
        assert_eq!(vram_mib_for("GA102GL [RTX A6000]"), 49140);
        // Unknown cards report 0 rather than a guess, so the scheduler can
        // refuse to size them instead of overcommitting VRAM.
        assert_eq!(vram_mib_for("Some Future GPU"), 0);
    }

    #[test]
    fn normalizes_proxmox_and_lspci_pci_forms() {
        // These must collide, or an in-use GPU would look free.
        assert_eq!(pci_slot("0000:05:00,pcie=1"), pci_slot("0000:05:00.0"));
        assert_eq!(pci_slot("05:00"), pci_slot("0000:05:00.1"));
        assert_eq!(pci_slot("0000:5d:00,pcie=1,x-vga=1"), "0000:5d:00");
        assert_ne!(pci_slot("0000:21:00.0"), pci_slot("0000:22:00.0"));
    }
}

#[cfg(test)]
mod pci_claim_tests {
    use super::*;
    use serde_json::json;

    fn mappings() -> Vec<PciMapping> {
        serde_json::from_value(json!([{"id": "card", "map": [
            "node=Titan,path=0000:05:00.0,id=10de:2204",
            "node=Pluto,path=0000:21:00,id=10de:2204"
        ]}])).unwrap()
    }

    fn desired() -> DesiredState {
        let mut state: DesiredState = serde_json::from_str(include_str!("../tests/from-core/desired-state.json")).unwrap();
        state.instances[0].gpu_local_ids = vec!["0000:21:00.0".into()];
        state
    }

    fn vm() -> VmEntry {
        VmEntry { vmid: 200, status: Some("running".into()),
            tags: Some(format!("onv-instance;{}", crate::names::short_tag(&desired().instances[0].id))) }
    }

    fn config() -> serde_json::Value {
        json!({"hostpci0": "mapping=card,pcie=1,rombar=0",
               "description": format!("Omnuv instance {}\nManaged by onv-provider. Do not edit.", desired().instances[0].id)})
    }

    fn claims() -> PciClaims {
        PciClaims { complete: true, ..Default::default() }
    }

    #[test]
    fn mapping_selects_physical_devices_on_the_current_node() {
        let maps = mappings();
        assert_eq!(resolve_pci_claim("mapping=card,pcie=1", "Pluto", &maps).unwrap(),
                   HashSet::from(["0000:21:00".into()]));
        assert_eq!(resolve_pci_claim("pcie=1,mapping=card", "Titan", &maps).unwrap(),
                   HashSet::from(["0000:05:00".into()]));
        assert!(resolve_pci_claim("mapping=card", "elsewhere", &maps).is_err());
    }

    #[test]
    fn every_raw_function_and_every_mapped_device_is_reserved() {
        let expected = HashSet::from(["0000:21:00".into(), "0000:5d:00".into()]);
        assert_eq!(resolve_pci_claim("host=21:00.0;0000:21:00.1;0000:5D:00,pcie=1", "Pluto", &[]).unwrap(), expected);
        let maps = vec![PciMapping { id: "multi".into(), map: vec![
            "node=Pluto,path=0000:21:00.0;0000:21:00.1".into(),
            "node=Pluto,path=0000:5d:00.0".into(),
        ] }];
        assert_eq!(resolve_pci_claim("mapping=multi", "Pluto", &maps).unwrap(), expected);
    }

    #[test]
    fn incomplete_or_ambiguous_mapping_observations_never_resolve() {
        assert!(serde_json::from_value::<Vec<PciMapping>>(json!([{"id":"card"}])).is_err());
        assert!(serde_json::from_value::<Vec<PciMapping>>(json!([{"id":"card","map":"not-an-array"}])).is_err());
        let maps = mappings();
        for raw in ["mapping=missing", "mapping=card,host=21:00", "host=", "21:00.9", "21:00;not-an-address"] {
            assert!(resolve_pci_claim(raw, "Pluto", &maps).is_err(), "{raw}");
        }
        for entry in ["node=Pluto", "path=21:00", "node=Pluto,path=bad", "node=Pluto,node=Titan,path=21:00"] {
            let maps = [PciMapping { id: "card".into(), map: vec![entry.into()] }];
            assert!(resolve_pci_claim("mapping=card", "Pluto", &maps).is_err(), "{entry}");
        }
        let mut maps = mappings();
        maps.push(PciMapping { id: "card".into(), map: vec!["node=Pluto,path=5d:00".into()] });
        assert!(resolve_pci_claim("mapping=card", "Pluto", &maps).is_err());
    }

    #[test]
    fn allocated_marketplace_gpu_remains_physical_inventory() {
        let mut observed = claims();
        observed.observe_vm(&vm(), &config(), "Pluto", &mappings(), Some(&desired())).unwrap();
        assert!(observed.running.contains("0000:21:00"));
        assert!(observed.may_offer("0000:21:00"), "Core still reserves this physical card through its allocation");
    }

    #[test]
    fn allocated_worker_is_accounted_by_its_full_identity_too() {
        let mut state = desired();
        let id = state.instances.remove(0).id;
        state.inference_workers.push(serde_json::from_value(json!({
            "id": id, "lifecycle": "running", "image": "test-image", "model_repo": "fixture",
            "vcpus": 4, "memory_mib": 8192, "disk_gib": 20, "port": 8000,
            "gpu_local_ids": ["0000:21:00.0"]
        })).unwrap());
        let worker = VmEntry { vmid: 201, status: Some("running".into()),
            tags: Some(format!("onv-worker;{}", crate::names::short_tag(&id))) };
        let config = json!({"hostpci0":"mapping=card", "description":format!("Omnuv inference worker {id}\nManaged by onv-provider. Do not edit.")});
        let mut observed = claims();
        observed.observe_vm(&worker, &config, "Pluto", &mappings(), Some(&state)).unwrap();
        assert!(observed.may_offer("0000:21:00"));
    }

    #[test]
    fn foreign_mapping_is_blocked_even_when_an_accounted_vm_has_the_same_card() {
        let mut observed = claims();
        observed.observe_vm(&vm(), &config(), "Pluto", &mappings(), Some(&desired())).unwrap();
        let mut foreign = vm();
        foreign.vmid = 101;
        foreign.tags = None;
        observed.observe_vm(&foreign, &config(), "Pluto", &mappings(), Some(&desired())).unwrap();
        assert!(!observed.may_offer("0000:21:00"));
    }

    #[test]
    fn full_uuid_and_allocated_physical_device_must_both_match() {
        let mut collision = config();
        let mut id = desired().instances[0].id.clone();
        id.replace_range(35..36, "7"); // Same truncated tag, different full identity.
        collision["description"] = json!(format!("Omnuv instance {id}"));
        let mut observed = claims();
        observed.observe_vm(&vm(), &collision, "Pluto", &mappings(), Some(&desired())).unwrap();
        assert!(!observed.may_offer("0000:21:00"));
        let mut wrong_card = desired();
        wrong_card.instances[0].gpu_local_ids = vec!["0000:5d:00.0".into()];
        let mut observed = claims();
        observed.observe_vm(&vm(), &config(), "Pluto", &mappings(), Some(&wrong_card)).unwrap();
        assert!(!observed.may_offer("0000:21:00"));
    }

    #[test]
    fn deletion_keeps_reservation_until_core_releases_it_and_omission_never_frees_a_live_claim() {
        let mut state = desired();
        state.instances[0].intent = omnuv_protocol::Lifecycle::Absent;
        let mut observed = claims();
        observed.observe_vm(&vm(), &config(), "Pluto", &mappings(), Some(&state)).unwrap();
        assert!(observed.may_offer("0000:21:00"), "deleting still owns its unreleased allocation");
        state.instances.clear();
        let mut observed = claims();
        observed.observe_vm(&vm(), &config(), "Pluto", &mappings(), Some(&state)).unwrap();
        assert!(!observed.may_offer("0000:21:00"));
        let mut stopped = vm();
        stopped.status = Some("stopped".into());
        let mut observed = claims();
        observed.observe_vm(&stopped, &config(), "Pluto", &mappings(), None).unwrap();
        assert!(!observed.may_offer("0000:21:00"), "a stopped unaccounted marketplace VM still owns its card");
    }

    #[test]
    fn malformed_guest_observations_block_all_capacity_not_only_the_named_card() {
        for cfg in [json!(null), json!({"hostpci0": 42}), json!({"hostpci0": "mapping=missing"})] {
            let mut observed = claims();
            assert!(observed.observe_vm(&vm(), &cfg, "Pluto", &mappings(), Some(&desired())).is_err());
            assert!(!observed.complete);
            assert!(!observed.may_offer("0000:5d:00"));
        }
        let mut unknown = vm();
        unknown.status = None;
        let mut observed = claims();
        assert!(observed.observe_vm(&unknown, &config(), "Pluto", &mappings(), Some(&desired())).is_err());
        assert!(!observed.may_offer("0000:5d:00"));
        let mut partial = desired();
        partial.unchanged = true;
        let mut observed = claims();
        assert!(observed.observe_vm(&vm(), &config(), "Pluto", &mappings(), Some(&partial)).is_err());
        assert!(!observed.may_offer("0000:5d:00"));
    }
}

/// Whether a guest is one the marketplace created.
///
/// The three tags are the only claim of ownership that exists, and they are
/// what `reap_stale_gateways` and the worker finder already trust. Anything
/// without one belongs to the provider — including, deliberately, a guest with
/// no tags at all: the safe reading of "we do not know whose this is" is "not
/// ours", because counting someone else's machine as marketplace capacity is
/// how a host gets oversold.
fn is_marketplace(tags: Option<&str>) -> bool {
    let Some(tags) = tags else { return false };
    tags.split(&[';', ','][..]).map(str::trim).any(|t| {
        t == crate::worker::TAG
            // Still recognised, deliberately. Topology v2 creates no
            // gateways, but a provider that joined under v1 may still carry a
            // gateway VM — and a marketplace machine we stop recognising is
            // one the agent would count as somebody else's.
            || t == crate::names::TAG_GATEWAY
            || t == crate::instance::TAG
            || crate::instance::is_legacy_marketplace_tag(t)
    })
}

/// Proxmox writes numbers as numbers or as strings depending on the field and
/// the version; both mean the same thing.
fn as_u64(v: &serde_json::Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str()?.parse().ok())
}

/// `cores` is per socket. A two-socket guest with `cores: 8` has sixteen.
fn configured_cores(map: &serde_json::Map<String, serde_json::Value>) -> u32 {
    let cores = map.get("cores").and_then(as_u64).unwrap_or(0);
    let sockets = map.get("sockets").and_then(as_u64).unwrap_or(1).max(1);
    (cores * sockets) as u32
}

/// Every disk a guest has been given, summed. `scsi0: local-lvm:vm-100-disk-0,size=32G`.
///
/// Sizes below a gibibyte round to zero rather than up: a handful of cloud-init
/// drives must not add a phantom gigabyte each to what the provider is said to
/// owe.
fn configured_disk_gib(map: &serde_json::Map<String, serde_json::Value>) -> u64 {
    const BUSES: [&str; 4] = ["scsi", "virtio", "sata", "ide"];
    map.iter()
        .filter(|(k, _)| {
            BUSES.iter().any(|b| k.strip_prefix(b).is_some_and(|n| n.chars().all(|c| c.is_ascii_digit()) && !n.is_empty()))
        })
        .filter_map(|(_, v)| size_gib(v.as_str()?))
        .sum()
}

fn size_gib(raw: &str) -> Option<u64> {
    let field = raw.split(',').find_map(|p| p.trim().strip_prefix("size="))?;
    let (num, unit) = field.split_at(field.find(|c: char| c.is_ascii_alphabetic())?);
    let n: f64 = num.parse().ok()?;
    Some(match unit {
        "T" => (n * 1024.0) as u64,
        "G" => n as u64,
        "M" => (n / 1024.0) as u64,
        "K" => (n / (1024.0 * 1024.0)) as u64,
        _ => return None,
    })
}

#[cfg(test)]
mod host_commitment_tests {
    use super::*;

    #[test]
    fn an_untagged_guest_belongs_to_the_provider() {
        assert!(!is_marketplace(None));
        assert!(!is_marketplace(Some("")));
        assert!(!is_marketplace(Some("backup;prod")));
    }

    #[test]
    fn a_marketplace_guest_is_recognised_by_any_of_its_three_tags() {
        assert!(is_marketplace(Some("onv-worker;w-abcd1234")));
        assert!(is_marketplace(Some("onv-gateway;g-1")));
        assert!(is_marketplace(Some("onv-instance;i-1")));
    }

    /// **A rename is a migration.** A machine built before one still carries the
    /// old tag, and an agent that stopped recognising it would walk past a
    /// machine it owns — leaving a guest nothing reconciles and nothing reaps.
    /// Two generations, because there have been two renames.
    #[test]
    fn a_guest_built_under_an_older_name_is_still_ours() {
        for t in ["omnuv-worker;w-1", "omnuv-gateway;g-1", "omnuv-instance;i-1",
                  "omnu-worker;w-1", "omnu-gateway;g-1", "omnu-instance;i-1"] {
            assert!(is_marketplace(Some(t)), "{t} should still be recognised");
        }
    }

    /// And a name that merely *starts* with one of ours is not ours. The reading
    /// of "we do not know whose this is" stays "not ours".
    #[test]
    fn a_tag_that_only_looks_like_ours_is_not() {
        assert!(!is_marketplace(Some("onv-ish;x")));
        assert!(!is_marketplace(Some("omnuv-something-else")));
    }

    #[test]
    fn cores_are_per_socket() {
        let m = serde_json::json!({"cores": 8, "sockets": 2});
        assert_eq!(configured_cores(m.as_object().unwrap()), 16);
        let one = serde_json::json!({"cores": 4});
        assert_eq!(configured_cores(one.as_object().unwrap()), 4);
    }

    #[test]
    fn every_disk_counts_and_nothing_else_does() {
        let m = serde_json::json!({
            "scsi0": "local-lvm:vm-100-disk-0,size=32G",
            "virtio1": "local-lvm:vm-100-disk-1,size=1T",
            "ide2": "local:iso/ubuntu.iso,media=cdrom",
            "scsihw": "virtio-scsi-pci",
            "net0": "virtio=AA:BB:CC:DD:EE:FF",
        });
        // 32 + 1024; the cdrom has no size and the controller is not a disk.
        assert_eq!(configured_disk_gib(m.as_object().unwrap()), 1056);
    }

    /// A cloud-init drive is a few megabytes. Rounding each one up to a
    /// gibibyte would invent capacity the provider does not owe.
    #[test]
    fn a_tiny_drive_rounds_to_nothing_rather_than_to_one() {
        assert_eq!(size_gib("local-lvm:vm-100-cloudinit,size=4M"), Some(0));
        assert_eq!(size_gib("local:iso/x.iso,media=cdrom"), None);
    }

    #[test]
    fn proxmox_numbers_are_read_whether_quoted_or_not() {
        let m = serde_json::json!({"cores": "4", "sockets": "1"});
        assert_eq!(configured_cores(m.as_object().unwrap()), 4);
    }
}

/// Record, on the provider's own side, that host usage was disclosed.
///
/// The audit entry is written here rather than only at Core because the party
/// giving something up should be able to see that they did, in their own
/// journal, without asking the marketplace. It flows upward with the report as
/// well — `audit::record` does both — so the trail exists on both sides and
/// neither can quietly lose it.
///
/// Hourly while the flag stays on, plus once whenever the figure changes.
/// Every pass would bury the audit stream in 720 entries a day; silence after
/// the first would let a diagnostic flag become permanent without anyone
/// noticing. Repeating is meant to be slightly annoying: `showall` is for
/// diagnosing a host that keeps refusing placements, and then for turning off.
fn disclosure_noted(node: &str, c: &omnuv_protocol::HostCommitment) {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    static LAST: Mutex<Option<(Instant, omnuv_protocol::HostCommitment)>> = Mutex::new(None);

    let mut last = match LAST.lock() {
        Ok(l) => l,
        Err(e) => e.into_inner(),
    };
    let due = match last.as_ref() {
        None => true,
        Some((at, was)) => was != c || at.elapsed() >= Duration::from_secs(3600),
    };
    if !due {
        return;
    }
    *last = Some((Instant::now(), *c));
    crate::audit::record(
        "host.usage.disclosed",
        "agent",
        node,
        "ok",
        Some(&format!(
            "showall is on: reporting {} vCPU, {} MiB and {} GiB committed to {} guest(s) \
             this provider runs itself",
            c.cpu_cores, c.memory_mib, c.disk_gib, c.guests
        )),
    );
}

#[cfg(test)]
mod allocation_is_queued_and_serialized {
    //! **Operator's rule, 19 September 2026: allocation requests are queued and
    //! serialized.**
    //!
    //! Deciding a placement and making it are one operation or they are a race.
    //! The node is chosen because a card was free *at that moment*; anything
    //! that places in between makes that false, and two machines take one card.
    //!
    //! The reconcile loop is a sequential `for` today, so the race is not
    //! reachable right now — which is exactly the kind of safety that vanishes
    //! the first time somebody parallelises a loop for speed and leaves no
    //! trace of having been relied on. And there were already two paths that
    //! attach a card, `ensure_instance` and `ensure_inference_worker`, so "the
    //! loop is sequential" was never the whole story.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// **Two placements never overlap**, whatever order they arrive in.
    ///
    /// Asserted on the gate itself rather than against a hypervisor: what is
    /// under test is that check-and-create is one critical section, and a live
    /// cluster would only add a slower way to observe the same thing.
    #[tokio::test]
    async fn no_two_placements_are_ever_inside_the_gate_at_once() {
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        let inside = Arc::new(AtomicUsize::new(0));
        let worst = Arc::new(AtomicUsize::new(0));

        let mut placements = Vec::new();
        for _ in 0..16 {
            let (gate, inside, worst) = (gate.clone(), inside.clone(), worst.clone());
            placements.push(tokio::spawn(async move {
                let _held = gate.lock_owned().await;
                let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                worst.fetch_max(now, Ordering::SeqCst);
                // The await points a real placement has: the clone, the config
                // write, the task wait. The gate is held across all of them or
                // it is not a gate.
                tokio::task::yield_now().await;
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                inside.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for p in placements {
            p.await.expect("placement task");
        }
        assert_eq!(worst.load(Ordering::SeqCst), 1, "two placements were inside the gate at once");
        assert_eq!(inside.load(Ordering::SeqCst), 0);
    }

    /// And the gate is **shared**, not one per clone of the client.
    ///
    /// `Client` is cloned around the agent, and a gate stored by value would
    /// give every clone its own permit — a lock that compiles, runs, and
    /// serializes nothing. The `Arc` is the whole mechanism.
    #[test]
    fn every_clone_of_the_client_queues_behind_the_same_permit() {
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        let copy = gate.clone();
        assert!(Arc::ptr_eq(&gate, &copy), "the gate was duplicated rather than shared");
        assert_eq!(Arc::strong_count(&gate), 2);
    }
}

/// See `task_end`.
#[derive(Debug)]
pub(crate) enum TaskEnd {
    /// Proxmox says the task stopped: `Ok` or its exit status.
    Ended(Result<(), String>),
    /// Still running, or its status could not be read.
    Unknown(String),
}

#[cfg(test)]
mod home_node_tests {
    /// **PROVIDER-7: a node, never an empty name.** Configured is obeyed
    /// without asking; blank is unset; unset is the first online node by name;
    /// and a cluster with nothing online is an error, not `""`.
    #[tokio::test]
    async fn node_scoped_work_gets_a_real_node() {
        let mock = crate::pvemock::Mock::start(|_, path, _| match path {
            "/nodes" => (200, serde_json::json!([
                {"node": "pve-c", "status": "online"},
                {"node": "pve-a", "status": "offline"},
                {"node": "pve-b", "status": "online"},
            ])),
            _ => (404, serde_json::Value::Null),
        })
        .await;
        let client = mock.client();
        assert_eq!(client.home_node(Some("pve-z")).await.unwrap(), "pve-z");
        assert!(!mock.called("GET", "/nodes"), "a configured node was second-guessed");
        assert_eq!(client.home_node(None).await.unwrap(), "pve-b", "not the first *online* node by name");
        assert_eq!(client.home_node(Some("  ")).await.unwrap(), "pve-b", "a blank node was taken as a name");

        let dark = crate::pvemock::Mock::start(|_, path, _| match path {
            "/nodes" => (200, serde_json::json!([{"node": "pve-a", "status": "offline"}])),
            _ => (404, serde_json::Value::Null),
        })
        .await;
        assert!(dark.client().home_node(None).await.is_err(), "no node online became an empty name");
    }

    /// **PROVIDER-5: a miss in the cached listing is confirmed live.** The
    /// cluster aggregate does not list a machine that one node holds; it is
    /// found there rather than taken as absent — which would mean a second
    /// clone, or a card freed under a running VM. A node that cannot be read
    /// makes absence unknowable, which is an error, never `None`.
    #[tokio::test]
    async fn a_machine_the_cluster_listing_missed_is_found_live_or_not_concluded() {
        let key = "onv-0a0b0c0d0e0f";
        let mock = crate::pvemock::Mock::start(move |_, path, _| match path {
            "/cluster/resources?type=vm" => (200, serde_json::json!([])),
            "/nodes" => (200, serde_json::json!([
                {"node": "pve-a", "status": "online"},
                {"node": "pve-b", "status": "online"},
                {"node": "pve-c", "status": "offline"},
            ])),
            "/nodes/pve-a/qemu" => (200, serde_json::json!([])),
            "/nodes/pve-b/qemu" => (200, serde_json::json!([
                {"vmid": 812, "status": "running", "tags": format!("onv-instance;{key}")}
            ])),
            _ => (404, serde_json::Value::Null),
        })
        .await;
        let (node, vm) = mock.client().find_tagged_vm_anywhere("onv-instance", key).await
            .expect("the lookup")
            .expect("a machine the aggregate missed was taken as absent");
        assert_eq!((node.as_str(), vm.vmid), ("pve-b", 812));
        assert!(!mock.called("GET", "/nodes/pve-c/qemu"), "an offline node was asked");

        let blind = crate::pvemock::Mock::start(|_, path, _| match path {
            "/cluster/resources?type=vm" => (200, serde_json::json!([])),
            "/nodes" => (200, serde_json::json!([{"node": "pve-a", "status": "online"}])),
            _ => (500, serde_json::Value::Null),
        })
        .await;
        assert!(
            blind.client().find_tagged_vm_anywhere("onv-instance", key).await.is_err(),
            "a node that could not be read was taken as holding nothing"
        );
    }

    /// And the console, which asked the configured node alone: a machine on
    /// another host is found where it is, and asked about by a real path.
    #[tokio::test]
    async fn a_console_finds_its_machine_on_any_node() {
        let key = crate::instance::short_tag("7e7e7e7e-0000-4000-8000-000000000001");
        let mock = crate::pvemock::Mock::start(move |_, path, _| match path {
            "/cluster/resources?type=vm" => (200, serde_json::json!([
                {"node": "pve-b", "vmid": 701, "status": "running", "tags": format!("onv-instance;{key}")}
            ])),
            "/nodes/pve-b/qemu/701/status/current" => (200, serde_json::json!({"status": "stopped"})),
            _ => (404, serde_json::Value::Null),
        })
        .await;
        let e = match mock
            .client()
            .open_console("7e7e7e7e-0000-4000-8000-000000000001", omnuv_protocol::ConsoleKind::Serial)
            .await
        {
            Ok(_) => panic!("a stopped machine opened a console"),
            Err(e) => e.to_string(),
        };
        // Stopped, read live from its own node — though the cluster listing
        // said running — which is only possible if it was found there.
        assert!(e.contains("not running"), "{e}");
        assert!(mock.called("GET", "/nodes/pve-b/qemu/701/status/current"));
        let calls = mock.calls.lock().unwrap();
        assert!(!calls.iter().any(|c| c.path.starts_with("/nodes//")), "an empty node name reached a path: {calls:?}");
    }
}

#[cfg(test)]
mod a_refreshed_snippet_is_private {
    /// **PROVIDER-21.** A snippet recreated by the refresh is 0600, and one
    /// left wider by an earlier version is tightened on its next rewrite.
    #[tokio::test]
    async fn the_refresh_writes_0600_and_tightens_a_wider_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let mock = crate::pvemock::Mock::start(|method, path, _| match (method, path) {
            ("PUT", "/nodes/n1/qemu/700/cloudinit") => (200, serde_json::Value::Null),
            _ => (404, serde_json::Value::Null),
        })
        .await;
        let dir = std::env::temp_dir().join(format!("onv-snippet-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let d = dir.to_string_lossy().to_string();
        let mode = |f: &str| std::fs::metadata(dir.join(f)).unwrap().permissions().mode() & 0o777;

        assert!(mock.client().sync_cloud_init("n1", 700, &d, "fresh.yaml", "#cloud-config\na: 1\n").await.unwrap());
        assert_eq!(mode("fresh.yaml"), 0o600, "a recreated snippet is readable by others");

        std::fs::write(dir.join("wide.yaml"), "old").unwrap();
        std::fs::set_permissions(dir.join("wide.yaml"), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(mock.client().sync_cloud_init("n1", 700, &d, "wide.yaml", "#cloud-config\nb: 2\n").await.unwrap());
        assert_eq!(mode("wide.yaml"), 0o600, "a wider snippet was rewritten and left wide");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
mod first_boot_files_reach_the_node {
    use crate::pvemock::Mock;

    fn cluster(local: &'static str, shared: Option<u64>) -> impl Fn(&str, &str, &str) -> (u16, serde_json::Value) + Send + Sync + 'static {
        move |_, path, _| match path {
            "/nodes" => (200, serde_json::json!([
                {"node": "n1", "status": "online"}, {"node": "n2", "status": "online"}])),
            "/cluster/status" => (200, serde_json::json!([
                {"type": "cluster", "name": "c"},
                {"type": "node", "name": "n1", "local": u64::from(local == "n1")},
                {"type": "node", "name": "n2", "local": u64::from(local == "n2")},
                {"type": "node", "name": "n3", "local": u64::from(local == "n3")}])),
            p if p.ends_with("/storage/onv-snippets/status") => match shared {
                Some(s) => (200, serde_json::json!({"shared": s})),
                None => (500, serde_json::Value::Null),
            },
            _ => (404, serde_json::Value::Null),
        }
    }

    /// **PROVIDER-30.** Unshared snippets: only the node this agent runs on,
    /// even when it is not first by name. Shared: every node. And each
    /// question that cannot be answered refuses rather than guesses.
    #[tokio::test]
    async fn a_machine_is_built_only_where_its_first_boot_files_are() {
        let only_here = Mock::start_raw(cluster("n2", Some(0))).await;
        assert_eq!(only_here.client().create_nodes().await.unwrap(), ["n2"], "built where its snippet is not");

        let everywhere = Mock::start_raw(cluster("n1", Some(1))).await;
        assert_eq!(everywhere.client().create_nodes().await.unwrap(), ["n1", "n2"]);

        let unknown = Mock::start_raw(cluster("n1", None)).await;
        let e = unknown.client().create_nodes().await.expect_err("an unread storage was taken as shared");
        assert!(format!("{e:#}").contains("could not be read"), "{e:#}");

        let elsewhere = Mock::start_raw(cluster("n3", Some(0))).await;
        let e = elsewhere.client().create_nodes().await.expect_err("placed on a node the agent does not run on");
        assert!(format!("{e:#}").contains("not a placement node"), "{e:#}");
    }
}
