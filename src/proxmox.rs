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

use omnuv_protocol::{ComputeCapabilities, GpuDevice, InventoryReport, NodeInventory, RuntimeKind};
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
struct PciEntry {
    id: String,
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

/// Which guests currently lay claim to a PCI device.
#[derive(Default)]
struct PciClaims {
    /// Held by a guest that is running. Never sellable, whatever the operator declares.
    running: HashSet<String>,
    /// Referenced only by stopped guests. Sellable if the operator explicitly
    /// offers it, because the conflict is theirs to accept: the stopped guest
    /// will simply fail to start while the device is allocated elsewhere.
    stopped: HashSet<String>,
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
    complete: bool,
}

pub struct Client {
    http: reqwest::Client,
    /// The pinned TLS configuration, shared with the console websocket.
    pub(crate) tls: std::sync::Arc<rustls::ClientConfig>,
    pub(crate) base: String,
    pub(crate) auth: String,
    node: Option<String>,
    contribute: Contribution,
    location: Option<omnuv_protocol::GeoLocation>,
    city: Option<String>,
    /// The package mirror machines built here should use. See
    /// `config::ProxmoxRuntime::apt_mirror`.
    pub(crate) apt_mirror: Option<String>,
    /// Whether this provider has opted in to disclosing what its host has
    /// already given its own guests. See `config::ProxmoxRuntime::showall`.
    showall: bool,
}

impl ComputeDriver for Client {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Proxmox
    }

    async fn inventory(&self) -> anyhow::Result<InventoryReport> {
        self.discover(self.node.as_deref(), &self.contribute).await
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
            auth: format!("PVEAPIToken={token_id}={token_secret}"),
            node,
            contribute,
            location,
            city,
            apt_mirror,
            showall,
        })
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
        std::fs::write(&path, desired).map_err(|e| anyhow::anyhow!("writing {path}: {e}"))?;
        self.regenerate_cloudinit(node, vmid).await?;
        Ok(true)
    }

    /// Writes a file inside a guest through the QEMU guest agent.
    ///
    /// Needs `VM.GuestAgent.FileWrite` on the VM. That is a root-level write
    /// into a guest, so bootstrap grants it on the gateway pool only: the agent
    /// can feed its own gateway's resolver and cannot touch a buyer VM or the
    /// provider's own machines. Proxmox base64-encodes `content` itself; the
    /// limit is 60 KiB.
    pub(crate) async fn guest_file_write(
        &self,
        node: &str,
        vmid: u32,
        file: &str,
        content: &str,
    ) -> anyhow::Result<()> {
        self.post_form::<Option<serde_json::Value>>(
            &format!("/nodes/{node}/qemu/{vmid}/agent/file-write"),
            &[("file".to_string(), file.to_string()), ("content".to_string(), content.to_string())],
        )
        .await
        .map(|_| ())
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
            .header("Authorization", &self.auth)
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
            .header("Authorization", &self.auth)
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
            .header("Authorization", &self.auth)
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

    /// Every PCI address referenced by any VM config on the node, running or
    /// stopped. A stopped VM still owns its passthrough device: selling it would
    /// break the guest the moment its owner starts it again.
    async fn claimed_pci(&self, node: &str) -> PciClaims {
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
        for vm in vms {
            let running = vm.status.as_deref() == Some("running");
            let cfg: serde_json::Value =
                match self.get(&format!("/nodes/{node}/qemu/{}/config", vm.vmid)).await {
                    Ok(c) => c,
                    Err(_) => {
                        eprintln!("  warning: cannot read config of vm {}; offering no GPUs", vm.vmid);
                        claims.complete = false;
                        continue;
                    }
                };
            let Some(map) = cfg.as_object() else { continue };

            // Anything the marketplace did not create is the provider's own,
            // and what it has been given is capacity nobody should sell twice.
            if !is_marketplace(vm.tags.as_deref()) {
                foreign.guests += 1;
                foreign.cpu_cores += configured_cores(map);
                foreign.memory_mib += map.get("memory").and_then(as_u64).unwrap_or(0);
                foreign.disk_gib += configured_disk_gib(map);
            }

            for (k, v) in map {
                if !k.starts_with("hostpci") {
                    continue;
                }
                if let Some(raw) = v.as_str() {
                    let slot = pci_slot(raw);
                    if running {
                        claims.running.insert(slot);
                    } else {
                        claims.stopped.insert(slot);
                    }
                }
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

            let claims = self.claimed_pci(&entry.node).await;
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
                if claims.running.contains(&slot) {
                    eprintln!("  skipping {slot}: passed through to a RUNNING guest");
                    continue;
                }
                if claims.stopped.contains(&slot) {
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

        Ok(InventoryReport {
            protocol_version: omnuv_protocol::PROTOCOL_VERSION,
            runtime: RuntimeKind::Proxmox,
            // Filled in by the agent from its own image map before reporting.
            images: Vec::new(),
            capabilities: ComputeCapabilities {
                vm: true,
                cloud_init: true,
                persistent_disk: true,
                // Discovering a display controller is not the same as the host
                // being configured for passthrough. IOMMU/VFIO is validated
                // during provider bootstrap; until then this stays false even
                // when GPUs are offered.
                gpu_passthrough: false,
                private_network: false,
                inference_worker: false,
                portable_volume_attach: false,
            },
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
            || t == crate::gateway::TAG
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
        assert!(is_marketplace(Some("omnuv-worker;w-abcd1234")));
        assert!(is_marketplace(Some("omnuv-gateway;g-1")));
        assert!(is_marketplace(Some("omnuv-instance;i-1")));
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
