//! Read-only inventory discovery against the Proxmox VE REST API.
//!
//! This is the narrow first slice of the Proxmox compute driver: it normalizes
//! what the host reports into `omnu_protocol::InventoryReport` and nothing else.
//! Proxmox concepts (node names, storage ids, PCI addresses) stop here.
//!
//! Discovery reports the DECLARED CONTRIBUTION clamped to physical reality, not
//! the physical machine. These are production hosts; advertising a host's full
//! CPU, memory or GPU complement would let the marketplace sell resources that
//! running workloads already depend on.

use std::collections::HashSet;

use omnu_protocol::{ComputeCapabilities, GpuDevice, InventoryReport, NodeInventory, RuntimeKind};
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
    location: Option<omnu_protocol::GeoLocation>,
    city: Option<String>,
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
fn pci_slot(raw: &str) -> String {
    let addr = raw.split(',').next().unwrap_or(raw).trim();
    let addr = addr.split('.').next().unwrap_or(addr);
    let full = if addr.matches(':').count() == 1 { format!("0000:{addr}") } else { addr.to_string() };
    full.to_lowercase()
}

impl Client {
    pub fn new(
        api_url: &str,
        fingerprint: Option<&str>,
        token_id: &str,
        token_secret: &str,
        node: Option<String>,
        contribute: Contribution,
        location: Option<omnu_protocol::GeoLocation>,
        city: Option<String>,
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
            });
        }

        if nodes.is_empty() {
            anyhow::bail!("no usable nodes found");
        }

        Ok(InventoryReport {
            protocol_version: omnu_protocol::PROTOCOL_VERSION,
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

        let mut c = Contribution::default();
        c.gpu_vram_mib = HashMap::from([("0000:21:00.0".to_string(), 31337u64)]);

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
