//! Development inventory: which machines tests and discovery are allowed to touch.
//! Never contains credentials; tokens are named here and read from the environment.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Root {
    #[serde(rename = "developmentInfrastructure")]
    pub infrastructure: Infrastructure,
}

#[derive(Debug, Deserialize)]
pub struct Infrastructure {
    #[serde(default)]
    pub proxmox: Vec<ProxmoxTarget>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxTarget {
    pub id: String,
    pub display_name: Option<String>,
    pub api_url: String,
    pub node: Option<String>,
    pub region: String,
    #[serde(default)]
    pub enabled: bool,
    pub tls_fingerprint_sha256: Option<String>,
    pub token_env: TokenEnv,
    /// What this provider offers to the marketplace. Absent means "nothing":
    /// a host must opt in to selling capacity, never opt out.
    #[serde(default)]
    pub contribute: Contribution,
}

/// Physical inventory is not sellable inventory. These machines run production
/// workloads, so the agent reports a declared slice and the marketplace never
/// sees the rest. Discovery clamps every figure to what is physically present,
/// so raising a number here can never over-report real hardware.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Contribution {
    #[serde(default)]
    pub cpu_cores: u32,
    #[serde(default)]
    pub memory_mib: u64,
    #[serde(default)]
    pub disk_gib: u64,
    /// Proxmox storage ids whose free space may back marketplace disks.
    #[serde(default)]
    pub storage: Vec<String>,
    /// Explicit PCI addresses of GPUs offered for sale. Empty offers none.
    #[serde(default)]
    pub gpus: Vec<String>,
    /// VRAM per GPU, keyed by PCI address, in MiB. Overrides the built-in
    /// device table. Without this an unrecognised card reports 0 and can never
    /// be scheduled, because placement refuses a GPU it cannot size.
    #[serde(default)]
    pub gpu_vram_mib: std::collections::HashMap<String, u64>,
}

#[derive(Debug, Deserialize)]
pub struct TokenEnv {
    pub id: String,
    pub secret: String,
}

impl ProxmoxTarget {
    pub fn name(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.id)
    }

    /// Reads the token from the environment. Credentials never live in the
    /// inventory file, so a leaked config cannot reach a provider.
    pub fn credentials(&self) -> anyhow::Result<(String, String)> {
        let id = std::env::var(&self.token_env.id)
            .map_err(|_| anyhow::anyhow!("{} is not set", self.token_env.id))?;
        let secret = std::env::var(&self.token_env.secret)
            .map_err(|_| anyhow::anyhow!("{} is not set", self.token_env.secret))?;
        Ok((id, secret))
    }
}

pub fn load(path: &str) -> anyhow::Result<Vec<ProxmoxTarget>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?;
    let root: Root = serde_yaml_ng::from_str(&raw)?;
    Ok(root.infrastructure.proxmox)
}

/// Never pick a target implicitly: a destructive run against the wrong machine
/// is not recoverable by apologising.
pub fn select<'a>(targets: &'a [ProxmoxTarget], id: &str) -> anyhow::Result<&'a ProxmoxTarget> {
    let t = targets
        .iter()
        .find(|t| t.id == id)
        .ok_or_else(|| anyhow::anyhow!("no development provider with id '{id}'"))?;
    if !t.enabled {
        anyhow::bail!("provider '{id}' is present but not enabled");
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_contribution_block() {
        let yaml = r#"
developmentInfrastructure:
  proxmox:
    - id: pve-x
      apiUrl: https://example:8006
      region: eu-west
      enabled: true
      tokenEnv: { id: A, secret: B }
      contribute:
        cpuCores: 16
        memoryMib: 16384
        diskGib: 500
        storage: ["zfs-fast"]
        gpus: []
"#;
        let root: super::Root = serde_yaml_ng::from_str(yaml).expect("config must parse");
        let t = &root.infrastructure.proxmox[0];
        assert_eq!(t.contribute.cpu_cores, 16, "cpuCores must map to cpu_cores");
        assert_eq!(t.contribute.memory_mib, 16384);
        assert_eq!(t.contribute.storage, vec!["zfs-fast"]);
    }
}

// ---------- agent configuration ----------
// Read from /etc/omnuv/agent.yaml on the provider host. This file holds the
// provider's own runtime credentials and must be root-owned, mode 0600. They
// never leave the machine: Core is told inventory, never how to reach Proxmox.

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentConfig {
    pub core: CoreEndpoint,
    /// Full inventory is re-reported on this interval; heartbeats are far more
    /// frequent and are what drive online/offline.
    #[serde(default = "default_inventory_secs")]
    pub inventory_every_secs: u64,
    pub proxmox: ProxmoxRuntime,
}

fn default_inventory_secs() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
pub struct CoreEndpoint {
    pub url: String,
    pub token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxRuntime {
    pub api_url: String,
    pub node: Option<String>,
    pub tls_fingerprint_sha256: Option<String>,
    pub token_id: String,
    pub token_secret: String,
    /// Template cloned for marketplace-managed VMs (inference workers, the
    /// overlay gateway), and for the shipped Linux image when `images` is not
    /// set.
    #[serde(default = "default_template_vmid")]
    pub template_vmid: u32,
    /// Marketplace image id → the local template that builds it. This is the
    /// one place a provider's template ids live; the marketplace only ever
    /// learns which image ids are offered. A Windows image is an entry here
    /// and a licensed template, nothing more.
    #[serde(default)]
    pub images: std::collections::BTreeMap<String, u32>,
    /// Where the agent writes cloud-init user-data. Must be a Proxmox storage
    /// with `snippets` content, owned by the agent's user.
    #[serde(default = "default_snippet_dir")]
    pub snippet_dir: String,
    /// The Debian/Ubuntu package mirror a machine built here should use.
    ///
    /// Unset means the image's own default, which is `archive.ubuntu.com` — a
    /// global round-robin, and on 11 September it served this provider at
    /// **32 KB/s** while a mirror 30 km away served 34 MB/s from the same host
    /// in the same second. A 200 KB package took nine minutes, because
    /// `apt-get update` drags several megabytes of indices through it first.
    ///
    /// Configured per provider rather than chosen by the marketplace: which
    /// mirror is close is a fact about where this hardware sits, and a provider
    /// knows it. Ubuntu's own geo-routing does not — `mirrors.ubuntu.com`
    /// returns `archive.ubuntu.com` here.
    #[serde(default)]
    pub apt_mirror: Option<String>,
    /// Physical location of this hardware, for marketplace maps and for
    /// latency-aware placement later. Optional.
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    #[serde(default)]
    pub contribute: Contribution,
}

fn default_template_vmid() -> u32 {
    9000
}

/// The image the marketplace shipped with; offered from `template_vmid` when
/// an operator has not written an `images` map.
pub const DEFAULT_IMAGE: &str = "ubuntu-26.04";

impl ProxmoxRuntime {
    /// The local template that builds a marketplace image, if this provider
    /// offers it.
    pub fn template_for(&self, image: &str) -> Option<u32> {
        if self.images.is_empty() {
            return (image == DEFAULT_IMAGE).then_some(self.template_vmid);
        }
        self.images.get(image).copied()
    }

    /// Image ids reported with the inventory, so the scheduler never places
    /// an image on a provider that cannot build it.
    pub fn offered_images(&self) -> Vec<String> {
        if self.images.is_empty() {
            return vec![DEFAULT_IMAGE.to_string()];
        }
        self.images.keys().cloned().collect()
    }
}

fn default_snippet_dir() -> String {
    "/var/lib/omnuv/snippets".to_string()
}

pub fn load_agent(path: &str) -> anyhow::Result<AgentConfig> {
    let raw = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?;
    Ok(serde_yaml_ng::from_str(&raw)?)
}
