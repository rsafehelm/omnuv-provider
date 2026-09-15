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

/// The *names* of the two environment variables holding the credentials —
/// never the values. `Debug` here prints `OMNUV_PVE_TOKEN_SECRET`, which is
/// exactly what somebody reading a log needs to see.
///
/// Said out loud because `secret: String` beside a redacted `token_secret`
/// looks like an omission. It is the opposite: a redaction driven by field
/// *name* rather than by type would hide this one, and a `<redacted>` standing
/// where a variable name belongs teaches everyone to skim past the redactions
/// that matter.
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

    /// **The agent's two credentials survive `{:?}` on the struct that holds
    /// them**, which is the whole reason their type changed.
    ///
    /// `AgentConfig` derives `Debug` and is passed by reference to four places
    /// in `agent.rs`. Before `Redacted` this test could not have been written
    /// to pass: one `tracing::debug!(?cfg)` on a bad afternoon printed the Core
    /// bearer token and the Proxmox API secret into the journal, side by side,
    /// out of a file the deployment deliberately keeps at mode `0600`.
    ///
    /// Asserted on the *formatted output* rather than on the source, because
    /// the defect is what `Debug` emits and a grep for `derive(Debug` would
    /// match the eighty legitimate ones — and its own needle. The second half
    /// matters as much as the first: a redaction that also hid the value from
    /// the code that has to spend it would be a broken agent, not a safe one.
    #[test]
    fn debug_on_the_agent_config_redacts_both_credentials() {
        let cfg: super::AgentConfig = serde_yaml_ng::from_str(
            r#"
core:
  url: https://api.omnuv.com
  token: core-bearer-AAAA1111
proxmox:
  apiUrl: https://127.0.0.1:8006
  tokenId: onv@pve!agent
  tokenSecret: pve-secret-BBBB2222
"#,
        )
        .expect("agent config must parse");

        let shown = format!("{cfg:?}");
        for secret in ["core-bearer-AAAA1111", "pve-secret-BBBB2222"] {
            assert!(!shown.contains(secret), "Debug leaked {secret}: {shown}");
        }
        assert_eq!(shown.matches("<redacted>").count(), 2, "both, not one: {shown}");

        // `token_id` is a username, not a credential, and stays readable — a
        // redaction driven by field name rather than by type would have taken
        // it too, and trained everyone to skim the redaction.
        assert!(shown.contains("onv@pve!agent"), "the token id is not a secret: {shown}");

        // And the value is still reachable by the code that spends it.
        assert_eq!(cfg.core.token.expose(), "core-bearer-AAAA1111");
        assert_eq!(cfg.proxmox.token_secret.expose(), "pve-secret-BBBB2222");
    }
}

// ---------- agent configuration ----------
// Read from /etc/onv/agent.yaml on the provider host. This file holds the
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
    /// `0600` protects the file; the type protects the log.
    ///
    /// `AgentConfig` derives `Debug` and holds this *and* the Proxmox secret
    /// below, so a single `tracing::debug!(?cfg)` at any of the four sites that
    /// take `&cfg` would write both credentials to the journal — where the file
    /// mode buys exactly nothing. A hand-written `Debug` on `AgentConfig` would
    /// fix today's two fields and nothing about the third one somebody adds, so
    /// the redaction lives on the field's type instead.
    pub token: omnuv_protocol::Redacted,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxRuntime {
    pub api_url: String,
    pub node: Option<String>,
    pub tls_fingerprint_sha256: Option<String>,
    pub token_id: String,
    /// Redacted for the reason given on `CoreEndpoint::token`: a different
    /// blast radius reached through the same derive, by the same one-line
    /// mistake. `token_id` beside it is a username and stays readable.
    pub token_secret: omnuv_protocol::Redacted,
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

    /// Disclose what this host has already given to guests the marketplace did
    /// not create. **Off by default, and off is the right default.**
    ///
    /// The marketplace books against advertised capacity and nothing else, so a
    /// host advertising 64 cores while its owner runs a 60-core workload of
    /// their own passes every oversell check Core has, and the first sign of
    /// trouble is a buyer's machine that will not start. Knowing the figure
    /// would let Core see that coming.
    ///
    /// It is still off by default, because the figure is a fact about the
    /// provider's own business. What a provider runs on their own hardware
    /// beside the marketplace's workloads is theirs, and a marketplace that
    /// collects it by default has decided something on their behalf. Even
    /// aggregated — four integers, no names, no identifiers — a guest count and
    /// a memory total say things about an operation that its owner may not have
    /// chosen to publish.
    ///
    /// So it is opt-in, per provider, and turning it on is *recorded by this
    /// agent* in its own audit log — `host.usage.disclosed` — so the disclosure
    /// has a trail on the provider's side rather than only on ours. The party
    /// giving something up should be able to see that they did.
    ///
    /// Turn it on to diagnose a host that keeps refusing placements, and turn
    /// it off afterwards. While it is on the agent says so, hourly, in the
    /// audit stream that flows up with every report — which is meant to be
    /// slightly annoying.
    #[serde(default)]
    pub showall: bool,
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
        self.image_map().into_keys().collect()
    }

    /// The same thing `template_for` and `offered_images` answer, as a map —
    /// which is what mirroring needs, because it has to know *where* to put
    /// each image as well as which ones are wanted.
    ///
    /// The empty-map fallback lives here once rather than in each caller: a
    /// provider that has written no `images` offers the shipped Linux image
    /// from `template_vmid`, and that default is a property of the config, not
    /// of whoever is reading it.
    pub fn image_map(&self) -> std::collections::BTreeMap<String, u32> {
        if self.images.is_empty() {
            return std::collections::BTreeMap::from([(
                DEFAULT_IMAGE.to_string(),
                self.template_vmid,
            )]);
        }
        self.images.clone()
    }
}

fn default_snippet_dir() -> String {
    "/var/lib/onv/snippets".to_string()
}

pub fn load_agent(path: &str) -> anyhow::Result<AgentConfig> {
    let raw = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?;
    Ok(serde_yaml_ng::from_str(&raw)?)
}
