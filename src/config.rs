//! Development inventory: which machines tests and discovery are allowed to touch.
//! Never contains credentials; tokens are named here and read from the environment.
//!
//! And, below it, the agent's own configuration: `/etc/onv/agent.yaml`, whose
//! `timings` are `crate::timings`, and its credentials in
//! `/etc/onv/agent-secrets.yaml` beside it.

use serde::{Deserialize, Serialize};

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
///
/// **What the owner keeps is the host less this slice**, and the owner's own
/// guests are expected to fit in it. Every inventory pass discloses how far
/// they do not: the part of their use that reaches into the slice, which Core
/// subtracts from it (`disclosure`; D10 makes it a condition of selling). An
/// owner who stays inside what they kept discloses zero. There is no switch:
/// the `showall` that once gated this was a diagnostic, and is gone.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
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
        // `token_env.secret` is the *name* of the variable holding the secret,
        // read on the line above; the message names the variable, never its value.
        let secret = std::env::var(&self.token_env.secret)
            .map_err(|_| anyhow::anyhow!("{} is not set", self.token_env.secret))?; // nosemgrep: a-secret-reaching-a-log
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
    /// **The key the template writes is the key the agent reads.**
    ///
    /// `AgentConfig` carries `#[serde(rename_all = "camelCase")]`, so a field
    /// whose name is more than one word arrives under a name the Ansible
    /// template does not write, `#[serde(default)]` fills in `None`, and every
    /// machine is built unstamped while nothing anywhere complains. That is the
    /// same silence as a credential belonging to a destroyed store: the value
    /// is valid, it is simply not the one anybody meant.
    ///
    /// So this parses what `templates/agent.yaml.j2` actually emits, including
    /// the empty string an inventory with no environment renders.
    #[test]
    fn the_environment_arrives_under_the_name_the_template_writes() {
        let with = |environment: &str| -> super::AgentConfig {
            serde_yaml_ng::from_str(&format!(
                r#"
core:
  url: https://api.test.omnuv.com
  token: t
environment: "{environment}"
proxmox:
  apiUrl: https://127.0.0.1:8006
  tokenId: onv@pve!agent
  tokenSecret: s
"#
            ))
            .expect("config must parse")
        };
        assert_eq!(with("test").environment.as_deref(), Some("test"));
        // An inventory that declares none renders the empty string, which
        // `names::tags` treats as unstamped rather than as a tag called `onv-`.
        assert_eq!(
            crate::names::tags(crate::names::TAG_INSTANCE, "id", with("").environment.as_deref()),
            format!("{};{}", crate::names::TAG_INSTANCE, crate::names::short_tag("id"))
        );
        // And a configuration written before the field existed still parses.
        let older: super::AgentConfig = serde_yaml_ng::from_str(
            "core:\n  url: https://api.omnuv.com\n  token: t\nproxmox:\n  apiUrl: https://127.0.0.1:8006\n  tokenId: onv@pve!agent\n  tokenSecret: s\n",
        )
        .expect("a config from before this field must still parse");
        assert_eq!(older.environment, None);
    }

    /// A zero inventory interval is refused at load, in words: the reconcile
    /// loop's `tokio::time::interval` would otherwise panic on it.
    #[test]
    fn a_zero_inventory_interval_is_refused_at_load() {
        // Its own directory: the process id is shared by every test in the
        // run, and the tests below write an `agent.yaml` of their own.
        let dir = tempfile::tempdir().expect("a directory");
        let dir = dir.path();
        let path = dir.join("agent.yaml");
        let body = |secs: &str| format!(
            "core:\n  url: https://api.omnuv.com\n  token: t\n{secs}proxmox:\n  apiUrl: https://127.0.0.1:8006\n  tokenId: onv@pve!agent\n  tokenSecret: s\n"
        );
        std::fs::write(&path, body("inventoryEverySecs: 0\n")).unwrap();
        let refused = super::load_agent(path.to_str().unwrap()).expect_err("a zero interval loaded");
        assert!(refused.to_string().contains("inventoryEverySecs is 0"), "{refused}");
        std::fs::write(&path, body("")).unwrap();
        assert!(super::load_agent(path.to_str().unwrap()).is_ok(), "the default must still load");
    }

    /// `windowsImages` names offered images only: a stray id is refused at
    /// load, and an offered one loads as a Windows shape.
    #[test]
    fn a_windows_image_must_be_one_the_provider_offers() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("agent.yaml");
        let body = |windows: &str| format!(
            "core:\n  url: https://api.omnuv.com\n  token: t\nproxmox:\n  apiUrl: https://127.0.0.1:8006\n  tokenId: onv@pve!agent\n  tokenSecret: s\n  images:\n    ubuntu-26.04: 9000\n    windows-11-gaming: 9005\n  windowsImages: [{windows}]\n"
        );
        std::fs::write(&path, body("windows-11-gamin")).unwrap();
        let refused = super::load_agent(path.to_str().unwrap()).expect_err("a stray Windows id loaded");
        assert!(refused.to_string().contains("windowsImages names windows-11-gamin"), "{refused}");
        std::fs::write(&path, body("windows-11-gaming")).unwrap();
        let cfg = super::load_agent(path.to_str().unwrap()).expect("an offered Windows id must load");
        assert!(cfg.proxmox.windows_images.contains("windows-11-gaming"));
        // Unset is every image Linux, as before the key existed.
        std::fs::write(&path, body("").replace("  windowsImages: []\n", "")).unwrap();
        assert!(super::load_agent(path.to_str().unwrap()).unwrap().proxmox.windows_images.is_empty());
    }

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

    /// `agent.yaml` as `deploy-agent.yml` writes it now: no credential in it.
    const WITHOUT_CREDENTIALS: &str =
        "core:\n  url: https://api.omnuv.com\nproxmox:\n  apiUrl: https://127.0.0.1:8006\n  tokenId: onv@pve!agent\n";
    /// And as every agent had it before 26 September 2026.
    const WITH_CREDENTIALS: &str = "core:\n  url: https://api.omnuv.com\n  token: core-bearer-AAAA1111\n\
         proxmox:\n  apiUrl: https://127.0.0.1:8006\n  tokenId: onv@pve!agent\n  tokenSecret: pve-secret-BBBB2222\n";
    const SECRETS: &str = "coreToken: core-bearer-CCCC3333\nproxmoxTokenSecret: pve-secret-DDDD4444\n";

    /// An `agent.yaml`, and an `agent-secrets.yaml` of the given mode beside it.
    fn files(agent: &str, secrets: Option<(&str, u32)>) -> (tempfile::TempDir, String) {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("agent.yaml");
        std::fs::write(&path, agent).unwrap();
        if let Some((body, mode)) = secrets {
            let s = dir.path().join(super::SECRETS_FILE);
            std::fs::write(&s, body).unwrap();
            std::fs::set_permissions(&s, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let path = path.to_str().unwrap().to_string();
        (dir, path)
    }

    /// **The credentials come from `agent-secrets.yaml`**, beside the
    /// configuration, and nothing else in the file changes.
    #[test]
    fn the_credentials_are_read_from_their_own_file() {
        let (_dir, path) = files(WITHOUT_CREDENTIALS, Some((SECRETS, 0o600)));
        let cfg = super::load_agent(&path).expect("loads");
        assert_eq!(cfg.core.token.expose(), "core-bearer-CCCC3333");
        assert_eq!(cfg.proxmox.token_secret.expose(), "pve-secret-DDDD4444");
        assert_eq!(cfg.credentials, super::CredentialSource::SecretsFile(super::secrets_beside(&path)));
        assert_eq!(cfg.timings, crate::timings::Timings::default());
    }

    /// **An agent enrolled by hand still starts after an upgrade.** `join`
    /// wrote both credentials into `agent.yaml`, and no play rewrites a host
    /// it did not deploy, so that file is still read, and says so.
    #[test]
    fn a_configuration_from_before_the_split_still_loads() {
        let (_dir, path) = files(WITH_CREDENTIALS, None);
        let cfg = super::load_agent(&path).expect("loads");
        assert_eq!(cfg.core.token.expose(), "core-bearer-AAAA1111");
        assert_eq!(cfg.credentials, super::CredentialSource::AgentYaml);
    }

    /// Two copies of a credential, or none, are refused, each by name.
    #[test]
    fn credentials_in_both_places_or_neither_are_refused() {
        let (_dir, path) = files(WITH_CREDENTIALS, Some((SECRETS, 0o600)));
        let e = super::load_agent(&path).expect_err("two copies loaded").to_string();
        assert!(e.contains("holds core.token and proxmox.tokenSecret") && e.contains("exists too"), "{e}");

        let (_dir, path) = files(WITHOUT_CREDENTIALS, None);
        let e = super::load_agent(&path).expect_err("no credentials loaded").to_string();
        assert!(e.contains("does not exist") && e.contains("neither credential"), "{e}");

        let half = WITH_CREDENTIALS.replace("  tokenSecret: pve-secret-BBBB2222\n", "");
        let (_dir, path) = files(&half, None);
        let e = super::load_agent(&path).expect_err("half the credentials loaded").to_string();
        assert!(e.contains("only core.token"), "{e}");
    }

    /// **Mode 0600 or nothing**: a credentials file its group can read is
    /// refused before it is read.
    #[test]
    fn a_credentials_file_others_can_read_is_refused() {
        let (_dir, path) = files(WITHOUT_CREDENTIALS, Some((SECRETS, 0o640)));
        let e = super::load_agent(&path).expect_err("a group-readable file loaded").to_string();
        assert!(e.contains("is mode 0640") && e.contains("0600"), "{e}");
    }

    /// **A refusal names the key and never the value**, including when the
    /// file is not YAML at all, which is the case a library's own message
    /// quotes.
    #[test]
    fn a_credentials_refusal_never_quotes_a_value() {
        for body in [
            "coreToken: SEKRET-ONE\nproxmoxTokenSecret: [SEKRET-TWO]\nsessionKey: SEKRET-THREE\n",
            "coreToken: \"SEKRET-ONE\nproxmoxTokenSecret: SEKRET-TWO\n",
            "coreToken: SEKRET-ONE\n",
            "coreToken: ''\nproxmoxTokenSecret: SEKRET-TWO\n",
        ] {
            let (_dir, path) = files(WITHOUT_CREDENTIALS, Some((body, 0o600)));
            let e = format!("{:#}", super::load_agent(&path).expect_err("a bad file loaded"));
            assert!(!e.contains("SEKRET"), "a value was quoted: {e}");
            assert!(e.contains("refused"), "{e}");
        }
        let names = |body: &str| super::AgentSecrets::parse(body).err().unwrap_or_default().join("; ");
        let said = names("coreToken: SEKRET-ONE\nproxmoxTokenSecret: [SEKRET-TWO]\nsessionKey: SEKRET-THREE\n");
        assert!(said.contains("`sessionKey` is not a credential") && said.contains("proxmoxTokenSecret must be a string"), "{said}");
        assert!(names("coreToken: SEKRET-ONE\n").contains("proxmoxTokenSecret is missing"));
        assert!(names("coreToken: ''\nproxmoxTokenSecret: x\n").contains("coreToken is empty"));
    }

    /// **What the agent logs at start names no secret**, and does name every
    /// value and where the credentials came from.
    #[test]
    fn the_effective_configuration_names_no_secret() {
        let (_dir, path) = files(WITHOUT_CREDENTIALS, Some((SECRETS, 0o600)));
        let cfg = super::load_agent(&path).expect("loads");
        let shown = cfg.effective().to_string();
        for secret in ["core-bearer-CCCC3333", "pve-secret-DDDD4444"] {
            assert!(!shown.contains(secret), "the effective configuration printed {secret}: {shown}");
        }
        assert_eq!(cfg.effective()["credentials"]["coreToken"], "set", "{shown}");
        assert_eq!(cfg.effective()["timings"]["tunnelPing"], "20s", "{shown}");
        assert_eq!(cfg.effective()["proxmox"]["tokenId"], "onv@pve!agent", "{shown}");
    }

    /// `inventoryEverySecs` is still read, as the timing it always was, and
    /// refused beside the key that replaced it.
    #[test]
    fn the_old_inventory_key_is_read_and_refused_beside_the_new_one() {
        let old = format!("{WITH_CREDENTIALS}inventoryEverySecs: 60\n");
        let (_dir, path) = files(&old, None);
        let cfg = super::load_agent(&path).expect("loads");
        assert_eq!(cfg.timings.inventory_every, crate::dur::Dur::secs(60));

        let both = format!("{old}timings:\n  inventoryEvery: 5m\n");
        let (_dir, path) = files(&both, None);
        let e = super::load_agent(&path).expect_err("both keys loaded").to_string();
        assert!(e.contains("both inventoryEverySecs and timings.inventoryEvery"), "{e}");
    }

    /// **A timing out of its bounds stops the load**, naming the key as the
    /// file spells it; before `timings` existed the section was ignored.
    /// **The opening arrives under the keys the template writes**, off and
    /// on, and an opening on with nothing to reach it by stops the load, so
    /// `check-config` refuses it before deploy-agent.yml installs the file.
    /// The two blocks are what `templates/agent.yaml.j2` renders for
    /// `onv_opening` unset and for one declaring a forward.
    #[test]
    fn the_opening_arrives_under_the_names_the_template_writes() {
        let off = "opening:\n  enabled: false\n  reach: null\n  publicAddress: null\n  interface: \"vmbr0\"\n  ports: \"31820-31970\"\n";
        let (_dir, path) = files(&format!("{WITHOUT_CREDENTIALS}{off}"), Some((SECRETS, 0o600)));
        let cfg = super::load_agent(&path).expect("off loads");
        assert_eq!(cfg.opening, crate::opening::OpeningConfig::default());
        assert_eq!(cfg.effective()["opening"]["enabled"], false, "said at start");

        let on = "opening:\n  enabled: true\n  reach: \"forwarded\"\n  publicAddress: \"193.137.26.160\"\n  interface: \"vmbr0\"\n  ports: \"31820-31829\"\n";
        let (_dir, path) = files(&format!("{WITHOUT_CREDENTIALS}{on}"), Some((SECRETS, 0o600)));
        let cfg = super::load_agent(&path).expect("on loads");
        let c = cfg.opening.check().unwrap().expect("on");
        assert_eq!((c.first, c.last, c.reach), (31820, 31829, crate::opening::Reach::Forwarded));

        let nothing = on.replace("reach: \"forwarded\"", "reach: null");
        let (_dir, path) = files(&format!("{WITHOUT_CREDENTIALS}{nothing}"), Some((SECRETS, 0o600)));
        let e = super::load_agent(&path).expect_err("on with no reach loaded").to_string();
        assert!(e.contains("no public address and no forward was declared"), "{e}");

        // A file from before the opening existed is off.
        let (_dir, path) = files(WITHOUT_CREDENTIALS, Some((SECRETS, 0o600)));
        assert!(!super::load_agent(&path).unwrap().opening.enabled);
    }

    #[test]
    fn a_timing_out_of_bounds_stops_the_load_by_name() {
        let (_dir, path) = files(&format!("{WITHOUT_CREDENTIALS}timings:\n  tunnelPing: 30s\n"), Some((SECRETS, 0o600)));
        let e = super::load_agent(&path).expect_err("a 30s ping loaded").to_string();
        assert!(e.contains("timings.tunnelPing is 30s"), "{e}");
        let (_dir, path) = files(&format!("{WITHOUT_CREDENTIALS}timings:\n  tunelPing: 10s\n"), Some((SECRETS, 0o600)));
        let e = super::load_agent(&path).expect_err("a misspelt key loaded").to_string();
        assert!(e.contains("tunelPing"), "{e}");
    }
}

// ---------- agent configuration ----------
// Read from /etc/onv/agent.yaml on the provider host, and the two credentials
// from /etc/onv/agent-secrets.yaml beside it, mode 0600. They never leave the
// machine: Core is told inventory, never how to reach Proxmox.

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentConfig {
    pub core: CoreEndpoint,
    /// `inventoryEverySecs`, the key `timings.inventoryEvery` replaced. Still
    /// read, so an `agent.yaml` written before 26 September 2026 — by `join`,
    /// on every host enrolled by hand — starts unchanged after an upgrade;
    /// never written, and refused beside the new key.
    #[serde(default, skip_serializing)]
    inventory_every_secs: Option<u64>,
    /// Which deployment this agent belongs to: `prod`, `test`, `dev`.
    ///
    /// Stamped onto every machine it creates as a third tag, so that a person
    /// reading a hypervisor's VM list can tell the marketplace's production
    /// machines from a test run's without consulting anything. It is **not a
    /// claim** and authorizes nothing — ownership is `onv-instance`,
    /// `onv-worker` or `onv-gateway`, matched as whole tokens.
    ///
    /// Optional, and absent means unstamped rather than wrong: an agent
    /// deployed before this existed keeps working, and its machines carry the
    /// two tags everything actually matches on.
    #[serde(default)]
    pub environment: Option<String>,
    pub proxmox: ProxmoxRuntime,
    /// How long, how often, how many: `crate::timings`. Absent means every
    /// default, which is what the code held before the section existed.
    #[serde(default)]
    pub timings: crate::timings::Timings,
    /// **The provider opening** (`crate::opening`): one UDP port of this
    /// host's public side per machine. Absent is off, as is every file
    /// written before it existed; deploy-agent.yml writes every key from the
    /// inventory's `onv_opening`.
    #[serde(default)]
    pub opening: crate::opening::OpeningConfig,
    /// Where the two credentials were read from. Not a key of any file: set by
    /// [`load_agent_with`], and said at start.
    #[serde(skip)]
    pub credentials: CredentialSource,
}

/// Where an agent's two credentials came from.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum CredentialSource {
    /// Not resolved: a configuration parsed without `load_agent`, in a test.
    #[default]
    Unresolved,
    /// `agent-secrets.yaml`, mode 0600, apart from everything else: where they
    /// belong (omnuv's runtime configuration plan, "secrets apart").
    SecretsFile(String),
    /// Inline in `agent.yaml`, as every agent kept them before 26 September
    /// 2026. Still read, so a host enrolled by hand starts after an upgrade
    /// with no play to rewrite its file; said as a warning at every start.
    AgentYaml,
}

/// A credential the file did not name. Never a valid one — an empty token is
/// refused everywhere it could be spent — so it can stand for "absent" without
/// wrapping every read of the field in an `Option`.
fn not_in_this_file() -> omnuv_protocol::Redacted {
    omnuv_protocol::Redacted::from("")
}

#[derive(Debug, Deserialize, Serialize)]
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
    ///
    /// **Never serialised**: the effective configuration the agent logs at
    /// start is this struct written out, and `Redacted`'s own `Serialize` is
    /// the wire's, which carries the characters.
    #[serde(default = "not_in_this_file", skip_serializing)]
    pub token: omnuv_protocol::Redacted,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxRuntime {
    pub api_url: String,
    pub node: Option<String>,
    pub tls_fingerprint_sha256: Option<String>,
    pub token_id: String,
    /// Redacted for the reason given on `CoreEndpoint::token`: a different
    /// blast radius reached through the same derive, by the same one-line
    /// mistake. `token_id` beside it is a username and stays readable. Never
    /// serialised, for the reason given there too.
    #[serde(default = "not_in_this_file", skip_serializing)]
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
    /// **Which of `images` are Windows images**, so the mirror imports each
    /// into a template of the shape `build-template-windows.yml` gives it
    /// (`images::TemplateShape`). Written by deploy-agent.yml from omnuv's
    /// `onv_windows_templates`, the list that play builds from. An id here
    /// that `images` does not offer is refused at load.
    ///
    /// **Here, because the catalogue entry does not say.** The OS family
    /// reaches the agent in `ImageSpec`, attached to a machine; the artefact a
    /// mirror fetches is bytes and a digest (`omnuv_protocol::ImageArtefact`).
    /// A Windows id missing here is mirrored in the Linux shape, and `held`
    /// then reports it held only while its template's `ostype` agrees with
    /// this list, so correcting the list makes the next pass import it again.
    #[serde(default)]
    pub windows_images: std::collections::BTreeSet<String>,
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

/// The name the credentials file has beside `agent.yaml`.
pub const SECRETS_FILE: &str = "agent-secrets.yaml";

/// Where the credentials are when nothing says otherwise: beside the
/// configuration, so `--config /some/dir/agent.yaml` finds its own.
pub fn secrets_beside(config: &str) -> String {
    std::path::Path::new(config).with_file_name(SECRETS_FILE).to_string_lossy().into_owned()
}

/// `load_agent_with`, the credentials read from beside the configuration.
pub fn load_agent(path: &str) -> anyhow::Result<AgentConfig> {
    load_agent_with(path, &secrets_beside(path))
}

/// Reads `agent.yaml` and its credentials, and refuses a configuration that
/// does not pass: the reason names the key, and the bound or the rule.
///
/// **The credentials come from one place.** `agent-secrets.yaml` when it
/// exists, and then `agent.yaml` may not hold them too: two copies are one
/// that is stale, and which one wins would be decided by whoever wrote this
/// loader rather than by whoever wrote the files. Without it, `agent.yaml`
/// must hold both, as it did before 26 September 2026.
pub fn load_agent_with(path: &str, secrets: &str) -> anyhow::Result<AgentConfig> {
    let raw = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?;
    let mut cfg: AgentConfig = serde_yaml_ng::from_str(&raw).map_err(|e| anyhow::anyhow!("{path}: {e}"))?;

    let inline: Vec<&str> = [
        ("core.token", cfg.core.token.expose().is_empty()),
        ("proxmox.tokenSecret", cfg.proxmox.token_secret.expose().is_empty()),
    ]
    .into_iter()
    .filter(|(_, absent)| !absent)
    .map(|(key, _)| key)
    .collect();
    match load_secrets(secrets)? {
        Some(s) => {
            anyhow::ensure!(
                inline.is_empty(),
                "{path} holds {} and {secrets} exists too: keep this provider's credentials in {secrets} \
                 alone, where deploy-agent.yml writes them",
                inline.join(" and ")
            );
            cfg.core.token = s.core_token;
            cfg.proxmox.token_secret = s.proxmox_token_secret;
            cfg.credentials = CredentialSource::SecretsFile(secrets.to_string());
        }
        None => {
            anyhow::ensure!(
                inline.len() == 2,
                "{secrets} does not exist and {path} holds {}: this provider's credentials are \
                 coreToken and proxmoxTokenSecret in {secrets}, mode 0600",
                if inline.is_empty() { "neither credential".to_string() } else { format!("only {}", inline[0]) }
            );
            cfg.credentials = CredentialSource::AgentYaml;
        }
    }

    // `inventoryEverySecs`, before `timings.inventoryEvery`. Whether the new
    // key was written is asked of the document itself: a default and a value
    // that happens to equal it are the same number and not the same choice.
    if let Some(secs) = cfg.inventory_every_secs {
        let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(&raw).map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
        anyhow::ensure!(
            doc.get("timings").and_then(|t| t.get("inventoryEvery")).is_none(),
            "{path} sets both inventoryEverySecs and timings.inventoryEvery; keep timings.inventoryEvery"
        );
        // `tokio::time::interval` panics on a zero period, so this is refused
        // here, in words, rather than as a panic in the reconcile loop.
        anyhow::ensure!(secs > 0, "{path}: inventoryEverySecs is 0; it must be at least 1");
        cfg.timings.inventory_every = crate::dur::Dur::secs(secs);
    }

    // A Windows image the provider does not offer would be a shape for a
    // template that is never mirrored: a typo, said rather than ignored.
    let offered = cfg.proxmox.image_map();
    let strays: Vec<&str> =
        cfg.proxmox.windows_images.iter().filter(|id| !offered.contains_key(*id)).map(String::as_str).collect();
    anyhow::ensure!(
        strays.is_empty(),
        "{path} refused: proxmox.windowsImages names {} that proxmox.images does not offer",
        strays.join(", ")
    );

    cfg.timings
        .check()
        .map_err(|bad| anyhow::anyhow!("{path} refused:\n  {}", bad.join("\n  ")))?;
    // The opening, by the same rule: a key that does not pass stops the load,
    // so `check-config` refuses it before deploy-agent.yml installs the file.
    cfg.opening
        .check()
        .map_err(|bad| anyhow::anyhow!("{path} refused:\n  {}", bad.join("\n  ")))?;
    Ok(cfg)
}

impl AgentConfig {
    /// The configuration in force, for the journal at start: every value, and
    /// of each credential only whether it is set and where it came from.
    /// Built from the struct itself, whose two credentials are never
    /// serialised, so a field added later is shown rather than forgotten and
    /// a secret added later is hidden by being declared like these two.
    pub fn effective(&self) -> serde_json::Value {
        let mut shown = serde_json::to_value(self).expect("the configuration serialises");
        let set = |r: &omnuv_protocol::Redacted| if r.expose().is_empty() { "unset" } else { "set" };
        shown["credentials"] = serde_json::json!({
            "from": match &self.credentials {
                CredentialSource::SecretsFile(p) => p.clone(),
                CredentialSource::AgentYaml => "agent.yaml".to_string(),
                CredentialSource::Unresolved => "unresolved".to_string(),
            },
            "coreToken": set(&self.core.token),
            "proxmoxTokenSecret": set(&self.proxmox.token_secret),
        });
        shown
    }
}

/// `agent-secrets.yaml`: this provider's two credentials, apart from
/// everything else (omnuv's runtime configuration plan). Both are required.
pub struct AgentSecrets {
    pub core_token: omnuv_protocol::Redacted,
    pub proxmox_token_secret: omnuv_protocol::Redacted,
}

/// The names `agent-secrets.yaml` may hold: both are the agent's.
pub const AGENT_SECRET_KEYS: [&str; 2] = ["coreToken", "proxmoxTokenSecret"];

impl AgentSecrets {
    /// Parse the file: `onv_agent_lib::secrets`' partial reading over the
    /// agent's two names, then both required.
    pub fn parse(yaml: &str) -> Result<AgentSecrets, Vec<String>> {
        let (mut found, mut bad) = onv_agent_lib::secrets::read_partial(yaml, &AGENT_SECRET_KEYS);
        for key in AGENT_SECRET_KEYS {
            if !found.contains_key(key) && !bad.iter().any(|b| b.starts_with(key)) {
                bad.push(format!("{key} is missing"));
            }
        }
        match (found.remove("coreToken"), found.remove("proxmoxTokenSecret")) {
            (Some(core_token), Some(proxmox_token_secret)) if bad.is_empty() => {
                Ok(AgentSecrets { core_token, proxmox_token_secret })
            }
            _ => Err(bad),
        }
    }
}

/// Reads the credentials file: `None` when there is none. **Refused when anyone
/// but its owner can read it**, before a byte of it is read, because a secret
/// in a file the whole group can read is a secret the mode was supposed to
/// keep and did not.
pub fn load_secrets(path: &str) -> anyhow::Result<Option<AgentSecrets>> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => anyhow::bail!("{path}: {e}"),
    };
    let mode = meta.permissions().mode() & 0o777;
    anyhow::ensure!(
        mode & 0o077 == 0,
        "{path} is mode {mode:04o}; it holds this provider's credentials and must be readable by its owner alone (0600)"
    );
    let raw = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
    AgentSecrets::parse(&raw)
        .map(Some)
        .map_err(|bad| anyhow::anyhow!("{path} refused:\n  {}", bad.join("\n  ")))
}
