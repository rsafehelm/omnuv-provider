//! `omnu-provider join` — onboarding, run by the provider on their own machine.
//!
//! Phone-home: this dials Core outward and nothing ever dials back. Omnu needs
//! no SSH access, no inbound rule and no credentials for the hypervisor — the
//! restricted Proxmox token is created here, locally, and never leaves.
//!
//! Everything it does is visible in this file, which is the point: a provider
//! is installing marketplace software on hardware they own and is entitled to
//! read exactly what it will do first.

use std::process::Command;

use crate::audit;

/// The privileges the marketplace role is granted. Deliberately excludes
/// `Sys.Modify`, `Permissions.Modify` and anything that can reconfigure the
/// host itself.
const ROLE_PRIVS: &str = "Sys.Audit,Datastore.Audit,Datastore.AllocateSpace,\
VM.Audit,VM.Allocate,VM.Clone,VM.PowerMgmt,\
VM.Config.Disk,VM.Config.CPU,VM.Config.Memory,VM.Config.Network,\
VM.Config.Options,VM.Config.Cloudinit,VM.Config.HWType,VM.Config.CDROM,\
VM.GuestAgent.Audit,Mapping.Audit,Mapping.Use,SDN.Audit,SDN.Use";

pub struct JoinArgs {
    pub core: String,
    pub token: String,
    pub region: String,
    pub cpu_cores: u32,
    pub memory_mib: u64,
    pub disk_gib: u64,
    pub storage: Option<String>,
    pub gpus: Vec<String>,
    pub dry_run: bool,
}

fn sh(cmd: &str) -> anyhow::Result<String> {
    let out = Command::new("bash").arg("-c").arg(cmd).output()?;
    if !out.status.success() {
        anyhow::bail!("`{cmd}` failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Prints every command before running it. A provider should be able to watch
/// what is happening to their machine, and to run `--dry-run` first.
fn step(label: &str, cmd: &str, dry: bool) -> anyhow::Result<String> {
    println!("  {label}");
    println!("    $ {cmd}");
    if dry {
        return Ok(String::new());
    }
    let out = sh(cmd)?;
    audit::record("join.step", "agent", label, "ok", None);
    Ok(out)
}

pub fn run(a: JoinArgs) -> anyhow::Result<()> {
    println!("omnu-provider join");
    println!("  core:   {}", a.core);
    println!("  region: {}", a.region);
    if a.dry_run {
        println!("  DRY RUN — nothing will be changed\n");
    }
    println!();

    // Refuse early rather than half-configure a machine we cannot support.
    let version = sh("pveversion").unwrap_or_default();
    if !version.contains("pve-manager/9.") {
        anyhow::bail!("unsupported or missing Proxmox VE (found: {version:?}); this build targets 9.x");
    }
    println!("  detected {version}");

    let node = sh("hostname")?;
    let storage = match a.storage {
        Some(s) => s,
        None => sh("pvesm status --content images | awk 'NR>1 {print $1; exit}'")?,
    };
    if storage.is_empty() {
        anyhow::bail!("no storage that can hold VM images; pass --storage");
    }
    println!("  node: {node}   storage: {storage}");

    if !a.gpus.is_empty() {
        let groups = sh("ls /sys/kernel/iommu_groups 2>/dev/null | wc -l").unwrap_or_default();
        if groups.trim() == "0" {
            anyhow::bail!("GPUs were offered but IOMMU is not active; passthrough would fail");
        }
        println!("  IOMMU active ({} groups)", groups.trim());
    }

    println!("\nCreating a restricted Proxmox token. It stays on this machine:");
    step(
        "role",
        &format!("pveum role list --output-format json | grep -q '\"OmnuAgent\"' || pveum role add OmnuAgent -privs \"{ROLE_PRIVS}\"; pveum role modify OmnuAgent -privs \"{ROLE_PRIVS}\""),
        a.dry_run,
    )?;
    step(
        "user",
        "pveum user list --output-format json | grep -q '\"omnu@pve\"' || pveum user add omnu@pve --comment 'Omnu marketplace agent'",
        a.dry_run,
    )?;
    step("acl", "pveum acl modify / -user omnu@pve -role OmnuAgent", a.dry_run)?;

    let secret = if a.dry_run {
        "<created at run time>".to_string()
    } else {
        sh("pveum user token remove omnu@pve agent >/dev/null 2>&1; \
            pveum user token add omnu@pve agent --privsep 1 --output-format json")
            .and_then(|out| {
                let v: serde_json::Value = serde_json::from_str(&out)?;
                Ok(v["value"].as_str().unwrap_or_default().to_string())
            })?
    };
    step("token acl", "pveum acl modify / -token 'omnu@pve!agent' -role OmnuAgent", a.dry_run)?;

    let fingerprint = sh("openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -fingerprint -sha256 | cut -d= -f2")
        .unwrap_or_default();

    let gpus = a
        .gpus
        .iter()
        .map(|g| format!("      - \"{g}\""))
        .collect::<Vec<_>>()
        .join("\n");

    let config = format!(
        r#"# Written by `omnu-provider join`. Contains this machine's own Proxmox
# credentials; they are never sent to Omnu.
core:
  url: "{core}"
  token: "{token}"

inventoryEverySecs: 300

proxmox:
  apiUrl: "https://127.0.0.1:8006"
  node: "{node}"
  tlsFingerprintSha256: "{fingerprint}"
  tokenId: "omnu@pve!agent"
  tokenSecret: "{secret}"
  templateVmid: 9000
  snippetDir: /var/lib/omnu/snippets
  contribute:
    cpuCores: {cpu}
    memoryMib: {mem}
    diskGib: {disk}
    storage: ["{storage}"]
    gpus:
{gpus}
"#,
        core = a.core,
        token = a.token,
        cpu = a.cpu_cores,
        mem = a.memory_mib,
        disk = a.disk_gib,
        gpus = if gpus.is_empty() { "      []".to_string() } else { gpus },
    );

    println!("\nWriting /etc/omnu/agent.yaml (0640 root:omnu)");
    if !a.dry_run {
        std::fs::create_dir_all("/etc/omnu")?;
        sh("id -u omnu >/dev/null 2>&1 || useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/omnu --create-home omnu")?;
        std::fs::write("/etc/omnu/agent.yaml", &config)?;
        sh("chgrp omnu /etc/omnu/agent.yaml && chmod 0640 /etc/omnu/agent.yaml")?;
        sh("install -d -o omnu -g omnu /var/lib/omnu/snippets /var/log/omnu")?;
        sh("pvesm status --storage omnu-snippets >/dev/null 2>&1 || pvesm add dir omnu-snippets --path /var/lib/omnu --content snippets")?;
    }

    println!("Installing and starting the service");
    if !a.dry_run {
        std::fs::write("/etc/systemd/system/omnu-provider.service", UNIT)?;
        sh("systemctl daemon-reload && systemctl enable --now omnu-provider")?;
        audit::record("join.complete", "agent", &node, "ok", Some(&a.region));
    }

    println!("\nDone. The agent now dials {} outward.", a.core);
    println!("Nothing listens on this machine, and Omnu never connects to it.");
    println!("Audit log:  /var/log/omnu/audit.log");
    println!("Logs:       journalctl -u omnu-provider -f");
    println!("To leave:   omnu-provider leave");
    Ok(())
}

const UNIT: &str = r#"[Unit]
Description=Omnu Provider Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/omnu-provider agent --config /etc/omnu/agent.yaml
User=omnu
Group=omnu
Restart=always
RestartSec=10s

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=/var/lib/omnu /var/log/omnu
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
"#;

/// Removes everything `join` created. A provider must be able to leave as
/// easily as they joined, without asking us.
pub fn leave(dry_run: bool) -> anyhow::Result<()> {
    println!("omnu-provider leave{}", if dry_run { " (dry run)" } else { "" });
    for (label, cmd) in [
        ("stop service", "systemctl disable --now omnu-provider 2>/dev/null || true"),
        ("remove unit", "rm -f /etc/systemd/system/omnu-provider.service; systemctl daemon-reload"),
        ("remove token", "pveum user token remove omnu@pve agent 2>/dev/null || true"),
        ("remove acl", "pveum acl delete / -token 'omnu@pve!agent' -role OmnuAgent 2>/dev/null || true; pveum acl delete / -user omnu@pve -role OmnuAgent 2>/dev/null || true"),
        ("remove user", "pveum user delete omnu@pve 2>/dev/null || true"),
        ("remove role", "pveum role delete OmnuAgent 2>/dev/null || true"),
        ("remove config", "rm -f /etc/omnu/agent.yaml"),
    ] {
        println!("  {label}\n    $ {cmd}");
        if !dry_run {
            let _ = sh(cmd);
        }
    }
    // The audit log is deliberately left in place: it is the provider's record.
    println!("\nRemoved. /var/log/omnu/audit.log is kept — it is your record, not ours.");
    Ok(())
}
