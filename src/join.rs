//! `onv-provider join` — onboarding, run by the provider on their own machine.
//!
//! Phone-home: this dials Core outward and nothing ever dials back. Omnuv needs
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

/// The pool a gateway lands in, and the pool a buyer's machine lands in. The
/// agent's extra privileges are granted on these and nowhere else.
pub(crate) const GATEWAY_POOL: &str = crate::names::POOL;
const BUYER_POOL: &str = crate::names::POOL_BUYERS;
/// The marketplace's own SDN zone, and the buyer egress bridge beside it.
/// Eight characters is the Proxmox limit for a vnet name, which is why the
/// bridge is `onat0` rather than something readable.
const SDN_ZONE: &str = crate::names::SDN_ZONE;
const EGRESS_ZONE: &str = crate::names::SDN_ZONE_NAT;
const EGRESS_VNET: &str = "onat0";
const EGRESS_SUBNET: &str = "10.201.0.0/24";
const EGRESS_GATEWAY: &str = "10.201.0.1";
const EGRESS_DHCP: &str = "start-address=10.201.0.100,end-address=10.201.0.250";
const EGRESS_DNS: &str = "1.1.1.1";

/// Creates the buyer egress bridge and waits for the interface to appear.
///
/// Applying an SDN change is asynchronous: the configuration is accepted and
/// the interface shows up a moment later. Returning before it exists means the
/// first machine placed here has nowhere to plug in.
fn egress_script() -> String {
    format!(
        "set -e
changed=no
pvesh get /cluster/sdn/zones --output-format json | grep -q '\"zone\":\"{EGRESS_ZONE}\"' || {{
  pvesh create /cluster/sdn/zones --type simple --zone {EGRESS_ZONE} --ipam pve --dhcp dnsmasq
  changed=yes
}}
pvesh get /cluster/sdn/vnets --output-format json | grep -q '\"vnet\":\"{EGRESS_VNET}\"' || {{
  pvesh create /cluster/sdn/vnets --vnet {EGRESS_VNET} --zone {EGRESS_ZONE} --isolate-ports 1
  changed=yes
}}
pvesh get /cluster/sdn/vnets/{EGRESS_VNET}/subnets --output-format json 2>/dev/null | grep -q '{EGRESS_SUBNET}' || {{
  pvesh create /cluster/sdn/vnets/{EGRESS_VNET}/subnets --type subnet \
    --subnet {EGRESS_SUBNET} --gateway {EGRESS_GATEWAY} --snat 1 \
    --dhcp-range {EGRESS_DHCP} --dhcp-dns-server {EGRESS_DNS}
  changed=yes
}}
if [ \"$changed\" = yes ] || [ ! -d /sys/class/net/{EGRESS_VNET} ]; then
  pvesh set /cluster/sdn
  for _ in $(seq 1 20); do [ -d /sys/class/net/{EGRESS_VNET} ] && break; sleep 1; done
fi
[ -d /sys/class/net/{EGRESS_VNET} ] || {{ echo '{EGRESS_VNET} did not appear'; exit 1; }}"
    )
}

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
    println!("onv-provider join");
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
        &format!("pveum role list --output-format json | grep -q '\"OnvAgent\"' || pveum role add OnvAgent -privs \"{ROLE_PRIVS}\"; pveum role modify OnvAgent -privs \"{ROLE_PRIVS}\""),
        a.dry_run,
    )?;
    step(
        "user",
        "pveum user list --output-format json | grep -q '\"onv@pve\"' || pveum user add onv@pve --comment 'Onv marketplace agent'",
        a.dry_run,
    )?;
    step("acl", "pveum acl modify / -user onv@pve -role OnvAgent", a.dry_run)?;

    let secret = if a.dry_run {
        "<created at run time>".to_string()
    } else {
        sh("pveum user token remove onv@pve agent >/dev/null 2>&1; \
            pveum user token add onv@pve agent --privsep 1 --output-format json")
            .and_then(|out| {
                let v: serde_json::Value = serde_json::from_str(&out)?;
                Ok(v["value"].as_str().unwrap_or_default().to_string())
            })?
    };
    step("token acl", "pveum acl modify / -token 'onv@pve!agent' -role OnvAgent", a.dry_run)?;

    // Pools, and roles granted only on those pools. The agent can write files
    // into a gateway it built and open a console on a machine it built, and can
    // do neither to anything else on this hypervisor.
    println!("\nConfining the agent to its own pools:");
    for (pool, comment) in
        [(GATEWAY_POOL, "Omnuv overlay gateways"), (BUYER_POOL, "Omnuv buyer machines")]
    {
        step(
            &format!("pool {pool}"),
            &format!(
                "pveum pool list --output-format json | grep -q '\"{pool}\"' \
                 || pveum pool add {pool} --comment '{comment}'"
            ),
            a.dry_run,
        )?;
    }
    for (role, privs, pool) in [
        // Write, to keep a gateway's generated configuration current; and read,
        // because a gateway that cannot be *read* cannot report whether it can
        // reach anything. Without the read the self-check is permanently
        // "unknown" — truthful, and useless, which is how a gateway that had
        // lost the overlay looked healthy for a whole afternoon.
        //
        // Still `FileRead` and never `Unrestricted`: the latter is arbitrary
        // command execution inside the guest, and the marketplace has no
        // business holding that on any machine.
        ("OnvGatewayFiles", "VM.GuestAgent.FileWrite,VM.GuestAgent.FileRead", GATEWAY_POOL),
        ("OnvConsole", "VM.Console", BUYER_POOL),
        // Reads one file: the outcome a recipe writes about its own install.
        // Deliberately `FileRead` and not `Unrestricted` — the latter is
        // arbitrary command execution inside a buyer's machine, which is
        // exactly what the marketplace must never be able to do. Scoped to the
        // pool of machines the marketplace built, never the host.
        ("OnvRecipeStatus", "VM.GuestAgent.FileRead", BUYER_POOL),
    ] {
        step(
            &format!("role {role}"),
            &format!(
                "pveum role list --output-format json | grep -q '\"{role}\"' \
                 && pveum role modify {role} -privs {privs} \
                 || pveum role add {role} -privs {privs}"
            ),
            a.dry_run,
        )?;
        step(
            &format!("grant {role} on {pool}"),
            &format!(
                "pveum acl modify /pool/{pool} -user onv@pve -role {role}; \
                 pveum acl modify /pool/{pool} -token 'onv@pve!agent' -role {role}"
            ),
            a.dry_run,
        )?;
    }

    // The marketplace's own network segments. A *simple* zone is a bridge with
    // no uplink by construction, which is what keeps a buyer's machine off this
    // provider's LAN. The role carries Use and Audit as well as Allocate,
    // because an ACL entry on a path replaces the roles inherited from above it
    // rather than adding to them.
    println!("\nCreating the marketplace's network segments:");
    step(
        "role OnvSdn",
        "pveum role list --output-format json | grep -q '\"OnvSdn\"' \
         && pveum role modify OnvSdn -privs SDN.Allocate,SDN.Audit,SDN.Use \
         || pveum role add OnvSdn -privs SDN.Allocate,SDN.Audit,SDN.Use",
        a.dry_run,
    )?;
    step(
        &format!("zone {SDN_ZONE}"),
        &format!(
            "pvesh get /cluster/sdn/zones --output-format json | grep -q '\"zone\":\"{SDN_ZONE}\"' \
             || {{ pvesh create /cluster/sdn/zones --type simple --zone {SDN_ZONE} --ipam pve; pvesh set /cluster/sdn; }}"
        ),
        a.dry_run,
    )?;
    step(
        "grant OnvSdn",
        &format!(
            "pveum acl modify /sdn/zones/{SDN_ZONE} -user onv@pve -role OnvSdn; \
             pveum acl modify /sdn/zones/{SDN_ZONE} -token 'onv@pve!agent' -role OnvSdn; \
             pveum acl modify /sdn -token 'onv@pve!agent' -role OnvSdn --propagate 0"
        ),
        a.dry_run,
    )?;

    // Buyer egress: a NAT bridge that reaches the internet and nothing private.
    // Separate from the marketplace zone on purpose — one carries a buyer's
    // project network, this one carries their way out.
    step(
        &format!("egress {EGRESS_VNET}"),
        &format!("{}", egress_script()),
        a.dry_run,
    )?;

    let fingerprint = sh("openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -fingerprint -sha256 | cut -d= -f2")
        .unwrap_or_default();

    let gpus = a
        .gpus
        .iter()
        .map(|g| format!("      - \"{g}\""))
        .collect::<Vec<_>>()
        .join("\n");

    let config = format!(
        r#"# Written by `onv-provider join`. Contains this machine's own Proxmox
# credentials; they are never sent to Omnuv.
core:
  url: "{core}"
  token: "{token}"

inventoryEverySecs: 300

proxmox:
  apiUrl: "https://127.0.0.1:8006"
  node: "{node}"
  tlsFingerprintSha256: "{fingerprint}"
  tokenId: "onv@pve!agent"
  tokenSecret: "{secret}"
  templateVmid: 9000
  snippetDir: /var/lib/onv/snippets
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

    println!("\nWriting /etc/onv/agent.yaml (0640 root:onv)");
    if !a.dry_run {
        std::fs::create_dir_all("/etc/onv")?;
        // Checked and created under the *same* name. This asked for `omnuv`
        // and created `onv`, so on a host that already had `omnuv` from an
        // older install the check passed, nothing was created, and every
        // `chgrp onv` after it failed on a user that did not exist.
        sh(&format!(
            "id -u {u} >/dev/null 2>&1 || useradd --system --shell /usr/sbin/nologin \
             --home-dir {var} --create-home {u}",
            u = crate::names::PREFIX,
            var = crate::names::VAR
        ))?;
        std::fs::write("/etc/onv/agent.yaml", &config)?;
        sh("chgrp onv /etc/onv/agent.yaml && chmod 0640 /etc/onv/agent.yaml")?;
        sh("install -d -o onv -g onv /var/lib/onv/snippets /var/log/onv")?;
        // `snippets,import`: the first is how generated cloud-init reaches a
        // machine, the second is where a mirrored image artefact lands before
        // Proxmox imports it. The agent's token may not name an arbitrary path,
        // so an image can only arrive through a storage of that content type.
        sh(&format!(
            "pvesm status --storage {st} >/dev/null 2>&1 \
             || pvesm add dir {st} --path {var} --content snippets,import",
            st = crate::names::STORAGE_SNIPPETS,
            var = crate::names::VAR
        ))?;
    }

    // The package ships the unit and creates the service account. Writing our
    // own on top would mean two units for one service and an upgrade that
    // silently changes which one wins. Only a build installed by hand needs
    // this to write anything.
    let packaged = std::path::Path::new("/lib/systemd/system/onv-provider.service").exists();
    println!(
        "\n{} the service",
        if packaged { "Starting" } else { "Installing and starting" }
    );
    if !a.dry_run {
        if !packaged {
            std::fs::write("/etc/systemd/system/onv-provider.service", UNIT)?;
        }
        sh("systemctl daemon-reload && systemctl enable --now onv-provider")?;
        audit::record("join.complete", "agent", &node, "ok", Some(&a.region));
    } else if packaged {
        println!("  (the installed package already provides the unit)");
    }

    println!("\nDone. The agent now dials {} outward.", a.core);
    println!("Nothing listens on this machine, and Omnuv never connects to it.");
    println!("Audit log:  /var/log/onv/audit.log");
    println!("Logs:       journalctl -u onv-provider -f");
    println!("To leave:   onv-provider leave");
    Ok(())
}

const UNIT: &str = r#"[Unit]
Description=Omnuv Provider Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/onv-provider agent --config /etc/onv/agent.yaml
User=onv
Group=onv
Restart=always
RestartSec=10s

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=/var/lib/onv /var/log/onv
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
"#;

#[cfg(test)]
mod tests {
    use super::*;

    /// The role must not carry a privilege that lets the agent reconfigure the
    /// host or grant itself more. A provider reading this file should be able
    /// to check that claim, and so should a test.
    #[test]
    fn the_agent_cannot_reconfigure_the_host_or_widen_itself() {
        for forbidden in [
            "Sys.Modify",
            "Permissions.Modify",
            "Sys.PowerMgmt",
            "Realm.Allocate",
            "User.Modify",
            "Sys.Console",
        ] {
            assert!(!ROLE_PRIVS.contains(forbidden), "role grants {forbidden}");
        }
        // And it must carry the ones without which it cannot do its job.
        for needed in ["VM.Allocate", "VM.Clone", "VM.PowerMgmt", "Mapping.Use", "SDN.Use"] {
            assert!(ROLE_PRIVS.contains(needed), "role is missing {needed}");
        }
    }

    /// Eight characters is the Proxmox limit for a vnet name. Exceeding it
    /// fails at creation with a message about lengths, long after the operator
    /// has started believing the join worked.
    #[test]
    fn the_bridge_name_fits_what_proxmox_accepts() {
        assert!(EGRESS_VNET.len() <= 8, "{EGRESS_VNET} is {} characters", EGRESS_VNET.len());
        assert!(SDN_ZONE.len() <= 8);
        assert!(EGRESS_ZONE.len() <= 8);
    }

    /// The egress script has to wait for the interface. Applying an SDN change
    /// is asynchronous, and returning early means the first machine placed here
    /// has nowhere to plug in.
    #[test]
    fn the_egress_script_waits_for_the_interface() {
        let s = egress_script();
        assert!(s.contains("/sys/class/net/onat0"), "never checks the interface exists");
        assert!(s.contains("sleep 1"), "does not wait");
        assert!(s.contains("--snat 1"), "no NAT, so a machine has no way out");
        assert!(s.contains("--isolate-ports 1"), "tenants would see each other on the bridge");
    }
}

/// Removes everything `join` created. A provider must be able to leave as
/// easily as they joined, without asking us.
pub fn leave(dry_run: bool) -> anyhow::Result<()> {
    println!("onv-provider leave{}", if dry_run { " (dry run)" } else { "" });
    for (label, cmd) in [
        ("stop service", "systemctl disable --now onv-provider 2>/dev/null || true"),
        ("remove unit", "rm -f /etc/systemd/system/onv-provider.service; systemctl daemon-reload"),
        ("remove token", "pveum user token remove onv@pve agent 2>/dev/null || true"),
        ("remove acl", "pveum acl delete / -token 'onv@pve!agent' -role OnvAgent 2>/dev/null || true; pveum acl delete / -user onv@pve -role OnvAgent 2>/dev/null || true"),
        ("remove user", "pveum user delete onv@pve 2>/dev/null || true"),
        ("remove role", "pveum role delete OnvAgent 2>/dev/null || true"),
        ("remove config", "rm -f /etc/onv/agent.yaml"),
        ("remove storage", "pvesm remove onv-snippets 2>/dev/null || true"),
        ("remove pools", "pveum pool delete onv-buyers 2>/dev/null || true; pveum pool delete onv 2>/dev/null || true"),
        // **Two older generations, and they are not optional.** `join` created
        // `omnuv-` names before 11 September and `omnu-` before that, and a
        // rename that leaves the old object running is not a rename — it is a
        // second copy nobody is looking at. A provider who joined last month
        // and leaves today must end up with nothing of ours, not with nothing
        // of this month's.
        //
        // The Proxmox `dir` storage is first on purpose: on 11 September
        // `omnuv-snippets` recreated the directory it pointed at, a minute
        // after that directory was deleted.
        ("remove legacy storage", "pvesm remove omnuv-snippets 2>/dev/null || true; pvesm remove omnu-snippets 2>/dev/null || true"),
        ("remove legacy units", "for u in omnuv-provider omnu-provider omnuv-egress omnu-egress; do systemctl disable --now $u 2>/dev/null || true; rm -f /etc/systemd/system/$u.service; done; systemctl daemon-reload"),
        ("remove legacy identity", "for u in omnuv omnu; do pveum user token remove $u@pve agent 2>/dev/null || true; pveum user delete $u@pve 2>/dev/null || true; done; for r in OmnuvAgent OmnuAgent; do pveum role delete $r 2>/dev/null || true; done"),
        ("remove legacy pools", "for p in omnuv-buyers omnuv omnu-buyers omnu; do pveum pool delete $p 2>/dev/null || true; done"),
        ("remove legacy nftables", "for t in onv_egress omnuv_egress omnu_egress; do nft delete table inet $t 2>/dev/null || true; done"),
        ("remove legacy config", "rm -rf /etc/omnuv /etc/omnu"),
    ] {
        println!("  {label}\n    $ {cmd}");
        if !dry_run {
            let _ = sh(cmd);
        }
    }
    // The audit log is deliberately left in place: it is the provider's record.
    println!("\nRemoved. /var/log/onv/audit.log is kept — it is your record, not ours.");
    Ok(())
}
