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
VM.GuestAgent.Audit,Mapping.Audit,Mapping.Use,SDN.Audit,SDN.Use,Pool.Audit";

/// The pool a gateway lands in, and the pool a buyer's machine lands in. The
/// agent's extra privileges are granted on these and nowhere else.
pub(crate) const GATEWAY_POOL: &str = crate::names::POOL;
const BUYER_POOL: &str = crate::names::POOL_BUYERS;
/// The marketplace's own SDN zone, and the buyer egress bridge beside it.
/// Eight characters is the Proxmox limit for a vnet name, and `onvnat0` is
/// seven.
const SDN_ZONE: &str = crate::names::SDN_ZONE;
const EGRESS_ZONE: &str = crate::names::SDN_ZONE_NAT;
// **The name buyer machines attach to** (`instance::EGRESS_BRIDGE`, which is
// `names::NAT_VNET`). This said `onat0` after the agent moved to `onvnat0`, so a
// host joined by hand got a NAT bridge no machine used, and the first buyer
// machine failed with "bridge 'onvnat0' does not exist".
const EGRESS_VNET: &str = crate::names::NAT_VNET;
const EGRESS_TABLE: &str = crate::names::EGRESS_TABLE;
const EGRESS_UNIT: &str = crate::names::EGRESS_UNIT;
pub(crate) const EGRESS_SUBNET: &str = "10.201.0.0/24";
const EGRESS_GATEWAY: &str = "10.201.0.1";
const EGRESS_DHCP: &str = "start-address=10.201.0.100,end-address=10.201.0.250";
const EGRESS_DNS: &str = "1.1.1.1";

/// Creates the buyer egress bridge and waits for the interface to appear.
///
/// Applying an SDN change is asynchronous: the configuration is accepted and
/// the interface shows up a moment later. Returning before it exists means the
/// first machine placed here has nowhere to plug in.
/// **Where the agent's privileges are granted (PROVIDER-20, 1 October 2026).**
/// The roles that manage a machine sit on the marketplace's pools, the storages
/// it writes, the card mappings and the zones it attaches to; `/` holds reads
/// alone. So the token cannot touch a guest outside its pools whatever the
/// agent's own claim-tag rule says. The same grants `deploy-agent.yml` writes,
/// measured there on Titan and Pluto: a clone also needs SDN.Use on
/// `localnetwork` (the template's net0 is on vmbr0) and on the NAT zone.
/// A grant of OnvAgent on `/` from an earlier join is taken away.
fn grants_script(storage: &str) -> String {
    let roles = [
        ("OnvAgentRead", "Sys.Audit,Datastore.Audit,VM.Audit,Mapping.Audit,SDN.Audit,Pool.Audit"),
        ("OnvStorage", "Datastore.AllocateSpace,Datastore.Audit"),
        ("OnvMapping", "Mapping.Use,Mapping.Audit"),
        ("OnvNetUse", "SDN.Use,SDN.Audit"),
    ];
    let mut paths: Vec<(String, &str)> = vec![
        (format!("/pool/{GATEWAY_POOL}"), "OnvAgent"),
        (format!("/pool/{BUYER_POOL}"), "OnvAgent"),
        (format!("/storage/{storage}"), "OnvStorage"),
        ("/mapping/pci".to_string(), "OnvMapping"),
        (format!("/sdn/zones/{EGRESS_ZONE}"), "OnvNetUse"),
        ("/sdn/zones/localnetwork".to_string(), "OnvNetUse"),
        ("/".to_string(), "OnvAgentRead"),
    ];
    if storage != crate::names::STORAGE_SNIPPETS {
        paths.push((format!("/storage/{}", crate::names::STORAGE_SNIPPETS), "OnvStorage"));
    }
    let mut lines: Vec<String> = roles
        .iter()
        .map(|(role, privs)| {
            format!(
                "{{ pveum role list --output-format json | grep -q '\"{role}\"' \
                 && pveum role modify {role} -privs {privs} || pveum role add {role} -privs {privs}; }}"
            )
        })
        .collect();
    for who in ["-user onv@pve", "-token 'onv@pve!agent'"] {
        for (path, role) in &paths {
            lines.push(format!("pveum acl modify {path} {who} -role {role}"));
        }
        lines.push(format!("{{ pveum acl delete / {who} -role OnvAgent 2>/dev/null || true; }}"));
    }
    lines.join(" && ")
}

/// The buyer egress policy `join` installs: the same table `deploy-agent.yml`
/// renders from `templates/egress.nft.j2` in the omnuv repository, with this
/// file's constants for its two variables. It is the whole of a buyer's way
/// out: what may leave, what the host answers, and the address translation.
///
/// **The translation is here, not in Proxmox SDN (4 October 2026).** The
/// subnet's `snat` flag made Proxmox write `post-up iptables -t nat -A …` and
/// `post-up iptables -t raw -I PREROUTING -i fwbr+ -j CT --zone 1` into the
/// bridge's stanza, and ifupdown2 re-runs every `post-up` on every
/// `ifreload -a` (each SDN apply, which the agent makes whenever it creates or
/// reaps a segment) while it runs a `post-down` only for an interface it
/// removes (`ifreload_down_changed=0` on Proxmox). So every apply left one
/// more copy of both: 183 SNAT and 267 CT on Pluto that day. This table is
/// loaded whole in one `nft -f` transaction that first deletes it, so it
/// holds one copy however often it is loaded.
///
/// Before this, `join` left the egress bridge with Proxmox's translation and
/// no policy at all: a buyer machine on a joined host could reach the
/// provider's LAN, which a host `deploy-agent.yml` provisioned never could.
fn egress_nft() -> String {
    format!(
        r#"#!/usr/sbin/nft -f
# Omnuv buyer egress policy for {EGRESS_VNET}. Written by onv-provider join.
table inet {EGRESS_TABLE}
delete table inet {EGRESS_TABLE}

table inet {EGRESS_TABLE} {{
    set private {{
        type ipv4_addr
        flags interval
        elements = {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 }}
    }}

    chain forward {{
        type filter hook forward priority filter - 10; policy accept;
        iifname "{EGRESS_VNET}" ip daddr @private drop
        iifname "{EGRESS_VNET}" ip6 daddr {{ fc00::/7, fe80::/10 }} drop
        oifname "{EGRESS_VNET}" ct state new drop
    }}

    chain input {{
        type filter hook input priority filter - 10; policy accept;
        iifname "{EGRESS_VNET}" udp dport 67 accept
        iifname "{EGRESS_VNET}" ip daddr {EGRESS_GATEWAY} udp dport 53 accept
        iifname "{EGRESS_VNET}" ip daddr {EGRESS_GATEWAY} tcp dport 53 accept
        iifname "{EGRESS_VNET}" ip daddr {EGRESS_GATEWAY} icmp type echo-request accept
        iifname "{EGRESS_VNET}" drop
    }}

    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        meta nfproto ipv4 iifname "{EGRESS_VNET}" oifname != "{EGRESS_VNET}" masquerade
    }}

    chain prerouting {{
        type filter hook prerouting priority raw; policy accept;
        meta nfproto ipv4 iifname "fwbr*" ct zone set 1
    }}
}}
"#
    )
}

/// The unit that loads it at boot. No `nft delete table` before the load: the
/// file deletes its own table inside the transaction that defines it again,
/// so there is no moment without a policy.
fn egress_unit() -> String {
    format!(
        "[Unit]
Description=Omnuv buyer egress policy (nftables table {EGRESS_TABLE})
After=network-online.target pve-firewall.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/onv/egress.nft
ExecStop=-/usr/sbin/nft delete table inet {EGRESS_TABLE}

[Install]
WantedBy=multi-user.target
"
    )
}

/// Every copy of the SNAT the flag left for the egress subnet, and the CT rule
/// down to none, or to one if another stanza still generates it. The same
/// rules as `deployment/ansible/files/egress-nat-handover.sh` in the omnuv
/// repository, whose hermetic test reloads both shapes many times; this copy
/// is pinned by the tests below. Reads the SDN file from `$sdn`.
fn egress_handover() -> String {
    format!(
        "for r in $(iptables-save -t nat | awk '$1 == \"-A\" && $2 == \"POSTROUTING\" && $3 == \"-s\" && $4 == \"{EGRESS_SUBNET}\" && $5 == \"-o\" && $7 == \"-j\" && $8 == \"SNAT\" && $9 == \"--to-source\" && NF == 10 {{ print $6 \",\" $10 }}'); do
  iptables -t nat -D POSTROUTING -s {EGRESS_SUBNET} -o \"${{r%,*}}\" -j SNAT --to-source \"${{r#*,}}\"
done
keep=0
grep -qF -- 'post-up iptables -t raw -I PREROUTING -i fwbr+ -j CT --zone 1' \"$sdn\" && keep=1
have=$(iptables-save -t raw | grep -cxF -- '-A PREROUTING -i fwbr+ -j CT --zone 1' || true)
while [ \"$have\" -gt \"$keep\" ]; do iptables -t raw -D PREROUTING -i 'fwbr+' -j CT --zone 1; have=$((have - 1)); done
[ \"$(iptables-save -t nat | grep -c -- '-s {EGRESS_SUBNET} .*-j SNAT' || true)\" = 0 ] || {{ echo 'SNAT copies for {EGRESS_SUBNET} are still there'; exit 1; }}
"
    )
}

fn egress_script() -> String {
    let nft = egress_nft();
    let unit = egress_unit();
    let handover = egress_handover();
    format!(
        "set -e
changed=no
sdn=/etc/network/interfaces.d/sdn
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
    --subnet {EGRESS_SUBNET} --gateway {EGRESS_GATEWAY} \
    --dhcp-range {EGRESS_DHCP} --dhcp-dns-server {EGRESS_DNS}
  changed=yes
}}
# The policy and its translation first, so turning the flag off below never
# leaves a moment with no way out.
install -d -m 0755 /etc/onv
cat > /etc/onv/egress.nft <<'ONV_EGRESS_NFT'
{nft}ONV_EGRESS_NFT
cat > /etc/systemd/system/{EGRESS_UNIT}.service <<'ONV_EGRESS_UNIT'
{unit}ONV_EGRESS_UNIT
systemctl daemon-reload
systemctl enable {EGRESS_UNIT} >/dev/null 2>&1
systemctl restart {EGRESS_UNIT}
nft list chain inet {EGRESS_TABLE} postrouting | grep -q masquerade
# A subnet an earlier join made carries Proxmox's snat flag: off.
read -r id snat < <(pvesh get /cluster/sdn/vnets/{EGRESS_VNET}/subnets --output-format json \
  | python3 -c 'import json, sys; s = next(s for s in json.load(sys.stdin) if s.get(\"cidr\") == \"{EGRESS_SUBNET}\"); print(s[\"subnet\"], int(s.get(\"snat\") or 0))')
if [ \"$snat\" != 0 ]; then
  pvesh set /cluster/sdn/vnets/{EGRESS_VNET}/subnets/$id --snat 0
  changed=yes
fi
if [ \"$changed\" = yes ] || [ ! -d /sys/class/net/{EGRESS_VNET} ]; then
  pvesh set /cluster/sdn
  for _ in $(seq 1 20); do [ -d /sys/class/net/{EGRESS_VNET} ] && break; sleep 1; done
fi
[ -d /sys/class/net/{EGRESS_VNET} ] || {{ echo '{EGRESS_VNET} did not appear'; exit 1; }}
for _ in $(seq 1 30); do grep -qF -- \"-A POSTROUTING -s '{EGRESS_SUBNET}' \" \"$sdn\" || break; sleep 1; done
if grep -qF -- \"-A POSTROUTING -s '{EGRESS_SUBNET}' \" \"$sdn\"; then echo 'the SDN file still generates the SNAT'; exit 1; fi
{handover}"
    )
}

pub struct JoinArgs {
    pub core: String,
    pub token: omnuv_protocol::Redacted,
    pub region: String,
    pub cpu_cores: u32,
    pub memory_mib: u64,
    pub disk_gib: u64,
    pub storage: Option<String>,
    pub gpus: Vec<String>,
    /// **The provider opening** (`crate::opening`), off unless
    /// `--opening-reach` is given: written into agent.yaml as every other key.
    pub opening: crate::opening::OpeningConfig,
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
    //
    // **The package, or nothing (24 September 2026).** Without it, join wrote a
    // unit of its own whose ExecStart was /usr/local/bin/onv-provider and whose
    // User was onv: no step installs that binary (deploy-agent deletes the
    // path) and only the package creates that account, so the service it
    // enabled could never start. By then join had already made the Proxmox
    // account and written the config, so the refusal is here, before any of it.
    let packaged = std::path::Path::new(PACKAGED_UNIT).exists();
    if !packaged && !a.dry_run {
        anyhow::bail!(
            "onv-provider is not installed from its package ({PACKAGED_UNIT} is missing). \
             Install the .deb (packaging/build-deb.sh builds it), then run join again; nothing was changed"
        );
    }
    // The opening, checked before anything is changed: a host told to open
    // with nothing to reach it by is refused here, in the agent's own words.
    if let Err(bad) = a.opening.check() {
        anyhow::bail!("the opening was refused, and nothing was changed:\n  {}", bad.join("\n  "));
    }
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

    let secret = if a.dry_run {
        "<created at run time>".to_string()
    } else {
        sh("pveum user token remove onv@pve agent >/dev/null 2>&1; \
            pveum user token add onv@pve agent --privsep 1 --output-format json")
            .and_then(|out| token_secret(&out))?
    };

    // Pools, and roles granted only on those pools. The agent can write files
    // into a gateway it built and open a console on a machine it built, and can
    // do neither to anything else on this hypervisor.
    println!("\nConfining the agent to its own pools:");
    for (pool, comment) in
        [(GATEWAY_POOL, "Omnuv marketplace-owned machines"), (BUYER_POOL, "Omnuv buyer machines")]
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
        // Read, because a Workload Agent reports through a file its worker
        // writes; and `Pool.Audit`, because an ACL on the pool replaces what is
        // inherited from `/`, and without it the agent cannot see the pool it
        // clones into. The same role `deploy-agent.yml` writes.
        //
        // No `FileWrite`: it existed to refresh a gateway's configuration, and
        // topology v2 removed gateways. Never `Unrestricted`, which is
        // arbitrary command execution inside the guest.
        ("OnvWorkloadFiles", "VM.GuestAgent.FileRead,Pool.Audit", GATEWAY_POOL),
        ("OnvConsole", "VM.Console", BUYER_POOL),
        // Reads the files a recipe writes about its own install and its
        // streaming identity, and writes one: the devices allowed to stream
        // (pairing by certificate, the operator's P-1, 5 October 2026), which
        // the machine's own converger applies. `FileRead` and `FileWrite`, not
        // `Unrestricted` — the latter is arbitrary command execution inside a
        // buyer's machine. Scoped to the pool of machines the marketplace
        // built, never the host.
        ("OnvRecipeStatus", "VM.GuestAgent.FileRead,VM.GuestAgent.FileWrite", BUYER_POOL),
        // Sets a buyer's console password when they reset it (BUYER-18).
        // `set-user-password` needs `Unrestricted`, which is also `exec`: root
        // inside the guest. The operator granted it on 23 September 2026, on
        // the buyer pool only, because the agent could already get the same by
        // rewriting a machine's cloud-init and rebooting it — Proxmox derives
        // the instance-id from the user-data, so cloud-init would run it again
        // as root. What this adds is doing it without a reboot, which is a
        // difference in visibility, not in power. The agent calls
        // `set-user-password` and nothing else with it.
        ("OnvConsolePassword", "VM.GuestAgent.Unrestricted", BUYER_POOL),
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
        &egress_script(),
        a.dry_run,
    )?;

    // After the egress zone exists: the agent's grants, on its own paths.
    println!("\nGranting the agent its pools, storage, cards and zones, and reads at /:");
    step("grants", &grants_script(&storage), a.dry_run)?;

    // **The host timer's own token** (omnuv's modular design, A3): it stops a
    // buyer's machine past its run lease while the agent is down, so it holds
    // VM.Audit and VM.PowerMgmt on the buyers' pool and nothing else, never the
    // agent's token, and never Core's. Its unit loads it with LoadCredential=
    // from a file only root can read. The same token deploy-agent.yml mints.
    println!("\nCreating the host timer's token, which can stop a buyer's machine and do nothing else:");
    step(&format!("role {LEASE_ROLE}"), &lease_role_script(), a.dry_run)?;
    let lease_secret = if a.dry_run {
        "<created at run time>".to_string()
    } else {
        sh(&format!(
            "pveum user token remove onv@pve {name} >/dev/null 2>&1; \
             pveum user token add onv@pve {name} --privsep 1 --output-format json",
            name = onv_agent_lib::lease_token::TOKEN_NAME
        ))
        .and_then(|out| token_secret(&out))?
    };
    step(&format!("grant {LEASE_ROLE} on {BUYER_POOL}"), &lease_grant_script(), a.dry_run)?;

    let fingerprint = sh("openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -fingerprint -sha256 | cut -d= -f2")
        .unwrap_or_default();

    let gpus = a
        .gpus
        .iter()
        .map(|g| format!("      - \"{g}\""))
        .collect::<Vec<_>>()
        .join("\n");

    let config = config_file(&a.core, &node, &fingerprint, &storage, a.cpu_cores, a.memory_mib, a.disk_gib, &gpus, &a.opening)?;
    let secrets = secrets_file(&a.token, &secret);

    println!("\nWriting /etc/onv/agent.yaml (0640 root:onv) and /etc/onv/{} (0600 onv:onv)", crate::config::SECRETS_FILE);
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
        // Created with their modes, never wider: `fs::write` then `chmod` left
        // the file world-readable, with both credentials in it, between the
        // two. The credentials are in their own file now, readable by the
        // agent's account alone, and the agent refuses one anybody else can
        // read.
        crate::names::write_private("/etc/onv/agent.yaml", config.as_bytes(), 0o640)?;
        sh("chgrp onv /etc/onv/agent.yaml")?;
        let secrets_path = format!("/etc/onv/{}", crate::config::SECRETS_FILE);
        crate::names::write_private(&secrets_path, secrets.as_bytes(), 0o600)?;
        sh(&format!("chown onv:onv {secrets_path}"))?;
        // Root's alone: systemd reads it for onv-lease-expire.service and hands
        // that run a copy; the agent, running as onv, cannot read it.
        crate::names::write_private(
            onv_agent_lib::lease_token::CREDENTIAL_SOURCE,
            lease_secrets_file(&lease_secret).as_bytes(),
            0o600,
        )?;
        sh("install -d -o onv -g onv /var/lib/onv/snippets /var/log/onv")?;
        // **And the audit log inside it.** `main` opened it before this ran,
        // as root, so it was root:root 0644 and the agent (`User=onv`) could
        // never append to it: every event went to the journal only, with a
        // warning nobody reads, on every host joined by hand.
        sh("touch /var/log/onv/audit.log && chown onv:onv /var/log/onv/audit.log \
            && chmod 0640 /var/log/onv/audit.log")?;
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
    println!("\nStarting the service");
    if !a.dry_run {
        sh("systemctl daemon-reload && systemctl enable --now onv-provider")?;
        // The opening's applier, once, so the kernel holds what agent.yaml
        // says from now on (off removes the table); its verdict is printed.
        let applied = Command::new("systemctl").args(["start", "onv-opening.service"]).status()?;
        let said = sh("journalctl -u onv-opening.service -n 1 -o cat --no-pager").unwrap_or_default();
        println!("  {said}");
        if !applied.success() {
            anyhow::bail!("onv-opening.service failed; the opening is not applied ({said})");
        }
        audit::record("join.complete", "agent", &node, "ok", Some(&a.region));
    } else if !packaged {
        println!("  (not installed from the package: a real run refuses at the start)");
    }

    println!("\nDone. The agent now dials {} outward.", a.core);
    println!("Nothing listens on this machine, and Omnuv never connects to it.");
    println!("Audit log:  /var/log/onv/audit.log");
    println!("Logs:       journalctl -u onv-provider -f");
    println!("To leave:   onv-provider leave");
    Ok(())
}

const PACKAGED_UNIT: &str = "/lib/systemd/system/onv-provider.service";

/// `agent.yaml` as `join` writes it: no credential in it, and every timing at
/// the value this build ships with, so the file on the host is the whole
/// configuration, as `deploy-agent.yml` writes it.
#[allow(clippy::too_many_arguments)] // One per line of the file it writes.
fn config_file(
    core: &str,
    node: &str,
    fingerprint: &str,
    storage: &str,
    cpu: u32,
    memory_mib: u64,
    disk_gib: u64,
    gpus: &str,
    opening: &crate::opening::OpeningConfig,
) -> anyhow::Result<String> {
    let opening: String = serde_yaml_ng::to_string(opening)?.lines().map(|l| format!("  {l}\n")).collect();
    let timings: String = serde_yaml_ng::to_string(&crate::timings::Timings::default())?
        .lines()
        .map(|l| format!("  {l}\n"))
        .collect();
    Ok(format!(
        r#"# Written by `onv-provider join`. This machine's own credentials are in
# {secrets} beside it, mode 0600; they are never sent to Omnuv.
core:
  url: "{core}"

proxmox:
  apiUrl: "https://127.0.0.1:8006"
  node: "{node}"
  tlsFingerprintSha256: "{fingerprint}"
  tokenId: "onv@pve!agent"
  templateVmid: 9000
  snippetDir: /var/lib/onv/snippets
  contribute:
    cpuCores: {cpu}
    memoryMib: {memory_mib}
    diskGib: {disk_gib}
    storage: ["{storage}"]
    gpus:
{gpus}

# The provider opening: one UDP port of this host's public side per buyer
# machine, so peers reach it directly. Off unless `join` was given
# --opening-reach.
opening:
{opening}
# How long, how often, how many: every key, at the values this build ships
# with. `onv-provider check-config` checks a change before a restart.
timings:
{timings}"#,
        secrets = crate::config::SECRETS_FILE,
        gpus = if gpus.is_empty() { "      []" } else { gpus },
    ))
}

/// What a `pveum user token add --output-format json` printed: its secret.
/// **An empty secret is a failure, not a value.** It was written into
/// agent.yaml as "", and the agent then failed every call to the hypervisor
/// with an authentication error far from here.
fn token_secret(out: &str) -> anyhow::Result<String> {
    let v: serde_json::Value = serde_json::from_str(out)?;
    v["value"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("pveum created a token and printed no secret"))
}

/// The host timer's role: `lease_token::PRIVILEGES`, the reads before a
/// stop and the stop.
const LEASE_ROLE: &str = onv_agent_lib::lease_token::ROLE;

fn lease_role_script() -> String {
    let privs = onv_agent_lib::lease_token::PRIVILEGES.join(",");
    format!(
        "pveum role list --output-format json | grep -q '\"{LEASE_ROLE}\"' \
         && pveum role modify {LEASE_ROLE} -privs {privs} \
         || pveum role add {LEASE_ROLE} -privs {privs}"
    )
}

/// The host timer's one grant: its role on the buyers' pool, to its token
/// alone. A privilege-separated token holds the intersection of its own
/// grants and its user's, so this is all it holds.
fn lease_grant_script() -> String {
    format!(
        "pveum acl modify /pool/{BUYER_POOL} -token 'onv@pve!{}' -role {LEASE_ROLE}",
        onv_agent_lib::lease_token::TOKEN_NAME
    )
}

/// `lease-secrets.yaml`, the host timer's credential: its token's id beside
/// its secret, each a JSON string, which is a YAML one.
fn lease_secrets_file(secret: &str) -> String {
    format!(
        "# Written by `onv-provider join`: the host timer's Proxmox token, mode 0600, root's.\n\
         # onv-lease-expire.service loads it with LoadCredential=; nothing else reads it.\n\
         proxmoxTokenId: {}\nproxmoxTokenSecret: {}\n",
        serde_json::Value::from(format!("onv@pve!{}", onv_agent_lib::lease_token::TOKEN_NAME)),
        serde_json::Value::from(secret)
    )
}

/// `agent-secrets.yaml` as `join` writes it. Each value is written as a JSON
/// string, which is a YAML one, so no character in a credential can end it.
fn secrets_file(core_token: &omnuv_protocol::Redacted, pve_secret: &str) -> String {
    format!(
        "# Written by `onv-provider join`: this provider's two credentials, mode 0600.\n\
         coreToken: {}\nproxmoxTokenSecret: {}\n",
        serde_json::Value::from(core_token.expose()),
        serde_json::Value::from(pve_secret)
    )
}

/// Removes everything `join` created. A provider must be able to leave as
/// easily as they joined, without asking us.
/// The machines a pool listing names, as `vmid`s. Pools are how the
/// marketplace marks its own machines on a host.
/// The pool ids in `pvesh get /pools`.
fn pool_ids(listing: &serde_json::Value) -> Vec<String> {
    listing
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| p["poolid"].as_str().map(str::to_string))
        .collect()
}

fn machines_in(pool: &serde_json::Value) -> Vec<u64> {
    pool["members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|m| m["type"] == "qemu")
        .filter_map(|m| m["vmid"].as_u64())
        .collect()
}

/// The marketplace's SDN objects in a vnet listing, in the order they must go:
/// every vnet of the marketplace's two zones. Their subnets are removed per
/// vnet before it, and the zones after.
fn marketplace_vnets(vnets: &serde_json::Value) -> Vec<String> {
    vnets
        .as_array()
        .into_iter()
        .flatten()
        .filter(|v| v["zone"] == SDN_ZONE || v["zone"] == EGRESS_ZONE)
        .filter_map(|v| v["vnet"].as_str().map(str::to_string))
        .collect()
}

pub async fn leave(dry_run: bool, without_core: bool, config: &str) -> anyhow::Result<()> {
    println!("onv-provider leave{}", if dry_run { " (dry run)" } else { "" });

    // **Refused while the marketplace still has a machine here.** What leave
    // removes below includes the network every buyer machine is attached to;
    // removing it from under a running machine would cut that machine off.
    // Nothing is changed before this check.
    //
    // **And refused when the question could not be asked (PROVIDER-25).** Each
    // pool used to be read with `if let Ok(..)`, so a failed query — the API
    // down, a permission missing — counted as an empty pool and leave went on
    // to remove the network under whatever was there. The pools are listed
    // first, which only succeeds if the API answers; a pool absent from that
    // list is genuinely empty, and one present that cannot be read stops leave.
    let listed = sh("pvesh get /pools --output-format json")
        .and_then(|out| Ok(serde_json::from_str::<serde_json::Value>(&out)?))
        .map_err(|e| anyhow::anyhow!("could not list this host's pools, so whether the marketplace still has machines here is unknown; nothing was changed: {e}"))?;
    let existing = pool_ids(&listed);
    let mut remaining = Vec::new();
    for pool in [GATEWAY_POOL, BUYER_POOL].into_iter().filter(|p| existing.iter().any(|e| e == p)) {
        let v: serde_json::Value = sh(&format!("pvesh get /pools/{pool} --output-format json"))
            .and_then(|out| Ok(serde_json::from_str(&out)?))
            .map_err(|e| anyhow::anyhow!("pool {pool} exists and could not be read; nothing was changed: {e}"))?;
        remaining.extend(machines_in(&v));
    }
    anyhow::ensure!(
        remaining.is_empty(),
        "the marketplace still has machines on this host ({remaining:?}). Leave the \
         marketplace from the provider console first, so they are removed through it, \
         then run leave again."
    );

    // **Core first, while the token that can tell it still exists
    // (PROVIDER-16).** Everything below removes that token.
    match crate::config::load_agent(config) {
        Ok(cfg) if dry_run => println!("  tell Core\n    POST {}/provider/v1/leave", cfg.core.url),
        Ok(cfg) => match crate::agent::leave_core(&cfg.core.url, &cfg.core.token, "the provider's operator ran onv-provider leave").await {
            Ok(crate::agent::CoreLeft::Removed(said)) => println!("  Core removed this provider: {said}"),
            Ok(crate::agent::CoreLeft::AlreadyForgotten) => println!("  Core no longer knows this provider's token; nothing to tell it"),
            Err(e) if without_core => eprintln!("  could not tell Core ({e:#}); going on because --without-core was given. Core still lists this provider and accepts its token."),
            Err(e) => anyhow::bail!(
                "could not tell Core this provider is leaving: {e:#}. Nothing was removed, so the \
                 token that can tell it is still here — run leave again once Core answers, or \
                 pass --without-core to leave Core listing a provider that has gone."
            ),
        },
        Err(e) if without_core => eprintln!("  no agent configuration at {config} ({e:#}); Core was not told"),
        Err(e) => anyhow::bail!(
            "no agent configuration at {config}, so Core cannot be told this provider is leaving: \
             {e:#}. Pass --without-core to leave anyway."
        ),
    }

    for (label, cmd) in [
        ("stop service", "systemctl disable --now onv-provider 2>/dev/null || true"),
        ("remove unit", "rm -f /etc/systemd/system/onv-provider.service; systemctl daemon-reload"),
        ("remove token", "pveum user token remove onv@pve agent 2>/dev/null || true"),
        ("remove the host timer's token", "pveum user token remove onv@pve lease 2>/dev/null || true"),
        ("remove acl", "pveum acl delete / -token 'onv@pve!agent' -role OnvAgent 2>/dev/null || true; pveum acl delete / -user onv@pve -role OnvAgent 2>/dev/null || true"),
        ("remove user", "pveum user delete onv@pve 2>/dev/null || true"),
        ("remove role", "pveum role delete OnvAgent 2>/dev/null || true"),
        ("remove config", "rm -f /etc/onv/agent.yaml /etc/onv/agent-secrets.yaml /etc/onv/lease-secrets.yaml"),
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
        ("remove egress and legacy units", "for u in onv-egress omnuv-provider omnu-provider omnuv-egress omnu-egress; do systemctl disable --now $u 2>/dev/null || true; rm -f /etc/systemd/system/$u.service; done; systemctl daemon-reload"),
        ("remove legacy identity", "for u in omnuv omnu; do pveum user token remove $u@pve agent 2>/dev/null || true; pveum user delete $u@pve 2>/dev/null || true; done; for r in OmnuvAgent OmnuAgent; do pveum role delete $r 2>/dev/null || true; done"),
        ("remove legacy pools", "for p in omnuv-buyers omnuv omnu-buyers omnu; do pveum pool delete $p 2>/dev/null || true; done"),
        ("remove egress nftables", "for t in onv_egress omnuv_egress omnu_egress; do nft delete table inet $t 2>/dev/null || true; done; rm -f /etc/onv/egress.nft"),
        ("remove legacy config", "rm -rf /etc/omnuv /etc/omnu"),
    ] {
        println!("  {label}\n    $ {cmd}");
        if !dry_run {
            let _ = sh(cmd);
        }
    }
    // The audit log is deliberately left in place: it is the provider's record.
    // What join creates that the list above did not remove: the roles granted
    // on the pools and the SDN zone, and the marketplace's two SDN zones with
    // every vnet and subnet in them (the old `onat0` bridge included).
    step(
        "remove pool and SDN roles",
        "for r in OnvSdn OnvWorkloadFiles OnvConsole OnvRecipeStatus OnvConsolePassword OnvAgentRead OnvStorage OnvMapping OnvNetUse OnvLease; do pveum role delete $r 2>/dev/null || true; done",
        dry_run,
    )?;
    let vnets = if dry_run {
        Vec::new()
    } else {
        sh("pvesh get /cluster/sdn/vnets --output-format json")
            .ok()
            .and_then(|o| serde_json::from_str::<serde_json::Value>(&o).ok())
            .map(|v| marketplace_vnets(&v))
            .unwrap_or_default()
    };
    for vnet in &vnets {
        step(
            &format!("remove segment {vnet}"),
            &format!(
                "for s in $(pvesh get /cluster/sdn/vnets/{vnet}/subnets --output-format json 2>/dev/null \
                   | grep -o '\"id\":\"[^\"]*\"' | cut -d'\"' -f4); do \
                   pvesh delete /cluster/sdn/vnets/{vnet}/subnets/$s 2>/dev/null || true; done; \
                 pvesh delete /cluster/sdn/vnets/{vnet} 2>/dev/null || true"
            ),
            dry_run,
        )?;
    }
    step(
        "remove SDN zones",
        &format!(
            "pvesh delete /cluster/sdn/zones/{SDN_ZONE} 2>/dev/null || true; \
             pvesh delete /cluster/sdn/zones/{EGRESS_ZONE} 2>/dev/null || true; \
             pvesh set /cluster/sdn"
        ),
        dry_run,
    )?;

    println!("\nRemoved. /var/log/onv/audit.log is kept — it is your record, not ours.");
    Ok(())
}

#[cfg(test)]
mod tests {

    /// **PROVIDER-20: nothing that manages a machine is granted at `/`.**
    #[test]
    fn join_grants_manage_only_off_the_root() {
        let script = super::grants_script("zfs-fast");
        let grants: Vec<&str> = script.split(" && ").filter(|l| l.starts_with("pveum acl modify")).collect();
        assert_eq!(grants.len(), 16, "two principals, eight paths each: {grants:#?}");
        for g in &grants {
            let path = g.split_whitespace().nth(3).unwrap();
            if path == "/" {
                assert!(g.ends_with("-role OnvAgentRead"), "/ holds more than reads: {g}");
            }
            if g.ends_with("-role OnvAgent") {
                assert!(path.starts_with("/pool/"), "OnvAgent granted off the pools: {g}");
            }
        }
        for path in ["/storage/zfs-fast", "/mapping/pci", "/sdn/zones/localnetwork", "/pool/onv-buyers"] {
            assert!(grants.iter().any(|g| g.contains(&format!(" {path} -token"))), "the token misses {path}");
        }
        assert!(script.contains("pveum acl delete / -token 'onv@pve!agent' -role OnvAgent"), "an old / grant is left");
        // The storage the snippets live on is granted once, not twice.
        let snip = super::grants_script(crate::names::STORAGE_SNIPPETS);
        assert_eq!(snip.matches("acl modify /storage/").count(), 2, "{snip}");
    }

    /// The pools that exist, from `pvesh get /pools` — and nothing from a
    /// listing that is not one.
    #[test]
    fn the_pools_that_exist_are_read_from_the_listing() {
        let listing = serde_json::json!([{"poolid": "onv"}, {"poolid": "backups", "comment": "x"}]);
        assert_eq!(super::pool_ids(&listing), ["onv", "backups"]);
        assert!(super::pool_ids(&serde_json::json!({"poolid": "onv"})).is_empty());
    }

    #[test]
    fn leave_finds_the_marketplaces_machines_and_segments() {
        use serde_json::json;
        let pool = json!({"members": [
            {"type": "qemu", "vmid": 120}, {"type": "storage", "storage": "onv-snippets"},
            {"type": "qemu", "vmid": 121}]});
        assert_eq!(super::machines_in(&pool), vec![120, 121]);
        assert!(super::machines_in(&json!({"members": []})).is_empty());

        let vnets = json!([
            {"vnet": "onvc4d90", "zone": "onv"}, {"vnet": "onvnat0", "zone": "onvnat"},
            {"vnet": "onat0", "zone": "onvnat"}, {"vnet": "lan", "zone": "operator"}]);
        // Negative: an operator's own zone is never touched.
        assert_eq!(super::marketplace_vnets(&vnets), vec!["onvc4d90", "onvnat0", "onat0"]);
    }
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

    /// **What `join` writes is what the agent loads**: the credentials in their
    /// own file, mode 0600, and nowhere else; every timing written out at its
    /// default; and a credential with a quote in it still one value.
    #[test]
    fn what_join_writes_the_agent_loads() {
        use std::os::unix::fs::PermissionsExt as _;
        let gpus = "      - \"0000:21:00.0\"";
        let off = crate::opening::OpeningConfig::default();
        let config = config_file("https://api.omnuv.com", "n1", "AB:CD", "local", 8, 16_384, 200, gpus, &off).unwrap();
        let secrets = secrets_file(&"prov_x_\"quoted\"".into(), "pve-SEKRET");
        assert!(!config.contains("prov_x") && !config.contains("SEKRET"), "a credential in agent.yaml: {config}");
        assert!(config.contains("  tunnelPing: 20s\n"), "the timings are not written out: {config}");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(&path, &config).unwrap();
        let secrets_path = dir.path().join(crate::config::SECRETS_FILE);
        std::fs::write(&secrets_path, &secrets).unwrap();
        std::fs::set_permissions(&secrets_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let cfg = crate::config::load_agent(path.to_str().unwrap()).expect("join's own files load");
        assert_eq!(cfg.core.token.expose(), "prov_x_\"quoted\"");
        assert_eq!(cfg.proxmox.token_secret.expose(), "pve-SEKRET");
        assert_eq!(cfg.timings, crate::timings::Timings::default());
        assert_eq!(cfg.proxmox.contribute.gpus, vec!["0000:21:00.0"]);
        assert!(matches!(cfg.credentials, crate::config::CredentialSource::SecretsFile(_)));
        assert_eq!(cfg.opening, off, "the opening is off unless join is told");

        // Told, it is written as given and loads on.
        let on = crate::opening::OpeningConfig {
            enabled: true,
            reach: Some(crate::opening::Reach::Forwarded),
            public_address: Some("193.137.26.160".into()),
            ..off
        };
        let config = config_file("https://api.omnuv.com", "n1", "AB:CD", "local", 8, 16_384, 200, gpus, &on).unwrap();
        std::fs::write(&path, &config).unwrap();
        let cfg = crate::config::load_agent(path.to_str().unwrap()).expect("join's opened file loads");
        assert_eq!(cfg.opening, on);
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
        assert!(s.contains("/sys/class/net/onvnat0"), "never checks the interface exists");
        // The bridge join builds is the one a buyer machine attaches to.
        assert_eq!(EGRESS_VNET, crate::instance::EGRESS_BRIDGE);
        assert!(s.contains("sleep 1"), "does not wait");
        assert!(!s.contains("--snat 1"), "Proxmox's snat flag is back: every SDN apply appends another SNAT copy");
        assert!(!s.contains("--gateway {EGRESS_GATEWAY} --snat"), "the subnet is created with the flag");
        assert!(s.contains("--snat 0"), "a subnet an earlier join made keeps the flag on");
        assert!(s.contains("systemctl restart onv-egress"), "the policy that carries the translation is never loaded");
        assert!(s.contains("--isolate-ports 1"), "tenants would see each other on the bridge");
        // The policy is written before the flag is turned off, and the copies
        // are removed only after: no moment without a translation, and no
        // reload left that could add one back.
        let load = s.find("systemctl restart onv-egress").expect("loaded");
        let off = s.find("--snat 0").expect("turned off");
        let strip = s.find("iptables -t nat -D POSTROUTING").expect("removed");
        assert!(load < off && off < strip, "out of order: load {load}, flag {off}, removal {strip}");
        // Two heredocs and a process substitution: parsed, not only grepped.
        let parsed = std::process::Command::new("bash").arg("-n").arg("-c").arg(&s).output().unwrap();
        assert!(parsed.status.success(), "{}", String::from_utf8_lossy(&parsed.stderr));
        assert!(s.contains(&format!("\n{}ONV_EGRESS_NFT\n", egress_nft())), "the table is not written whole");
    }

    /// The table join writes replaces itself in one transaction and carries
    /// one translation, the conntrack zone Proxmox's flag used to add, and the
    /// policy's drops.
    #[test]
    fn the_egress_table_replaces_itself_and_carries_the_translation() {
        let t = egress_nft();
        let lines: Vec<&str> = t.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()).collect();
        assert_eq!(&lines[..2], &["table inet onv_egress", "delete table inet onv_egress"],
                   "not replaced in one transaction: loading it twice would duplicate every rule");
        assert_eq!(t.matches("masquerade").count(), 1);
        assert!(t.contains(r#"meta nfproto ipv4 iifname "onvnat0" oifname != "onvnat0" masquerade"#), "{t}");
        assert!(t.contains("type nat hook postrouting priority srcnat"));
        assert!(t.contains(r#"meta nfproto ipv4 iifname "fwbr*" ct zone set 1"#));
        assert!(t.contains("type filter hook prerouting priority raw"));
        assert!(t.contains(r#"iifname "onvnat0" ip daddr @private drop"#), "a buyer machine could reach the provider LAN");
        assert!(t.contains(r#"oifname "onvnat0" ct state new drop"#));
        assert!(t.contains(r#"iifname "onvnat0" ip daddr 10.201.0.1 udp dport 53 accept"#));
        let u = egress_unit();
        assert!(u.contains("ExecStart=/usr/sbin/nft -f /etc/onv/egress.nft"));
        assert!(!u.contains("ExecStartPre"), "a delete before the load opens a moment with no policy");
    }

    /// **The handover against stand-ins for iptables**: a table of copies the
    /// flag left, beside rules that are not ours, run twice. Fixtures, not a
    /// host: `iptables` here edits a text file, and the omnuv repository's
    /// `tests/egress_nat/run.sh` runs the same rules against a real kernel.
    #[test]
    fn the_handover_removes_exactly_ours() {
        let dir = tempfile::tempdir().expect("tempdir");
        let d = dir.path();
        let bin = d.join("bin");
        std::fs::create_dir(&bin).unwrap();
        // `iptables-save -t <table>` prints the table's file; `iptables -t
        // <table> -D <rule>` removes the first line equal to `-A <rule>`.
        std::fs::write(bin.join("iptables-save"), "#!/bin/bash\ncat \"$STATE/$2\"\n").unwrap();
        std::fs::write(
            bin.join("iptables"),
            "#!/bin/bash\nt=$2; shift 3; want=\"-A $*\"\n\
             awk -v w=\"$want\" 'done || $0 != w {print; next} {done = 1}' \"$STATE/$t\" > \"$STATE/$t.new\"\n\
             cmp -s \"$STATE/$t\" \"$STATE/$t.new\" && { echo \"no such rule: $want\" >&2; exit 1; }\n\
             mv \"$STATE/$t.new\" \"$STATE/$t\"\n",
        )
        .unwrap();
        for f in ["iptables-save", "iptables"] {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(bin.join(f), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let ours = "-A POSTROUTING -s 10.201.0.0/24 -o vmbr0 -j SNAT --to-source 192.168.100.78";
        let ct = "-A PREROUTING -i fwbr+ -j CT --zone 1";
        let foreign = [
            "-A POSTROUTING -s 10.99.0.0/24 -o vmbr0 -j SNAT --to-source 192.168.100.78",
            "-A POSTROUTING -s 10.201.0.0/24 -o vmbr0 -j MASQUERADE",
        ];
        let mut nat = vec!["*nat".to_string()];
        nat.extend(std::iter::repeat_n(ours.to_string(), 5));
        nat.extend(foreign.iter().map(|s| s.to_string()));
        // A copy whose uplink address changed is ours too.
        nat.push("-A POSTROUTING -s 10.201.0.0/24 -o vmbr1 -j SNAT --to-source 10.0.0.9".into());
        nat.push("COMMIT".into());
        let mut raw = vec!["*raw".to_string()];
        raw.extend(std::iter::repeat_n(ct.to_string(), 4));
        raw.push("-A PREROUTING -i fwbr9100i0 -j CT --zone 2".into());
        raw.push("COMMIT".into());

        let run = |sdn: &str, nat: &[String], raw: &[String]| -> (std::process::Output, String, String) {
            std::fs::write(d.join("nat"), nat.join("\n") + "\n").unwrap();
            std::fs::write(d.join("raw"), raw.join("\n") + "\n").unwrap();
            std::fs::write(d.join("sdn"), sdn).unwrap();
            let out = std::process::Command::new("bash")
                .arg("-c")
                .arg(format!("set -e\nsdn={}\n{}", d.join("sdn").display(), egress_handover()))
                .env("STATE", d)
                .env("PATH", format!("{}:{}", bin.display(), std::env::var("PATH").unwrap_or_default()))
                .output()
                .unwrap();
            (out, std::fs::read_to_string(d.join("nat")).unwrap(), std::fs::read_to_string(d.join("raw")).unwrap())
        };

        let off = "auto onvnat0\niface onvnat0\n\taddress 10.201.0.1/24\n";
        let (out, n, r) = run(off, &nat, &raw);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert!(!n.contains("-s 10.201.0.0/24 -o vmbr0 -j SNAT") && !n.contains("--to-source 10.0.0.9"), "copies left:\n{n}");
        for f in foreign {
            assert!(n.contains(f), "removed a rule that is not ours: {f}\n{n}");
        }
        assert!(!r.lines().any(|l| l == ct), "CT copies left with no stanza generating it:\n{r}");
        assert!(r.contains("-A PREROUTING -i fwbr9100i0 -j CT --zone 2"), "another raw rule was removed");

        // A second run over what the first left changes nothing.
        let n2: Vec<String> = n.lines().map(str::to_string).collect();
        let r2: Vec<String> = r.lines().map(str::to_string).collect();
        let (out, n3, r3) = run(off, &n2, &r2);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert_eq!((n3.trim(), r3.trim()), (n.trim(), r.trim()));

        // Another stanza still generating the CT rule keeps one copy.
        let other = format!("{off}auto other0\niface other0\n\tpost-up iptables -t raw -I PREROUTING -i fwbr+ -j CT --zone 1\n");
        let (out, _, r) = run(&other, &nat, &raw);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(r.lines().filter(|l| *l == ct).count(), 1, "{r}");
    }

    /// **The host timer's credential, as `join` writes it, is the one the
    /// timer reads** (A3): its own token's id and secret, quoted so no
    /// character ends them, and no Core credential.
    #[test]
    fn the_host_timers_credential_reads_back_as_its_token() {
        let dir = tempfile::tempdir().unwrap();
        let body = lease_secrets_file("pve-\"LEASE\"-SEKRET");
        std::fs::write(dir.path().join(onv_agent_lib::lease_token::CREDENTIAL), &body).unwrap();
        let token = onv_agent_lib::lease_token::read_token(Some(dir.path())).expect("join's file is refused by the timer");
        assert_eq!(token.id, "onv@pve!lease");
        assert_eq!(token.secret.expose(), "pve-\"LEASE\"-SEKRET");
        assert!(!body.contains("coreToken"), "{body}");
    }

    /// **The host timer's token can stop a buyer's machine and nothing else**:
    /// its role holds the reads before a stop and the stop, and its one grant
    /// is on the buyers' pool, to its own token, never to the user or the
    /// agent's token.
    #[test]
    fn the_host_timers_token_holds_a_stop_on_the_buyers_pool_alone() {
        let role = lease_role_script();
        assert!(role.contains("-privs VM.Audit,VM.PowerMgmt"), "{role}");
        assert_eq!(role.matches("-privs ").count(), 2, "{role}");
        let grant = lease_grant_script();
        assert_eq!(grant, "pveum acl modify /pool/onv-buyers -token 'onv@pve!lease' -role OnvLease");
        // Privilege separation: what the user holds there covers the role.
        for p in onv_agent_lib::lease_token::PRIVILEGES {
            assert!(ROLE_PRIVS.split(',').any(|q| q == p), "onv@pve lacks {p}, so the token would too");
        }
    }
}
