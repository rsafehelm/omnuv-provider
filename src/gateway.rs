//! The provider's overlay gateway VM.
//!
//! # Why this is a VM and not a package on the host
//!
//! The overlay client brings up a WireGuard interface and writes routing table
//! entries. On a Proxmox host the management address and the default route
//! share one bridge, so a route covering the management range — or a botched
//! default route — makes the hypervisor unreachable and strands every guest on
//! it behind an administratively dead node. Recovery then needs IPMI or
//! physical access.
//!
//! That is not a risk to be managed carefully. It is a component that must not
//! be installed there at all. So the peer lives in a guest, the host's own
//! networking is never touched, and a gateway that misconfigures its routes can
//! only hurt its own namespace.
//!
//! # One per buyer network
//!
//! A gateway serves one network: it sits on that network's own segment here
//! (see `sdn`), holds that network's key, and answers that network's names.
//! The agent creates the segment before the first gateway on it and removes
//! it with the last, so a tenant's machines never share a wire with another's.
//!
//! # What it carries
//!
//! Buyer traffic, and nothing else. The agent reaches Core over TLS on the
//! provider's own path, so a gateway that is broken, rebuilding, or absent
//! never makes a healthy provider look offline — it still heartbeats, still
//! reports inventory, still serves inference, and can be told to rebuild this.

use omnuv_protocol::{GatewaySpec, GatewayState, GatewayStatus, Lifecycle};

use crate::audit;
use crate::proxmox;

/// An empty form body, for POSTs that carry no parameters.
const NO_FORM: &[(String, String)] = &[];

pub const TAG: &str = "omnuv-gateway";

/// The gateway's root disk.
///
/// The template's own is 3.5 GB, of which 2.3 GB is the root partition, and a
/// gateway then installs the overlay client and a resolver on top. Both of
/// this lab's gateways reached 100% and cloud-init stopped running entirely —
/// `[Errno 28] No space left on device` in `init-local` — which silently
/// froze their configuration at whatever it was last time there was room.
/// A full disk on the one machine that carries a buyer's traffic is not worth
/// saving 6 GB over.
const DISK_GIB: u32 = 8;

/// Prefixes a gateway must never advertise, whatever it is told.
///
/// Core checks this too, but the agent is the last place the decision can be
/// stopped before a route is actually written, and it is the side that would
/// suffer. A default route is included: advertising one would pull a
/// provider's own traffic onto the overlay.
const NEVER_ADVERTISE: &[&str] = &["0.0.0.0/0", "192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"];

/// Refuses a slice that is wider than a marketplace project network, or that
/// covers space the provider needs for itself.
fn advertisable(cidr: &str) -> Result<(), String> {
    if NEVER_ADVERTISE.contains(&cidr) {
        return Err(format!("{cidr} must never be advertised"));
    }
    let Some((_, len)) = cidr.split_once('/') else {
        return Err(format!("{cidr} is not a prefix"));
    };
    let Ok(len) = len.parse::<u8>() else {
        return Err(format!("{cidr} has no prefix length"));
    };
    // A project slice is a /24. Anything shorter is a supernet, and a supernet
    // is how a gateway ends up carrying traffic that is not its buyer's.
    if len < 24 {
        return Err(format!("{cidr} is wider than a project slice"));
    }
    if !cidr.starts_with("10.200.") && !cidr.starts_with("10.20") {
        return Err(format!("{cidr} is outside the marketplace pool"));
    }
    Ok(())
}

/// The slice a gateway advertises must be the one its own address is in:
/// `10.200.7.1/24` advertises `10.200.7.0/24` and nothing else. The negative
/// guard above stops the dangerous prefixes; this is the positive half.
fn holds_its_slice(slice_address: &str, advertise_cidr: &str) -> bool {
    fn parse(s: &str) -> Option<(u32, u8)> {
        let (ip, len) = s.split_once('/')?;
        let ip: std::net::Ipv4Addr = ip.parse().ok()?;
        let len: u8 = len.parse().ok()?;
        (len <= 32).then_some((u32::from(ip), len))
    }
    let (Some((a, alen)), Some((c, clen))) = (parse(slice_address), parse(advertise_cidr)) else {
        return false;
    };
    let mask = if clen == 0 { 0 } else { u32::MAX << (32 - clen) };
    alen == clen && a & mask == c & mask && c & !mask == 0
}

/// The gateway's cloud-init.
///
/// `netbird up` is idempotent, so a rebuilt gateway re-enrols with the same key
/// and rejoins the same buyer's network without anyone intervening.
const FENCE_RULES: &str = r#"# NetBird puts overlay routes in table 7120, but its own ip rule for that
# table (pref 110) sits after the main table (pref 105, which only
# suppresses the default route). So the /24 this gateway holds on the bridge
# shadows the remote /32s and forwarded buyer traffic never reaches the
# overlay — it is redirected back onto the bridge and dropped. Consult the
# overlay table first for the whole marketplace pool: a remote machine's /32
# wins, a local address misses table 7120 and falls back to the on-link /24.
# Table 7120 is NetBird 0.78.1's default; del-then-add keeps it single per boot.
ip rule del to 10.200.0.0/13 lookup 7120 pref 100 2>/dev/null || true
ip rule add to 10.200.0.0/13 lookup 7120 pref 100
# The gateway forwards buyer traffic into the overlay and nowhere else. It
# has a default route out net0 onto the provider's LAN, so without this a
# buyer that routed the LAN through .1 would be forwarded there. Likewise
# the gateway itself answers the bridge only on its marketplace address.
# Idempotent, and runs before the overlay client adds its own rules.
iptables -C FORWARD -i $DEV ! -d 10.200.0.0/13 -j DROP 2>/dev/null || iptables -I FORWARD -i $DEV ! -d 10.200.0.0/13 -j DROP
iptables -C INPUT -i $DEV ! -d 10.200.0.0/13 -j DROP 2>/dev/null || iptables -I INPUT -i $DEV ! -d 10.200.0.0/13 -j DROP
# A member's own device reaches buyer machines through here too, from an
# overlay address the machines have no route back to — their default route
# is the internet, which drops it. Rewrite only such sources to this
# gateway's marketplace address; buyer-to-buyer traffic keeps its source.
# Replies then come back on the bridge as part of an established flow,
# which the DROP above must let through.
iptables -t nat -C POSTROUTING -o $DEV ! -s 10.200.0.0/13 -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING -o $DEV ! -s 10.200.0.0/13 -j MASQUERADE
iptables -C FORWARD -i $DEV -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I FORWARD -i $DEV -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# And outbound: traffic from the bridge bound for the overlay leaves with
# this gateway's own overlay address as its source. The far gateway admits
# traffic per peer, and a bridge address is no peer; it masquerades onto
# its bridge in turn (the rule above), so neither machine needs a route
# back to the overlay. Across providers a machine sees its peer's gateway
# rather than the peer — the v0.1 masquerade trade the design allows.
iptables -t nat -C POSTROUTING -o wt0 -s 10.200.0.0/13 -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING -o wt0 -s 10.200.0.0/13 -j MASQUERADE
# The same boundary from the overlay side. A peer's client only sends what
# its routes allow, but a member owns their device and could send anything
# with the same key; this gateway forwards overlay traffic onto the bridge
# and nowhere else, and answers it only on its marketplace address. In
# mangle, which runs before the filter chain the overlay client fills with
# its own accept rules at start-up, so ordering cannot undo it.
iptables -t mangle -C FORWARD -i wt0 ! -d 10.200.0.0/13 -j DROP 2>/dev/null || iptables -t mangle -I FORWARD -i wt0 ! -d 10.200.0.0/13 -j DROP
iptables -t mangle -C INPUT -i wt0 ! -d 10.200.0.0/13 -j DROP 2>/dev/null || iptables -t mangle -I INPUT -i wt0 ! -d 10.200.0.0/13 -j DROP
"#;

/// The forwarding rules, as a script the gateway re-runs.
///
/// They cannot be applied once. The overlay client owns the firewall too, and
/// when its routing changes it rebuilds the tables — taking with it the
/// masquerade a member's device needs for a reply path, which fails silently
/// and looks to a buyer exactly like the machine being down. Every line is
/// `-C || -I`, so re-running it every minute costs nothing.
fn fence_script(mac: &str) -> String {
    format!(
        "#!/bin/sh\n\
         # Managed by omnuv-provider; re-run on a timer. Do not edit.\n\
         {resolve}\n\
         [ -n \"$DEV\" ] || exit 0\n\
         sysctl -qw net.ipv4.ip_forward=1\n\
{rules}",
        resolve = crate::instance::resolve_dev(mac),
        rules = FENCE_RULES,
    )
}

fn cloud_init(spec: &GatewaySpec) -> String {
    let keys: String = spec
        .ssh_keys
        .iter()
        .map(|k| format!("      - {k}\n"))
        .collect();
    // The gateway's own place on the marketplace bridge, and the forwarding
    // that makes it a gateway rather than merely a machine with two interfaces.
    //
    // Which prefixes it carries is decided by the marketplace and configured on
    // the overlay control plane, not here: the peer needs an address, a route
    // into the bridge, and `ip_forward`. `advertise_cidr` is still checked
    // before any of this is written, because the agent is the last place a
    // forbidden prefix can be stopped before a route reaches a provider.
    let routes = match (&spec.slice_address, spec.advertise_cidr.as_deref()) {
        (Some(addr), Some(cidr)) if advertisable(cidr).is_ok() && holds_its_slice(addr, cidr) => format!(
            r#"  # This interface is the provider's isolated marketplace bridge. This
  # address is the next hop for every buyer machine here, and the bridge has no
  # uplink, so nothing on it can reach the provider's own network. One block
  # scalar, not flow entries: the MAC-resolution shell contains "$DEV", which
  # would close a `[ sh, -c, "..." ]` string and break the whole cloud-config.
  - |
    {resolve}
    ip link set dev $DEV up
    ip addr replace {addr} dev $DEV
    # Without forwarding the VM is not a gateway at all: buyer traffic arrives
    # from the overlay and would be dropped instead of forwarded onto the bridge.
    sysctl -w net.ipv4.ip_forward=1
    printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/99-omnuv.conf
    # Declarative copy so systemd-networkd owns the interface across reboots.
    printf '[Match]\nMACAddress={mac}\n\n[Network]\nAddress={addr}\nIPForward=yes\n' > /etc/systemd/network/10-omnuv.network
    systemctl enable systemd-networkd 2>/dev/null || true
    # Install the fence and put it on a timer. Here, in bootcmd, rather than in
    # write_files: that module runs on a machine's first boot only, so a
    # gateway that already exists would never receive it, and the whole point
    # is that existing gateways converge.
    #
    # The timer is not for drift of its own making. The overlay client owns the
    # firewall too, and when its routing changes it rebuilds the tables —
    # taking these with them, which silently costs every member device its
    # reply path, because a buyer machine has no route back to an overlay
    # address. Applying them once is not enough; they have to be true
    # continuously. Every line is check-then-insert, so re-running is free.
    echo {fence} | base64 -d > /usr/local/sbin/omnuv-gateway-fence
    chmod 0755 /usr/local/sbin/omnuv-gateway-fence
    printf '[Unit]\nDescription=Re-assert the Omnuv gateway forwarding rules\nAfter=network.target\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/omnuv-gateway-fence\n' > /etc/systemd/system/omnuv-gateway-fence.service
    printf '[Unit]\nDescription=Keep the Omnuv gateway forwarding rules true\n[Timer]\nOnBootSec=20s\nOnUnitActiveSec=60s\nAccuracySec=5s\n[Install]\nWantedBy=timers.target\n' > /etc/systemd/system/omnuv-gateway-fence.timer
    # The gateway says, out loud and continuously, whether it can actually reach
    # anything — and *how*. `--detail` is what carries `Connection type: P2P`
    # or `Relayed` per peer, which is the difference between cross-provider
    # traffic going straight over the LAN and going through the marketplace's
    # own host at every byte.
    #
    # A gateway that exists and is running can be unable to register with the
    # overlay, and nothing above it can tell: the VM is there, the interface is
    # there, the config is there. That state lasted hours and every published
    # endpoint answered 502 while the machines behind them were healthy.
    #
    # Written to a file rather than answered on a port, because the agent reads
    # it with VM.GuestAgent.FileRead — the same privilege the Workload Agent's
    # report needs, and far short of the unrestricted exec that running a
    # command in here would require. /run is tmpfs, so a stale file cannot
    # outlive a reboot and pretend to be current.
    printf '#!/bin/sh\nmkdir -p /run/omnuv\n( netbird status --detail; echo ---; ip -br addr; echo ---; ip -br route; echo ---; netbird status --json ) > /run/omnuv/gateway-status.txt.new 2>&1\nmv /run/omnuv/gateway-status.txt.new /run/omnuv/gateway-status.txt\n' > /usr/local/sbin/omnuv-gateway-selfcheck
    chmod 0755 /usr/local/sbin/omnuv-gateway-selfcheck
    printf '[Unit]\nDescription=Report what the Omnuv gateway can actually reach\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/omnuv-gateway-selfcheck\n' > /etc/systemd/system/omnuv-gateway-selfcheck.service
    printf '[Unit]\nDescription=Keep the Omnuv gateway self-check current\n[Timer]\nOnBootSec=15s\nOnUnitActiveSec=30s\nAccuracySec=5s\n[Install]\nWantedBy=timers.target\n' > /etc/systemd/system/omnuv-gateway-selfcheck.timer
    systemctl daemon-reload
    systemctl enable --now --no-block omnuv-gateway-fence.timer 2>/dev/null || true
    systemctl enable --now --no-block omnuv-gateway-selfcheck.timer 2>/dev/null || true
    /usr/local/sbin/omnuv-gateway-fence || true
    /usr/local/sbin/omnuv-gateway-selfcheck || true
"#,
            addr = addr,
            mac = crate::instance::marketplace_mac(&spec.id),
            resolve = crate::instance::resolve_dev(&crate::instance::marketplace_mac(&spec.id)),
            fence = {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD
                    .encode(fence_script(&crate::instance::marketplace_mac(&spec.id)))
            },
        ),
        _ => String::new(),
    };

    // The project's private resolver. dnsmasq listens only on the slice
    // address, is authoritative for `internal` and never forwards, and reads
    // its records from a directory it watches — so the agent keeps the map
    // current with a guest-agent file write and needs no exec privilege. The
    // seed written here is the map at build time; the agent replaces it on
    // every reconcile.
    let dns = match &spec.slice_address {
        Some(addr) => {
            let ip = addr.split('/').next().unwrap_or(addr);
            let seed: String = hosts_file(&spec.dns_records)
                .lines()
                .map(|l| format!("      {l}\n"))
                .collect();
            format!(
                "  - path: /etc/dnsmasq.d/omnuv.conf
    content: |
      bind-dynamic
      listen-address={ip}
      no-resolv
      local=/internal/
      hostsdir=/etc/omnuv/hosts.d
  - path: {DNS_HOSTS_PATH}
    content: |
{seed}"
            )
        }
        None => String::new(),
    };

    format!(
        "#cloud-config
# Omnuv marketplace overlay gateway. Managed by omnuv-provider; do not edit.
#
# This VM is one buyer network's overlay peer on this provider. The hypervisor
# never runs the overlay client, because a WireGuard interface writing routes
# there could take the host and every guest on it off the network.
hostname: omnuv-gw-{short}
manage_etc_hosts: true
users:
  - default
  - name: omnuv
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
{keys}ssh_authorized_keys:
{keys}packages:
  - qemu-guest-agent
  - dnsmasq
write_files:
  - path: /etc/omnuv/gateway.env
    permissions: '0600'
    content: |
      OMNUV_GATEWAY_ID={id}
      NB_MANAGEMENT_URL={mgmt}
{dns}# bootcmd runs in the init stage, before the config stage where apt runs. A
# slow or absent apt must not delay the gateway's address, forwarding or the
# overlay: they are configured here and depend on nothing installed later.
bootcmd:
  # --no-block: in the init stage a start job for a unit ordered after
  # basic.target cannot complete until this very stage finishes; waiting on
  # it is a deadlock that looks like a boot stuck at cloud-init-network.
  - [ sh, -c, \"systemctl enable --now --no-block qemu-guest-agent 2>/dev/null || true\" ]
{routes}runcmd:
  - [ mkdir, -p, /etc/omnuv ]
  # runcmd is the final stage, after packages: both are installed by then.
  - [ sh, -c, \"systemctl enable --now qemu-guest-agent || true\" ]
  - [ sh, -c, \"systemctl enable --now dnsmasq || true\" ]
  # 150 MB of package lists on a small disk, for packages already installed.
  - [ sh, -c, \"apt-get clean || true\" ]
  # Enrol against the marketplace control plane over the LAN. The curl install
  # is time-bounded so it can never hang the boot.
  - [ sh, -c, \"command -v netbird >/dev/null || timeout 60 bash -c 'curl -fsSL https://pkgs.netbird.io/install.sh | sh' || true\" ]
  - [ sh, -c, \"systemctl enable --now netbird || true\" ]
  - [ sh, -c, \"netbird up --management-url {mgmt} --setup-key {key} --hostname omnuv-gw-{short}\" ]",
        keys = if keys.is_empty() { "      []\n".to_string() } else { keys },
        id = spec.id,
        mgmt = spec.management_url,
        key = spec.setup_key,
        short = &spec.id[..spec.id.len().min(8)],
        routes = routes,
        dns = dns,
    )
}

impl proxmox::Client {
    /// Brings the provider's gateway to the state Core asked for.
    ///
    /// Idempotent by construction: an existing gateway is started or stopped to
    /// match, and only a missing one is built. Rebuilding is therefore just
    /// deleting and letting the next pass converge.
    pub async fn ensure_gateway(
        &self,
        node: &str,
        template_vmid: u32,
        storage: &str,
        snippet_dir: &str,
        spec: &GatewaySpec,
    ) -> anyhow::Result<GatewayStatus> {
        if let Some(cidr) = &spec.advertise_cidr {
            // Refuse rather than build something that would advertise it. This
            // is the last point before a route is written on the provider:
            // never a forbidden prefix, and only the slice this gateway's own
            // address is in.
            let refused = match advertisable(cidr) {
                Err(why) => Some(why),
                Ok(()) => spec
                    .slice_address
                    .as_deref()
                    .filter(|addr| !holds_its_slice(addr, cidr))
                    .map(|addr| format!("{cidr} is not the slice {addr} is in")),
            };
            if let Some(why) = refused {
                return Ok(GatewayStatus {
                    id: spec.id.clone(),
                    state: GatewayState::Error,
                    retryable: None,
                    waiting_on: None,
                    local_id: None,
                    overlay_address: None,
                    adapters: Vec::new(),
                    diagnostics: None,
                    message: Some(why),
                });
            }
        }

        let tag = short_tag(&spec.id);
        if let Some(vm) = self.find_tagged_vm(node, TAG, &tag).await? {
            let mut running = vm.status.as_deref() == Some("running");
            if !running && spec.lifecycle == Lifecycle::Running {
                let upid: String = self
                    .post_form(
                        &format!("/nodes/{node}/qemu/{}/status/start", vm.vmid),
                        NO_FORM,
                    )
                    .await?;
                self.wait_task(node, &upid).await?;
                running = true;
            }
            if running && spec.lifecycle == Lifecycle::Stopped {
                let upid: String = self
                    .post_form(
                        &format!("/nodes/{node}/qemu/{}/status/shutdown", vm.vmid),
                        NO_FORM,
                    )
                    .await?;
                self.wait_task(node, &upid).await?;
                running = false;
            }

            // The generated cloud-init, brought up to date. A gateway built
            // before a generator changed would otherwise keep the old
            // configuration for its whole life, and the fix would be a human
            // editing iptables on a guest — which is how it went once, and
            // exactly what the reconciliation model exists to prevent. The
            // gateway is marketplace-owned, holds no state and its loss is
            // survivable (5.15), so the agent applies it: rewrite, regenerate
            // the drive, reboot. bootcmd runs on every boot, so the reboot is
            // what makes it true.
            let mut refreshed = false;
            if running && spec.lifecycle == Lifecycle::Running {
                match self
                    .sync_cloud_init(node, vm.vmid, snippet_dir, &format!("omnuv-gw-{tag}.yaml"), &cloud_init(spec))
                    .await
                {
                    Ok(true) => {
                        let upid: String = self
                            .post_form(&format!("/nodes/{node}/qemu/{}/status/reboot", vm.vmid), NO_FORM)
                            .await?;
                        self.wait_task(node, &upid).await?;
                        audit::record("gateway.refresh", "agent", &spec.id, "ok", Some(&vm.vmid.to_string()));
                        refreshed = true;
                    }
                    Ok(false) => {}
                    Err(e) => eprintln!("gateway {}: cloud-init not refreshed: {e}", spec.id),
                }
            }

            // The guest answering is the liveness signal, and only that. The
            // address it hands back is the gateway's LAN address; calling that
            // the overlay address is the bug this replaced.
            let reachable = if running { self.guest_ipv4(node, vm.vmid).await } else { None };
            let overlay = if running { self.gateway_overlay(node, vm.vmid).await } else { None };
            let addr = overlay.clone();

            // Keep the resolver's map current. dnsmasq watches the directory,
            // so replacing the file is the whole update; the write is idempotent
            // and cheap, and needs only the pool-scoped file-write privilege.
            if reachable.is_some()
                && let Err(e) = self
                    .guest_file_write(node, vm.vmid, DNS_HOSTS_PATH, &hosts_file(&spec.dns_records))
                    .await
            {
                eprintln!("gateway {}: private DNS map not written: {e}", spec.id);
            }

            return Ok(GatewayStatus {
                id: spec.id.clone(),
                // READY means the guest is answering, not merely that a VM
                // exists: a gateway that never booted is not carrying traffic.
                // READY still means the guest is answering, not that it has an
                // overlay address: a gateway whose overlay client is still
                // enrolling is up and reachable, and reporting it Offline
                // because one field is late would be a regression.
                state: match (running, reachable.is_some() && !refreshed) {
                    (true, true) => GatewayState::Ready,
                    (true, false) => GatewayState::Deploying,
                    _ => GatewayState::Offline,
                },
                retryable: None,
                waiting_on: match (running, reachable.is_some(), overlay.is_some()) {
                    (true, true, false) => Some("the overlay client to enrol".to_string()),
                    (true, false, _) => Some("first boot to finish".to_string()),
                    (false, _, _) => Some("the gateway to start".to_string()),
                    _ => None,
                },
                local_id: Some(vm.vmid.to_string()),
                overlay_address: addr,
                adapters: self.observed_adapters(node, vm.vmid, reachable.as_deref()).await,
                diagnostics: Some(
                    self.diagnose(node, vm.vmid, reachable.is_some(), Some(reachable.is_some())).await,
                ),
                message: refreshed.then(|| "configuration refreshed; rebooting".to_string()),
            });
        }

        if spec.lifecycle == Lifecycle::Deleted {
            return Ok(GatewayStatus {
                id: spec.id.clone(),
                state: GatewayState::Offline,
                retryable: None,
                waiting_on: None,
                local_id: None,
                overlay_address: None,
                adapters: Vec::new(),
                diagnostics: None,
                message: Some("not present".into()),
            });
        }

        // The network's own segment on this provider, before anything sits
        // on it. Idempotent, so a gateway rebuilt after a crash finds it.
        let bridge = crate::sdn::vnet_for(&spec.network_id);
        self.ensure_vnet(node, &bridge).await?;

        let file = format!("omnuv-gw-{tag}.yaml");
        std::fs::write(format!("{snippet_dir}/{file}"), cloud_init(spec))
            .map_err(|e| anyhow::anyhow!("writing the gateway's cloud-init: {e}"))?;

        let vmid: u32 = self.get_json::<String>("/cluster/nextid").await?.parse()?;
        let upid: String = self
            .post_form(
                &format!("/nodes/{node}/qemu/{template_vmid}/clone"),
                &[
                    ("newid".to_string(), vmid.to_string()),
                    ("name".to_string(), format!("omnuv-gw-{tag}")),
                    ("full".to_string(), "1".to_string()),
                    ("storage".to_string(), storage.to_string()),
                    // Into the pool that carries the file-write grant; a
                    // gateway is the only kind of VM that ever goes there.
                    ("pool".to_string(), GATEWAY_POOL.to_string()),
                ],
            )
            .await?;
        self.wait_task(node, &upid).await?;

        // Room to run. Cloud-init grows the partition on the next boot, which
        // is this machine's first.
        self.put_form::<serde_json::Value>(
            &format!("/nodes/{node}/qemu/{vmid}/resize"),
            &[("disk".to_string(), "scsi0".to_string()), ("size".to_string(), format!("{DISK_GIB}G"))],
        )
        .await?;

        self.post_form::<serde_json::Value>(
            &format!("/nodes/{node}/qemu/{vmid}/config"),
            &[
                // A gateway forwards packets; it does not compute. One core and
                // a gigabyte is the whole cost of the overlay to a provider.
                ("cores".to_string(), "1".to_string()),
                ("memory".to_string(), "1024".to_string()),
                ("agent".to_string(), "enabled=1".into()),
                ("ipconfig0".to_string(), "ip=dhcp".into()),
                // net0 reaches the overlay control plane over the provider's
                // own network; net1 is the network's isolated segment, where
                // its machines live. The gateway is the only thing that sees
                // both, which is the entire point of it.
                (
                    "net1".to_string(),
                    format!("virtio={},bridge={bridge}", crate::instance::marketplace_mac(&spec.id)),
                ),
                ("cicustom".to_string(), format!("user=omnuv-snippets:snippets/{file}")),
                ("tags".to_string(), format!("{TAG};{tag}")),
                // The gateway must come back with the host, or a reboot leaves
                // the provider silently off the overlay.
                //
                // `onboot` only; not `startup`. Boot *order* is a node-level
                // setting requiring Sys.Modify on `/`, which the agent's token
                // deliberately does not have — the agent manages guests, not
                // the host. Ordering is a nicety; widening the token to get it
                // would be a real cost.
                ("onboot".to_string(), "1".to_string()),
                (
                    "description".into(),
                    format!(
                        "Omnuv overlay gateway {}\nOne buyer network's overlay peer on this \
                         provider; the host never runs it.\nManaged by omnuv-provider. Do not edit.",
                        spec.id
                    ),
                ),
            ],
        )
        .await?;

        let upid: String = self
            .post_form(&format!("/nodes/{node}/qemu/{vmid}/status/start"), NO_FORM)
            .await?;
        self.wait_task(node, &upid).await?;

        audit::record("gateway.create", "core", &spec.id, "ok", Some(&vmid.to_string()));
        Ok(GatewayStatus {
            id: spec.id.clone(),
            state: GatewayState::Deploying,
            retryable: None,
            waiting_on: None,
            local_id: Some(vmid.to_string()),
            overlay_address: None,
            adapters: Vec::new(),
            diagnostics: None,
            message: Some(format!("gateway vm {vmid} created and started")),
        })
    }

    /// Removes gateways on this node that Core no longer knows about: a VM
    /// carrying this agent's gateway tag whose id is in no desired spec,
    /// running or deleted. A protocol upgrade or a Core restore leaves such a
    /// VM behind, holding a key nothing distributes any more and capacity no
    /// allocation pays for. Nothing without the tag is ever touched.
    pub async fn reap_stale_gateways(&self, node: &str, desired: &[GatewaySpec]) -> anyhow::Result<usize> {
        let vms: Vec<crate::worker::VmRef> = self.get_json(&format!("/nodes/{node}/qemu")).await?;
        let keep: Vec<String> = desired.iter().map(|s| short_tag(&s.id)).collect();
        let mut reaped = 0;
        for vm in vms {
            let Some(tags) = vm.tags.as_deref() else { continue };
            if !tags.split(';').any(|t| t == TAG) || tags.split(';').any(|t| keep.iter().any(|k| k == t)) {
                continue;
            }
            if vm.status.as_deref() == Some("running") {
                let upid: String =
                    self.post_form(&format!("/nodes/{node}/qemu/{}/status/stop", vm.vmid), NO_FORM).await?;
                self.wait_task(node, &upid).await?;
            }
            let upid: String = self.delete_task(&format!("/nodes/{node}/qemu/{}", vm.vmid)).await?;
            self.wait_task(node, &upid).await?;
            audit::record("gateway.reap", "agent", tags, "ok", Some(&vm.vmid.to_string()));
            reaped += 1;
        }
        Ok(reaped)
    }

    /// Destroys the gateway, and with it the network's segment here: Core asks
    /// for this only once the network has no machine left on this provider.
    /// Rebuilding is this plus the next reconcile pass — there is no separate
    /// repair path, because a gateway holds no state worth keeping.
    pub async fn delete_gateway(&self, node: &str, gateway_id: &str, network_id: &str) -> anyhow::Result<()> {
        if let Some(vm) = self.find_tagged_vm(node, TAG, &short_tag(gateway_id)).await? {
            if vm.status.as_deref() == Some("running") {
                let upid: String = self
                    .post_form(&format!("/nodes/{node}/qemu/{}/status/stop", vm.vmid), NO_FORM)
                    .await?;
                self.wait_task(node, &upid).await?;
            }
            let upid: String = self.delete_task(&format!("/nodes/{node}/qemu/{}", vm.vmid)).await?;
            self.wait_task(node, &upid).await?;
            audit::record("gateway.delete", "core", gateway_id, "ok", Some(&vm.vmid.to_string()));
        }
        self.delete_vnet(node, &crate::sdn::vnet_for(network_id)).await
    }
}

/// The Proxmox pool gateways are cloned into. Bootstrap grants
/// `VM.GuestAgent.FileWrite` on this pool and nowhere else, so the agent can
/// write the resolver's map into its own gateway and into nothing else on the
/// host — not a buyer VM, not the provider's own machines.
pub(crate) const GATEWAY_POOL: &str = "omnuv";

/// Where the gateway's resolver reads the project's names. dnsmasq watches
/// the directory (`hostsdir`), so replacing this file is the whole update.
const DNS_HOSTS_PATH: &str = "/etc/omnuv/hosts.d/project";

/// The resolver's hosts file: one `address name` line per record, sorted so
/// the same map always produces the same bytes.
fn hosts_file(records: &[omnuv_protocol::DnsRecord]) -> String {
    let mut lines: Vec<String> =
        records.iter().map(|r| format!("{} {}", r.address, r.name)).collect();
    lines.sort();
    let mut out = String::from("# Managed by omnuv-provider; the marketplace owns these names.\n");
    for l in lines {
        out.push_str(&l);
        out.push('\n');
    }
    out
}

/// A tag Proxmox accepts: lowercase alphanumerics only, and short enough to
/// read in the UI.
fn short_tag(id: &str) -> String {
    let s: String = id.chars().filter(|c| c.is_ascii_alphanumeric()).take(8).collect();
    format!("gw-{}", s.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The assertion the whole phase exists for. A gateway that advertised any
    /// of these would pull the provider's own traffic — including the
    /// hypervisor's — onto the overlay.
    #[test]
    fn refuses_to_advertise_anything_wider_than_a_slice() {
        for bad in ["0.0.0.0/0", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "10.200.0.0/13"] {
            assert!(advertisable(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn accepts_a_project_slice() {
        assert!(advertisable("10.200.1.0/24").is_ok());
        assert!(advertisable("10.200.99.0/24").is_ok());
    }

    /// Outside the marketplace pool is refused even at /24: a provider's own
    /// /24 is not ours to route.
    #[test]
    fn refuses_a_slice_outside_the_pool() {
        assert!(advertisable("192.168.100.0/24").is_err());
        assert!(advertisable("172.28.5.0/24").is_err());
    }

    /// A refused slice must not reach the cloud-init at all, or the gateway
    /// would be built ready to advertise it.
    #[test]
    fn a_refused_slice_is_not_written_into_cloud_init() {
        let spec = GatewaySpec {
            id: "abcdef12".into(),
            budget_secs: None,
            network_id: "c4d90fd2-be3d-4225-a4a6-265138a76e49".into(),
            lifecycle: Lifecycle::Running,
            management_url: "https://nb.example".into(),
            setup_key: "K".into(),
            slice_address: Some("10.200.7.1/24".into()),
            advertise_cidr: Some("0.0.0.0/0".into()),
            ssh_keys: vec![],
            dns_records: vec![],
        };
        // A refused advertise_cidr renders no routes block at all, so the
        // gateway is never built to forward for that slice.
        let ci = cloud_init(&spec);
        assert!(!ci.contains("0.0.0.0/0"));
        assert!(!ci.contains("ip_forward"));
    }

    #[test]
    fn a_slice_that_is_allowed_is_written() {
        let spec = GatewaySpec {
            id: "abcdef12".into(),
            budget_secs: None,
            network_id: "c4d90fd2-be3d-4225-a4a6-265138a76e49".into(),
            lifecycle: Lifecycle::Running,
            management_url: "https://nb.example".into(),
            setup_key: "K".into(),
            slice_address: Some("10.200.7.1/24".into()),
            advertise_cidr: Some("10.200.7.0/24".into()),
            ssh_keys: vec!["ssh-ed25519 AAAA test".into()],
            dns_records: vec![omnuv_protocol::DnsRecord {
                name: "gpu-2.internal".into(),
                address: "10.200.7.11".into(),
            }],
        };
        let ci = cloud_init(&spec);
        // The resolver listens on the slice address only, is authoritative for
        // `internal`, reads a watched directory, and is seeded with the map.
        assert!(ci.contains("listen-address=10.200.7.1\n"));
        assert!(ci.contains("hostsdir=/etc/omnuv/hosts.d"));
        assert!(ci.contains("10.200.7.11 gpu-2.internal"));
        // The rules ride as a script the gateway re-runs, so they are asserted
        // where they actually live rather than in the document that carries
        // them. The timer is what makes them true continuously: the overlay
        // client rebuilds the firewall when its routing changes, and applying
        // these once at boot loses them without a word.
        assert!(ci.contains("/usr/local/sbin/omnuv-gateway-fence"));
        assert!(ci.contains("omnuv-gateway-fence.timer"));
        assert!(ci.contains("OnUnitActiveSec=60s"));
        let fence = fence_script("02:09:a4:76:f8:ee");
        // The gateway must never be a path from the bridge to the provider's
        // LAN: forwarding and the gateway's own services are pool-only.
        assert!(fence.contains("iptables -I FORWARD -i $DEV ! -d 10.200.0.0/13 -j DROP"));
        assert!(fence.contains("iptables -I INPUT -i $DEV ! -d 10.200.0.0/13 -j DROP"));
        // Device traffic is rewritten to the gateway's address, buyer traffic
        // is not, and the reply path through the DROP is open.
        assert!(fence.contains("POSTROUTING -o $DEV ! -s 10.200.0.0/13 -j MASQUERADE"));
        // And bridge traffic leaves for the overlay as this gateway: the far
        // side admits per peer, so a machine's own address would be dropped.
        assert!(fence.contains("POSTROUTING -o wt0 -s 10.200.0.0/13 -j MASQUERADE"));
        assert!(fence.contains("-I FORWARD -i $DEV -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"));
        assert!(fence.find("-j DROP").unwrap() < fence.find("ESTABLISHED,RELATED -j ACCEPT").unwrap());
        // And the overlay side is fenced the same way, ahead of the client's
        // own chains.
        assert!(fence.contains("iptables -t mangle -I FORWARD -i wt0 ! -d 10.200.0.0/13 -j DROP"));
        assert!(fence.contains("iptables -t mangle -I INPUT -i wt0 ! -d 10.200.0.0/13 -j DROP"));
        // Every rule is check-then-insert, which is what lets a timer re-run it.
        for line in fence.lines().filter(|l| l.trim_start().starts_with("iptables ")) {
            assert!(line.contains(" -C ") && line.contains("||"), "not idempotent: {line}");
        }
        // The slice address and forwarding land in bootcmd, before the config
        // stage where apt (which needs internet this VM may not have) runs.
        assert!(ci.contains("10.200.7.1/24"));
        assert!(ci.contains("net.ipv4.ip_forward=1"));
        assert!(ci.contains("bootcmd:"));
        assert!(ci.contains("netbird up"));
        assert!(ci.contains("ssh-ed25519 AAAA test"));
        // Must parse: the slice-address shell uses `[ -n "$DEV" ]`, which only
        // survives inside a block scalar. As a flow scalar it broke the config.
        let doc: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&ci).expect("gateway cloud-init must be valid YAML");
        assert!(doc.get("bootcmd").is_some_and(|b| b.is_sequence()));
        assert!(doc.get("runcmd").is_some_and(|r| r.is_sequence()));
    }

    /// 5.8, the positive half: the slice a gateway advertises is exactly the
    /// one its own address is in — never a neighbour's, never a supernet.
    #[test]
    fn a_gateway_advertises_exactly_the_slice_it_holds() {
        assert!(holds_its_slice("10.200.7.1/24", "10.200.7.0/24"));
        assert!(holds_its_slice("10.200.99.1/24", "10.200.99.0/24"));
        assert!(!holds_its_slice("10.200.7.1/24", "10.200.8.0/24"), "a neighbour's slice");
        assert!(!holds_its_slice("10.200.7.1/24", "10.200.0.0/16"), "a supernet");
        assert!(!holds_its_slice("10.200.7.1/24", "10.200.7.1/24"), "not a prefix");
        assert!(!holds_its_slice("10.200.7.1/24", "10.200.7.0/25"), "a different length");
        assert!(!holds_its_slice("10.200.7.1/24", "nonsense"));
        // A mismatch never reaches cloud-init: no forwarding is written.
        let spec = GatewaySpec {
            id: "abcdef12".into(),
            budget_secs: None,
            network_id: "c4d90fd2-be3d-4225-a4a6-265138a76e49".into(),
            lifecycle: Lifecycle::Running,
            management_url: "https://nb.example".into(),
            setup_key: "K".into(),
            slice_address: Some("10.200.7.1/24".into()),
            advertise_cidr: Some("10.200.8.0/24".into()),
            ssh_keys: vec![],
            dns_records: vec![],
        };
        assert!(!cloud_init(&spec).contains("ip_forward"));
    }

    /// The invariant the refresh rests on: the same spec must render the same
    /// bytes. If it did not, every reconcile pass would see drift and reboot
    /// the gateway, forever.
    #[test]
    fn cloud_init_is_deterministic() {
        let spec = GatewaySpec {
            id: "abcdef12".into(),
            budget_secs: None,
            network_id: "c4d90fd2-be3d-4225-a4a6-265138a76e49".into(),
            lifecycle: Lifecycle::Running,
            management_url: "https://nb.example".into(),
            setup_key: "K".into(),
            slice_address: Some("10.200.7.1/24".into()),
            advertise_cidr: Some("10.200.7.0/24".into()),
            ssh_keys: vec!["ssh-ed25519 AAAA test".into()],
            dns_records: vec![
                omnuv_protocol::DnsRecord { name: "b.internal".into(), address: "10.200.7.11".into() },
                omnuv_protocol::DnsRecord { name: "a.internal".into(), address: "10.200.7.10".into() },
            ],
        };
        assert_eq!(cloud_init(&spec), cloud_init(&spec));
        // Including the record order, which arrives however the query sorted it.
        let mut shuffled = spec.clone();
        shuffled.dns_records.reverse();
        assert_eq!(cloud_init(&spec), cloud_init(&shuffled), "records must not reorder the config");
    }

    #[test]
    fn tags_are_stable_and_proxmox_safe() {
        let t = short_tag("b784148b-e05c-4df4-80a8-4d085f9f9aa4");
        assert_eq!(t, short_tag("b784148b-e05c-4df4-80a8-4d085f9f9aa4"));
        assert!(t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    }
}

impl crate::proxmox::Client {
    /// What this gateway can actually reach, read from inside it.
    ///
    /// Best-effort by construction. A gateway still booting, one whose guest
    /// agent has not started, or one built before the self-check existed all
    /// return `Unknown` — which is neither a pass nor a failure, and that
    /// distinction is most of the value of asking at all.
    /// The whole gateway status file, if the guest can be read.
    async fn gateway_status_file(&self, node: &str, vmid: u32) -> Option<String> {
        #[derive(serde::Deserialize)]
        struct FileRead {
            content: String,
        }
        let r: FileRead = self
            .get_json(&format!(
                "/nodes/{node}/qemu/{vmid}/agent/file-read?file=/run/omnuv/gateway-status.txt"
            ))
            .await
            .ok()?;
        Some(r.content)
    }

    /// The gateway's address **on the overlay**, read from the overlay client
    /// rather than from the guest's primary NIC.
    pub(crate) async fn gateway_overlay(&self, node: &str, vmid: u32) -> Option<String> {
        let content = self.gateway_status_file(node, vmid).await?;
        crate::selfcheck::overlay_address_in(json_section(&content)?)
    }

    /// Every overlay link this gateway can currently see, with the latency it
    /// measured. Empty for a gateway built before the status file carried JSON,
    /// which is the point of appending a section rather than replacing one.
    pub(crate) async fn gateway_links(
        &self,
        node: &str,
        vmid: u32,
        gateway_id: &str,
    ) -> Vec<omnuv_protocol::LinkReport> {
        let Some(content) = self.gateway_status_file(node, vmid).await else { return Vec::new() };
        let Some(json) = json_section(&content) else { return Vec::new() };
        crate::selfcheck::links_in(json, gateway_id, crate::worker::now_unix())
    }

    pub(crate) async fn gateway_checks(
        &self,
        node: &str,
        vmid: u32,
        gateway_id: &str,
    ) -> Vec<omnuv_protocol::SelfCheck> {
        use crate::selfcheck::*;
        use omnuv_protocol::CheckKind;

        #[derive(serde::Deserialize)]
        struct FileRead {
            content: String,
        }

        let read: Option<FileRead> = self
            .get_json(&format!(
                "/nodes/{node}/qemu/{vmid}/agent/file-read?file=/run/omnuv/gateway-status.txt"
            ))
            .await
            .ok();

        let Some(read) = read else {
            return vec![about(
                unknown(
                    "gateway.selfcheck",
                    CheckKind::Connectivity,
                    "no self-check yet: still booting, no guest agent, or built before this existed",
                ),
                gateway_id,
            )];
        };

        // netbird status, then interfaces, then routes.
        let mut parts = read.content.split("\n---\n");
        let netbird = parts.next().unwrap_or("");
        let links = parts.next().unwrap_or("");
        let routes = parts.next().unwrap_or("");

        let mut out = vec![
            about(peer_connectivity(netbird), gateway_id),
            about(peer_reachability(netbird), gateway_id),
            // Connected and reachable is not the same as reached *directly*: a
            // relayed gateway means cross-provider buyer traffic crosses the
            // platform, twice, on the link Edge Rule 3 calls the most expensive
            // in the system.
            about(peer_paths(netbird), gateway_id),
            about(adapter_presence("wt0", links), gateway_id),
        ];

        // A default route is the difference between a gateway that can forward
        // and one that can only talk to its own subnet.
        out.push(about(
            if routes.lines().any(|l| l.trim_start().starts_with("default")) {
                pass("gateway.route.default", CheckKind::Connectivity, "default route present")
            } else {
                fail("gateway.route.default", CheckKind::Connectivity, "no default route")
            },
            gateway_id,
        ));
        out
    }
}

/// The fourth section of the gateway status file: `netbird status --json`.
///
/// Absent on a gateway built before it was added, which must read as "no links
/// reported" and never as a failure — the first three sections still answer
/// every check they answered yesterday.
fn json_section(content: &str) -> Option<&str> {
    let s = content.split("\n---\n").nth(3)?.trim();
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
mod status_file_sections {
    use super::json_section;

    #[test]
    fn an_older_gateway_has_three_sections_and_no_json() {
        assert_eq!(json_section("netbird\n---\naddrs\n---\nroutes"), None);
    }

    #[test]
    fn the_fourth_section_is_the_json_one() {
        let f = "netbird\n---\naddrs\n---\nroutes\n---\n{\"netbirdIp\":\"100.93.1.1/16\"}";
        assert_eq!(json_section(f), Some("{\"netbirdIp\":\"100.93.1.1/16\"}"));
    }

    #[test]
    fn an_empty_fourth_section_is_not_a_document() {
        assert_eq!(json_section("a\n---\nb\n---\nc\n---\n   "), None);
    }
}
