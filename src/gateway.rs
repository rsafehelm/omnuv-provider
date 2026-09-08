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

use omnu_protocol::{GatewaySpec, GatewayState, GatewayStatus, Lifecycle};

use crate::audit;
use crate::proxmox;

/// An empty form body, for POSTs that carry no parameters.
const NO_FORM: &[(String, String)] = &[];

pub const TAG: &str = "omnu-gateway";

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
    printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/99-omnu.conf
    # NetBird puts overlay routes in table 7120, but its own ip rule for that
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
    # Declarative copy so systemd-networkd owns the interface across reboots.
    printf '[Match]\nMACAddress={mac}\n\n[Network]\nAddress={addr}\nIPForward=yes\n' > /etc/systemd/network/10-omnu.network
    systemctl enable systemd-networkd 2>/dev/null || true
"#,
            addr = addr,
            mac = crate::instance::marketplace_mac(&spec.id),
            resolve = crate::instance::resolve_dev(&crate::instance::marketplace_mac(&spec.id)),
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
                "  - path: /etc/dnsmasq.d/omnu.conf
    content: |
      bind-dynamic
      listen-address={ip}
      no-resolv
      local=/internal/
      hostsdir=/etc/omnu/hosts.d
  - path: {DNS_HOSTS_PATH}
    content: |
{seed}"
            )
        }
        None => String::new(),
    };

    format!(
        "#cloud-config
# Omnu marketplace overlay gateway. Managed by omnu-provider; do not edit.
#
# This VM is one buyer network's overlay peer on this provider. The hypervisor
# never runs the overlay client, because a WireGuard interface writing routes
# there could take the host and every guest on it off the network.
hostname: omnu-gw-{short}
manage_etc_hosts: true
users:
  - default
  - name: omnu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
{keys}ssh_authorized_keys:
{keys}packages:
  - qemu-guest-agent
  - dnsmasq
write_files:
  - path: /etc/omnu/gateway.env
    permissions: '0600'
    content: |
      OMNU_GATEWAY_ID={id}
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
  - [ mkdir, -p, /etc/omnu ]
  # runcmd is the final stage, after packages: both are installed by then.
  - [ sh, -c, \"systemctl enable --now qemu-guest-agent || true\" ]
  - [ sh, -c, \"systemctl enable --now dnsmasq || true\" ]
  # Enrol against the marketplace control plane over the LAN. The curl install
  # is time-bounded so it can never hang the boot.
  - [ sh, -c, \"command -v netbird >/dev/null || timeout 60 bash -c 'curl -fsSL https://pkgs.netbird.io/install.sh | sh' || true\" ]
  - [ sh, -c, \"systemctl enable --now netbird || true\" ]
  - [ sh, -c, \"netbird up --management-url {mgmt} --setup-key {key} --hostname omnu-gw-{short}\" ]",
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
                    local_id: None,
                    overlay_address: None,
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
                    .sync_cloud_init(node, vm.vmid, snippet_dir, &format!("omnu-gw-{tag}.yaml"), &cloud_init(spec))
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

            let addr = if running { self.guest_ipv4(node, vm.vmid).await } else { None };

            // Keep the resolver's map current. dnsmasq watches the directory,
            // so replacing the file is the whole update; the write is idempotent
            // and cheap, and needs only the pool-scoped file-write privilege.
            if addr.is_some()
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
                state: match (running, addr.is_some() && !refreshed) {
                    (true, true) => GatewayState::Ready,
                    (true, false) => GatewayState::Deploying,
                    _ => GatewayState::Offline,
                },
                local_id: Some(vm.vmid.to_string()),
                overlay_address: addr,
                message: refreshed.then(|| "configuration refreshed; rebooting".to_string()),
            });
        }

        if spec.lifecycle == Lifecycle::Deleted {
            return Ok(GatewayStatus {
                id: spec.id.clone(),
                state: GatewayState::Offline,
                local_id: None,
                overlay_address: None,
                message: Some("not present".into()),
            });
        }

        // The network's own segment on this provider, before anything sits
        // on it. Idempotent, so a gateway rebuilt after a crash finds it.
        let bridge = crate::sdn::vnet_for(&spec.network_id);
        self.ensure_vnet(node, &bridge).await?;

        let file = format!("omnu-gw-{tag}.yaml");
        std::fs::write(format!("{snippet_dir}/{file}"), cloud_init(spec))
            .map_err(|e| anyhow::anyhow!("writing the gateway's cloud-init: {e}"))?;

        let vmid: u32 = self.get_json::<String>("/cluster/nextid").await?.parse()?;
        let upid: String = self
            .post_form(
                &format!("/nodes/{node}/qemu/{template_vmid}/clone"),
                &[
                    ("newid".to_string(), vmid.to_string()),
                    ("name".to_string(), format!("omnu-gw-{tag}")),
                    ("full".to_string(), "1".to_string()),
                    ("storage".to_string(), storage.to_string()),
                    // Into the pool that carries the file-write grant; a
                    // gateway is the only kind of VM that ever goes there.
                    ("pool".to_string(), GATEWAY_POOL.to_string()),
                ],
            )
            .await?;
        self.wait_task(node, &upid).await?;

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
                ("cicustom".to_string(), format!("user=omnu-snippets:snippets/{file}")),
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
                        "Omnu overlay gateway {}\nOne buyer network's overlay peer on this \
                         provider; the host never runs it.\nManaged by omnu-provider. Do not edit.",
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
            local_id: Some(vmid.to_string()),
            overlay_address: None,
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
            audit::record("gateway.reap", "agent", &tags, "ok", Some(&vm.vmid.to_string()));
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
pub(crate) const GATEWAY_POOL: &str = "omnu";

/// Where the gateway's resolver reads the project's names. dnsmasq watches
/// the directory (`hostsdir`), so replacing this file is the whole update.
const DNS_HOSTS_PATH: &str = "/etc/omnu/hosts.d/project";

/// The resolver's hosts file: one `address name` line per record, sorted so
/// the same map always produces the same bytes.
fn hosts_file(records: &[omnu_protocol::DnsRecord]) -> String {
    let mut lines: Vec<String> =
        records.iter().map(|r| format!("{} {}", r.address, r.name)).collect();
    lines.sort();
    let mut out = String::from("# Managed by omnu-provider; the marketplace owns these names.\n");
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
            network_id: "c4d90fd2-be3d-4225-a4a6-265138a76e49".into(),
            lifecycle: Lifecycle::Running,
            management_url: "https://nb.example".into(),
            setup_key: "K".into(),
            slice_address: Some("10.200.7.1/24".into()),
            advertise_cidr: Some("10.200.7.0/24".into()),
            ssh_keys: vec!["ssh-ed25519 AAAA test".into()],
            dns_records: vec![omnu_protocol::DnsRecord {
                name: "gpu-2.internal".into(),
                address: "10.200.7.11".into(),
            }],
        };
        let ci = cloud_init(&spec);
        // The resolver listens on the slice address only, is authoritative for
        // `internal`, reads a watched directory, and is seeded with the map.
        assert!(ci.contains("listen-address=10.200.7.1\n"));
        assert!(ci.contains("hostsdir=/etc/omnu/hosts.d"));
        assert!(ci.contains("10.200.7.11 gpu-2.internal"));
        // The gateway must never be a path from the bridge to the provider's
        // LAN: forwarding and the gateway's own services are pool-only.
        assert!(ci.contains("iptables -I FORWARD -i $DEV ! -d 10.200.0.0/13 -j DROP"));
        assert!(ci.contains("iptables -I INPUT -i $DEV ! -d 10.200.0.0/13 -j DROP"));
        // Device traffic is rewritten to the gateway's address, buyer traffic
        // is not, and the reply path through the DROP is open.
        assert!(ci.contains("POSTROUTING -o $DEV ! -s 10.200.0.0/13 -j MASQUERADE"));
        // And bridge traffic leaves for the overlay as this gateway: the far
        // side admits per peer, so a machine's own address would be dropped.
        assert!(ci.contains("POSTROUTING -o wt0 -s 10.200.0.0/13 -j MASQUERADE"));
        assert!(ci.contains("-I FORWARD -i $DEV -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"));
        assert!(ci.find("-j DROP").unwrap() < ci.find("ESTABLISHED,RELATED -j ACCEPT").unwrap());
        // And the overlay side is fenced the same way, ahead of the client's
        // own chains.
        assert!(ci.contains("iptables -t mangle -I FORWARD -i wt0 ! -d 10.200.0.0/13 -j DROP"));
        assert!(ci.contains("iptables -t mangle -I INPUT -i wt0 ! -d 10.200.0.0/13 -j DROP"));
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
            network_id: "c4d90fd2-be3d-4225-a4a6-265138a76e49".into(),
            lifecycle: Lifecycle::Running,
            management_url: "https://nb.example".into(),
            setup_key: "K".into(),
            slice_address: Some("10.200.7.1/24".into()),
            advertise_cidr: Some("10.200.7.0/24".into()),
            ssh_keys: vec!["ssh-ed25519 AAAA test".into()],
            dns_records: vec![
                omnu_protocol::DnsRecord { name: "b.internal".into(), address: "10.200.7.11".into() },
                omnu_protocol::DnsRecord { name: "a.internal".into(), address: "10.200.7.10".into() },
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
