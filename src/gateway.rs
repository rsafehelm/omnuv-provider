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
    let routes = match spec.advertise_cidr.as_deref() {
        Some(cidr) if advertisable(cidr).is_ok() => format!(
            "  # Advertise this buyer's slice and nothing wider. Never a supernet,\n  \
             # never a default route: either would pull the provider's own traffic\n  \
             # onto the overlay.\n  - [ sh, -c, \"echo '{cidr}' > /etc/omnu/advertise\" ]\n"
        ),
        _ => String::new(),
    };

    format!(
        "#cloud-config
# Omnu marketplace overlay gateway. Managed by omnu-provider; do not edit.
#
# This VM is the only overlay peer on this provider. The hypervisor never runs
# the overlay client, because a WireGuard interface writing routes there could
# take the host and every guest on it off the network.
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
{keys}package_update: true
packages:
  - qemu-guest-agent
  - curl
  - ca-certificates
write_files:
  - path: /etc/omnu/gateway.env
    permissions: '0600'
    content: |
      OMNU_GATEWAY_ID={id}
      NB_MANAGEMENT_URL={mgmt}
runcmd:
  - [ mkdir, -p, /etc/omnu ]
  - [ systemctl, enable, --now, qemu-guest-agent ]
  - bash -c 'curl -fsSL https://pkgs.netbird.io/install.sh | sh'
  - [ systemctl, enable, --now, netbird ]
  - bash -c 'netbird up --management-url {mgmt} --setup-key {key} --hostname omnu-gw-{short}'
{routes}",
        keys = if keys.is_empty() { "      []\n".to_string() } else { keys },
        id = spec.id,
        mgmt = spec.management_url,
        key = spec.setup_key,
        short = &spec.id[..spec.id.len().min(8)],
        routes = routes,
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
        if let Some(cidr) = &spec.advertise_cidr
            && let Err(why) = advertisable(cidr)
        {
            // Refuse rather than build something that would advertise it. This
            // is the last point before a route is written on the provider.
            return Ok(GatewayStatus {
                id: spec.id.clone(),
                state: GatewayState::Error,
                local_id: None,
                overlay_address: None,
                message: Some(why),
            });
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

            let addr = if running { self.guest_ipv4(node, vm.vmid).await } else { None };
            return Ok(GatewayStatus {
                id: spec.id.clone(),
                // READY means the guest is answering, not merely that a VM
                // exists: a gateway that never booted is not carrying traffic.
                state: match (running, addr.is_some()) {
                    (true, true) => GatewayState::Ready,
                    (true, false) => GatewayState::Deploying,
                    _ => GatewayState::Offline,
                },
                local_id: Some(vm.vmid.to_string()),
                overlay_address: addr,
                message: None,
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
                        "Omnu overlay gateway {}\nThe only overlay peer on this provider; the \
                         host never runs it.\nManaged by omnu-provider. Do not edit.",
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

    /// Destroys the gateway. Rebuilding is this plus the next reconcile pass —
    /// there is no separate repair path, because a gateway holds no state worth
    /// keeping.
    pub async fn delete_gateway(&self, node: &str, gateway_id: &str) -> anyhow::Result<()> {
        let Some(vm) = self.find_tagged_vm(node, TAG, &short_tag(gateway_id)).await? else {
            return Ok(());
        };
        if vm.status.as_deref() == Some("running") {
            let upid: String = self
                .post_form(&format!("/nodes/{node}/qemu/{}/status/stop", vm.vmid), NO_FORM)
                .await?;
            self.wait_task(node, &upid).await?;
        }
        let upid: String = self.delete_task(&format!("/nodes/{node}/qemu/{}", vm.vmid)).await?;
        self.wait_task(node, &upid).await?;
        audit::record("gateway.delete", "core", gateway_id, "ok", Some(&vm.vmid.to_string()));
        Ok(())
    }
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
            lifecycle: Lifecycle::Running,
            management_url: "https://nb.example".into(),
            setup_key: "K".into(),
            advertise_cidr: Some("0.0.0.0/0".into()),
            ssh_keys: vec![],
        };
        assert!(!cloud_init(&spec).contains("0.0.0.0/0"));
    }

    #[test]
    fn a_slice_that_is_allowed_is_written() {
        let spec = GatewaySpec {
            id: "abcdef12".into(),
            lifecycle: Lifecycle::Running,
            management_url: "https://nb.example".into(),
            setup_key: "K".into(),
            advertise_cidr: Some("10.200.7.0/24".into()),
            ssh_keys: vec!["ssh-ed25519 AAAA test".into()],
        };
        let ci = cloud_init(&spec);
        assert!(ci.contains("10.200.7.0/24"));
        assert!(ci.contains("netbird up"));
        assert!(ci.contains("ssh-ed25519 AAAA test"));
    }

    #[test]
    fn tags_are_stable_and_proxmox_safe() {
        let t = short_tag("b784148b-e05c-4df4-80a8-4d085f9f9aa4");
        assert_eq!(t, short_tag("b784148b-e05c-4df4-80a8-4d085f9f9aa4"));
        assert!(t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    }
}
