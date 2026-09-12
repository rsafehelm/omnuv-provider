//! Per-network segments on the provider.
//!
//! Every buyer network with a machine on this provider gets a bridge of its
//! own here: an SDN vnet in the marketplace zone, with the network's gateway
//! and its machines on it and nothing else. Two tenants on one provider never
//! share a segment, so isolation is the wiring, not a filter rule.
//!
//! The zone is bootstrap's: a *simple* zone is a bridge with no uplink, so a
//! vnet in it has no path to the provider's LAN by construction. The agent's
//! token holds `SDN.Allocate` on that zone and, without propagation, on `/sdn`
//! — the least that lets it create a vnet there and apply, and not enough to
//! create a zone or touch another one (verified at source: Vnets.pm checks
//! `/sdn/zones/{zone}`, SDN.pm's apply checks `/sdn`, Zones.pm checks
//! `/sdn/zones`).
//!
//! Applying is `ifreload -a` on the node. ifupdown2 reloads by diff, so an
//! unchanged uplink is left alone; the smoke run on a live host confirmed the
//! management address and route untouched.

use crate::proxmox::Client;

/// The marketplace zone every segment lives in. Created at provider bootstrap.
pub(crate) const ZONE: &str = crate::names::SDN_ZONE;

const NO_FORM: &[(String, String)] = &[];

/// The vnet a buyer network gets on this provider: a Proxmox SDN id is at
/// most 8 alphanumerics starting with a letter, so `o` plus the first seven
/// hex digits of the network id. Stable, and the same for the gateway and
/// every machine of the network here.
pub(crate) fn vnet_for(network_id: &str) -> String {
    crate::names::vnet(network_id)
}

impl Client {
    /// Creates the segment if it is missing and applies it, then waits for the
    /// bridge to exist on the node. Idempotent: an applied vnet is left alone.
    pub(crate) async fn ensure_vnet(&self, node: &str, vnet: &str) -> anyhow::Result<()> {
        let vnets: Vec<serde_json::Value> = self.get_json("/cluster/sdn/vnets?pending=1").await?;
        match vnets.iter().find(|v| v["vnet"] == vnet) {
            // Present and applied. `state` is only set while a change is pending.
            Some(v) if v.get("state").is_none() && self.vnet_available(node, vnet).await? => return Ok(()),
            Some(_) => {}
            None => {
                self.post_form::<Option<serde_json::Value>>(
                    "/cluster/sdn/vnets",
                    &[("vnet".to_string(), vnet.to_string()), ("zone".to_string(), ZONE.to_string())],
                )
                .await?;
            }
        }
        self.apply(node).await?;
        // The apply task returns before the node's own reload has finished;
        // a VM attached in that window fails to start with "bridge does not
        // exist". Converge on the bridge being up, not on the config.
        for _ in 0..30 {
            if self.vnet_available(node, vnet).await? {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        anyhow::bail!("segment {vnet} not up on {node} after applying")
    }

    /// Removes any segment of ours on this node that no machine is attached to.
    ///
    /// **Nothing else deletes them any more.** A project segment used to be
    /// created and destroyed as a side effect of the per-provider gateway;
    /// topology v2 stopped Core asking for gateways, so both halves fell away.
    /// The creating half now lives with the machine that needs it, and this is
    /// the other half: a buyer who deletes their last machine on a provider
    /// should not leave a bridge behind there, and deleting the network in the
    /// marketplace should not leave one either.
    ///
    /// **Attachment is read from every VM's configuration, not from what is
    /// running.** A stopped machine still owns its segment, and reaping one
    /// out from under it would leave a VM that cannot start.
    ///
    /// Only vnets in the marketplace's own zone, and never the NAT bridge:
    /// `onat0` is host configuration that every buyer machine's first
    /// interface sits on, and it belongs to no project.
    pub(crate) async fn reap_unused_segments(&self, node: &str) -> anyhow::Result<usize> {
        let vnets: Vec<serde_json::Value> = self.get_json("/cluster/sdn/vnets?pending=1").await?;
        let ours: Vec<String> = vnets
            .iter()
            .filter(|v| v["zone"] == ZONE)
            .filter_map(|v| v["vnet"].as_str().map(str::to_string))
            .filter(|v| v != crate::names::NAT_VNET)
            .collect();
        if ours.is_empty() {
            return Ok(0);
        }

        // Every bridge any VM on this node references, running or stopped.
        let vms: Vec<serde_json::Value> = self.get_json(&format!("/nodes/{node}/qemu")).await?;
        let mut used: std::collections::BTreeSet<String> = Default::default();
        for vm in &vms {
            let Some(vmid) = vm["vmid"].as_u64() else { continue };
            let Ok(cfg) = self
                .get_json::<serde_json::Value>(&format!("/nodes/{node}/qemu/{vmid}/config"))
                .await
            else {
                // Unreadable is not unused. Skipping the whole reap is the
                // safe direction: a bridge left behind costs nothing, and one
                // removed from under a machine costs that machine.
                return Ok(0);
            };
            if let Some(obj) = cfg.as_object() {
                for (k, v) in obj {
                    if k.starts_with("net")
                        && let Some(s) = v.as_str()
                        && let Some(b) = s.split(',').find_map(|kv| kv.strip_prefix("bridge="))
                    {
                        used.insert(b.to_string());
                    }
                }
            }
        }

        let mut removed = 0;
        for v in ours.iter().filter(|v| !used.contains(*v)) {
            match self.delete_vnet(node, v).await {
                Ok(()) => {
                    crate::audit::record("segment.reap", "agent", v, "removed", None);
                    removed += 1;
                }
                Err(e) => eprintln!("segment {v}: not removed: {e}"),
            }
        }
        Ok(removed)
    }

    /// Removes the segment and applies. Nothing to do when it is already gone.
    pub(crate) async fn delete_vnet(&self, node: &str, vnet: &str) -> anyhow::Result<()> {
        let vnets: Vec<serde_json::Value> = self.get_json("/cluster/sdn/vnets?pending=1").await?;
        match vnets.iter().find(|v| v["vnet"] == vnet) {
            None => return Ok(()),
            Some(v) if v["state"] == "deleted" => {}
            Some(_) => {
                self.delete_task::<Option<serde_json::Value>>(&format!("/cluster/sdn/vnets/{vnet}")).await?;
            }
        }
        self.apply(node).await
    }

    /// Whether the node reports the vnet's bridge as up.
    async fn vnet_available(&self, node: &str, vnet: &str) -> anyhow::Result<bool> {
        let content: Vec<serde_json::Value> =
            self.get_json(&format!("/nodes/{node}/sdn/zones/{ZONE}/content")).await?;
        Ok(content.iter().any(|c| c["vnet"] == vnet && c["status"] == "available"))
    }

    /// Commits the pending SDN configuration and reloads the nodes.
    async fn apply(&self, node: &str) -> anyhow::Result<()> {
        let upid: String = self.put_form("/cluster/sdn", NO_FORM).await?;
        self.wait_task(node, &upid).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vnet_ids_fit_proxmox_and_are_stable() {
        let a = vnet_for("c4d90fd2-be3d-4225-a4a6-265138a76e49");
        assert_eq!(a, "onvc4d90");
        assert_eq!(a, vnet_for("c4d90fd2-be3d-4225-a4a6-265138a76e49"));
        assert_ne!(a, vnet_for("db885ae5-f466-4526-96bd-cfbe447d0fec"));
        for id in ["c4d90fd2-be3d-4225-a4a6-265138a76e49", "ABCDEF01-2", "x"] {
            let v = vnet_for(id);
            assert!(v.len() <= 8 && v.len() >= 2, "{v}");
            assert!(v.chars().next().unwrap().is_ascii_alphabetic());
            assert!(v.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()), "{v}");
        }
    }
}
