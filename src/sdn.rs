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
