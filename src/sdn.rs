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

/// The names a network's segment may take, in the order they are tried. The
/// first is the one it always had, so every existing segment keeps its name;
/// the rest are further slices of a hash of the whole id, for when the first
/// is another network's (PROVIDER, 23 September 2026). Stable: the same id
/// always yields the same list, so every node and every restart agree.
pub(crate) fn vnet_candidates(network_id: &str) -> Vec<String> {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(network_id.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    let mut out = vec![vnet_for(network_id)];
    for i in 0..8 {
        let name = format!("{}{}", crate::names::PREFIX, &hex[i * 5..i * 5 + 5]);
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// Which segment a network has or gets, among the vnets the cluster reports:
/// the one whose alias is this network, wherever it sits; else the first free
/// candidate name. A vnet with no alias is adopted only under the first name,
/// the one a segment from before the alias would have. `Err` names the
/// networks holding every candidate.
pub(crate) fn choose(vnets: &[serde_json::Value], network_id: &str) -> Result<(String, Segment), Vec<String>> {
    if let Some(v) = vnets.iter().find(|v| {
        v["alias"].as_str().map(str::trim) == Some(network_id)
    }) && let Some(name) = v["vnet"].as_str()
    {
        return Ok((name.to_string(), segment(Some(v), network_id)));
    }
    let candidates = vnet_candidates(network_id);
    let mut owners = Vec::new();
    for (i, name) in candidates.iter().enumerate() {
        match segment(vnets.iter().find(|v| v["vnet"] == name.as_str()), network_id) {
            Segment::Create => return Ok((name.clone(), Segment::Create)),
            Segment::Adopt if i == 0 => return Ok((name.clone(), Segment::Adopt)),
            Segment::Adopt => owners.push(format!("{name} (no alias)")),
            Segment::Collision(owner) => owners.push(format!("{name} ({owner})")),
            // An alias naming this network was found above.
            Segment::Ready | Segment::Pending => {}
        }
    }
    Err(owners)
}

/// The bridges a VM's configuration attaches to, from its `net<N>` keys.
fn bridges_of(cfg: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(obj) = cfg.as_object() {
        for (k, v) in obj {
            if k.starts_with("net")
                && let Some(s) = v.as_str()
                && let Some(b) = s.split(',').find_map(|kv| kv.strip_prefix("bridge="))
            {
                out.push(b.to_string());
            }
        }
    }
    out
}

/// What to do about a network's segment, given the vnet of that name as the
/// cluster reports it (or none).
///
/// **The name carries only 20 bits of the network id**, because a Proxmox vnet
/// id is at most eight characters and three are `onv`. Two networks whose ids
/// share those bits get the same name, and reusing a vnet by name alone would
/// put two tenants on one bridge without a word. So the vnet records the whole
/// network id in its `alias`, and a vnet whose alias names another network is
/// refused rather than joined. A vnet with no alias predates this and is
/// adopted: nothing can say whose it was, which is no worse than before.
#[derive(Debug, PartialEq)]
pub(crate) enum Segment {
    /// No vnet of that name: create it, with the alias.
    Create,
    /// Ours and applied: nothing to do if the bridge is up.
    Ready,
    /// Ours, with a change still pending: apply.
    Pending,
    /// Ours by name only, from before the alias: write the alias, then apply.
    Adopt,
    /// Another network's segment. Carries that network's id.
    Collision(String),
}

pub(crate) fn segment(existing: Option<&serde_json::Value>, network_id: &str) -> Segment {
    let Some(v) = existing else { return Segment::Create };
    match v.get("alias").and_then(|a| a.as_str()).map(str::trim).filter(|a| !a.is_empty()) {
        Some(owner) if owner != network_id => Segment::Collision(owner.to_string()),
        None => Segment::Adopt,
        Some(_) if v.get("state").is_some() => Segment::Pending,
        Some(_) => Segment::Ready,
    }
}

impl Client {
    /// Creates the segment if it is missing and applies it, then waits for the
    /// bridge to exist on the node, and says which vnet it is. Idempotent: an
    /// applied vnet is left alone.
    ///
    /// **A name another network holds is passed over, not refused.** The name
    /// carries 20 bits of the id, so two networks can want the same one; the
    /// second used to be refused, and could then have no machine on this
    /// provider. It now takes the next free candidate, and every caller uses
    /// the name this returns rather than computing one.
    pub(crate) async fn ensure_vnet(&self, node: &str, network_id: &str) -> anyhow::Result<String> {
        let vnets: Vec<serde_json::Value> = self.get_json("/cluster/sdn/vnets?pending=1").await?;
        // `state` is only set while a change is pending. See `segment`.
        let (vnet, found) = choose(&vnets, network_id).map_err(|held| {
            anyhow::anyhow!("every segment name network {network_id} may take is held by another: {}", held.join(", "))
        })?;
        let vnet = vnet.as_str();
        match found {
            Segment::Ready if self.vnet_available(node, vnet).await? => return Ok(vnet.to_string()),
            Segment::Ready | Segment::Pending => {}
            Segment::Collision(_) => unreachable!("choose never returns a collision"),
            Segment::Adopt => {
                self.put_form::<Option<serde_json::Value>>(
                    &format!("/cluster/sdn/vnets/{vnet}"),
                    &[("alias".to_string(), network_id.to_string())],
                )
                .await?;
            }
            Segment::Create => {
                self.post_form::<Option<serde_json::Value>>(
                    "/cluster/sdn/vnets",
                    &[
                        ("vnet".to_string(), vnet.to_string()),
                        ("zone".to_string(), ZONE.to_string()),
                        ("alias".to_string(), network_id.to_string()),
                    ],
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
                return Ok(vnet.to_string());
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

        // **Every bridge any VM in the cluster references, running or
        // stopped.** A vnet is cluster-wide, and this asked only the node the
        // agent runs on, so on a cluster a segment whose machines all ran on
        // another node looked unused and was removed from under them. Each
        // node is asked live, not through `/cluster/resources`, whose cached
        // view can miss a machine created a moment ago. A node or a VM that
        // cannot be read stops the reap: unreadable is not unused.
        let nodes: Vec<serde_json::Value> = self.get_json("/nodes").await?;
        let mut used: std::collections::BTreeSet<String> = Default::default();
        for n in &nodes {
            let Some(name) = n["node"].as_str() else { return Ok(0) };
            if n["status"].as_str() != Some("online") {
                return Ok(0);
            }
            let Ok(vms) = self.get_json::<Vec<serde_json::Value>>(&format!("/nodes/{name}/qemu")).await else {
                return Ok(0);
            };
            for vm in &vms {
                let Some(vmid) = vm["vmid"].as_u64() else { continue };
                let Ok(cfg) = self
                    .get_json::<serde_json::Value>(&format!("/nodes/{name}/qemu/{vmid}/config"))
                    .await
                else {
                    return Ok(0);
                };
                used.extend(bridges_of(&cfg));
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
    use serde_json::json;

    /// `ensure_vnet` through the real client: a new segment is created with
    /// the network's id as its alias, and when its name is another network's
    /// it takes the next candidate, and writes nothing to the other's.
    #[tokio::test]
    async fn a_segment_is_created_with_its_owner_and_a_taken_name_is_passed_over() {
        use crate::pvemock::{task_ok, Mock};
        let net = "c4d90fd2-be3d-4225-a4a6-265138a76e49";
        let other = "c4d90aaa-0000-4000-8000-000000000000";
        let names = vnet_candidates(net);
        let route = |existing: serde_json::Value, up: Vec<String>| {
            move |method: &str, path: &str, _b: &str| {
                if let Some(r) = task_ok(path) {
                    return r;
                }
                match (method, path) {
                    ("GET", "/cluster/sdn/vnets?pending=1") => (200, existing.clone()),
                    ("POST", "/cluster/sdn/vnets") | ("PUT", _) => (200, json!("UPID:n1:x")),
                    ("GET", p) if p.ends_with("/content") => (200, json!(up.iter()
                        .map(|v| json!({"vnet": v, "status": "available"})).collect::<Vec<_>>())),
                    _ => (404, json!(null)),
                }
            }
        };

        let fresh = Mock::start(route(json!([]), names.clone())).await;
        assert_eq!(fresh.client().ensure_vnet("n1", net).await.expect("created"), "onvc4d90");
        let body = fresh.body_of("POST", "/cluster/sdn/vnets").expect("a vnet was created");
        assert!(body.contains(&format!("alias={net}")), "the new segment does not name its network: {body}");

        let taken = Mock::start(route(json!([{"vnet": "onvc4d90", "zone": "onv", "alias": other}]), names.clone())).await;
        let got = taken.client().ensure_vnet("n1", net).await.expect("placed under another name");
        assert_eq!(got, names[1], "not the next candidate");
        let body = taken.body_of("POST", "/cluster/sdn/vnets").expect("a vnet was created");
        assert!(body.contains(&format!("vnet={}", names[1])) && body.contains(&format!("alias={net}")), "{body}");
        assert!(!taken.called("PUT", "/cluster/sdn/vnets/onvc4d90"), "the other network's segment was written to");
    }

    /// The choice itself: this network's alias wins wherever it sits, a taken
    /// name is passed over, an unaliased vnet is adopted only under the first
    /// name, and every name held is an error that names the holders.
    #[test]
    fn a_network_finds_its_segment_by_alias_and_takes_the_first_free_name() {
        let net = "c4d90fd2-be3d-4225-a4a6-265138a76e49";
        let other = "c4d90aaa-0000-4000-8000-000000000000";
        let names = vnet_candidates(net);
        assert_eq!(names[0], "onvc4d90", "the first name must stay the one every segment has today");
        assert!(names.len() >= 5 && names.iter().all(|n| n.len() == 8), "{names:?}");

        let held = json!({"vnet": "onvc4d90", "zone": "onv", "alias": other});
        let mine_elsewhere = json!({"vnet": names[2], "zone": "onv", "alias": net});
        assert_eq!(choose(&[held.clone(), mine_elsewhere], net), Ok((names[2].clone(), Segment::Ready)));
        assert_eq!(choose(&[held.clone()], net), Ok((names[1].clone(), Segment::Create)));
        assert_eq!(choose(&[json!({"vnet": "onvc4d90", "zone": "onv"})], net), Ok(("onvc4d90".into(), Segment::Adopt)));
        let unaliased_second = json!({"vnet": names[1], "zone": "onv"});
        assert_eq!(choose(&[held.clone(), unaliased_second], net), Ok((names[2].clone(), Segment::Create)),
                   "an unaliased vnet under a later name was adopted");
        let all: Vec<_> = names.iter().map(|n| json!({"vnet": n, "zone": "onv", "alias": other})).collect();
        let err = choose(&all, net).expect_err("every name held");
        assert_eq!(err.len(), names.len());
    }

    /// **Through the real client, against a two-node cluster.** `onvbbb02` is
    /// used only by a machine on the *other* node and must survive; `onvccc03`
    /// is used by nothing and must go. Then the other node stops answering,
    /// and nothing at all may be deleted.
    #[tokio::test]
    async fn the_reaper_keeps_a_segment_used_on_another_node() {
        use crate::pvemock::{task_ok, Mock};
        fn route(other_node_readable: bool) -> impl Fn(&str, &str, &str) -> (u16, serde_json::Value) {
            move |method, path, _body| {
                if let Some(r) = task_ok(path) {
                    return r;
                }
                match (method, path) {
                    ("GET", "/cluster/sdn/vnets?pending=1") => (200, json!([
                        {"vnet": "onvaaa01", "zone": "onv"},
                        {"vnet": "onvbbb02", "zone": "onv"},
                        {"vnet": "onvccc03", "zone": "onv"}])),
                    ("GET", "/nodes") => (200, json!([
                        {"node": "n1", "status": "online"}, {"node": "n2", "status": "online"}])),
                    ("GET", "/nodes/n1/qemu") => (200, json!([{"vmid": 100}])),
                    ("GET", "/nodes/n2/qemu") if other_node_readable => (200, json!([{"vmid": 200}])),
                    ("GET", "/nodes/n2/qemu") => (500, json!(null)),
                    ("GET", "/nodes/n1/qemu/100/config") => (200, json!({"net1": "virtio=AA,bridge=onvaaa01"})),
                    ("GET", "/nodes/n2/qemu/200/config") => (200, json!({"net1": "virtio=BB,bridge=onvbbb02"})),
                    ("DELETE", p) if p.starts_with("/cluster/sdn/vnets/") => (200, json!(null)),
                    ("PUT", "/cluster/sdn") => (200, json!("UPID:n1:apply")),
                    _ => (404, json!(null)),
                }
            }
        }

        let mock = Mock::start(route(true)).await;
        let removed = mock.client().reap_unused_segments("n1").await.expect("reap");
        assert_eq!(removed, 1, "exactly the unused segment is removed");
        assert!(mock.called("DELETE", "/cluster/sdn/vnets/onvccc03"));
        assert!(!mock.called("DELETE", "/cluster/sdn/vnets/onvbbb02"),
                "a segment in use on another node was removed");
        assert!(!mock.called("DELETE", "/cluster/sdn/vnets/onvaaa01"));

        let blind = Mock::start(route(false)).await;
        assert_eq!(blind.client().reap_unused_segments("n1").await.expect("reap"), 0);
        assert!(!blind.calls.lock().unwrap().iter().any(|c| c.method == "DELETE"),
                "a node that could not be read still had segments reaped");
    }

    #[test]
    fn a_vms_bridges_are_read_from_every_nic() {
        let cfg = json!({
            "net0": "virtio=BC:24:11:00:00:01,bridge=onvnat0",
            "net1": "virtio=BC:24:11:00:00:02,bridge=onvc4d90,firewall=1",
            "name": "onv-m", "netmask": "not a nic, no bridge",
        });
        let mut b = super::bridges_of(&cfg);
        b.sort();
        assert_eq!(b, vec!["onvc4d90", "onvnat0"]);
        assert!(super::bridges_of(&json!({"name": "no nics"})).is_empty());
    }

    #[test]
    fn a_segment_named_like_ours_is_joined_only_when_it_is_ours() {
        let net = "c4d90fd2-be3d-4225-a4a6-265138a76e49";
        // Same first five hex digits, a different network: the case the
        // 20-bit name cannot tell apart.
        let other = "c4d90aaa-0000-4000-8000-000000000000";
        assert_eq!(vnet_for(net), vnet_for(other), "the fixture must collide on name");

        assert_eq!(segment(None, net), Segment::Create);
        let ours = json!({"vnet": "onvc4d90", "zone": "onv", "alias": net});
        assert_eq!(segment(Some(&ours), net), Segment::Ready);
        let pending = json!({"vnet": "onvc4d90", "alias": net, "state": "new"});
        assert_eq!(segment(Some(&pending), net), Segment::Pending);
        // Negative: another network's segment is refused, never joined.
        assert_eq!(segment(Some(&ours), other), Segment::Collision(net.to_string()));
        // From before the alias, as `onvaca8e` on the test cluster is today.
        let legacy = json!({"vnet": "onvc4d90", "zone": "onv"});
        assert_eq!(segment(Some(&legacy), net), Segment::Adopt);
        assert_eq!(segment(Some(&json!({"vnet": "onvc4d90", "alias": " "})), net), Segment::Adopt);
    }

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
