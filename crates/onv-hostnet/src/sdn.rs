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

/// The marketplace zone every segment lives in. Created at provider bootstrap.
pub const ZONE: &str = onv_agent_lib::names::SDN_ZONE;

/// The vnet a buyer network gets on this provider: a Proxmox SDN id is at
/// most 8 alphanumerics starting with a letter, so `o` plus the first seven
/// hex digits of the network id. Stable, and the same for the gateway and
/// every machine of the network here.
pub fn vnet_for(network_id: &str) -> String {
    onv_agent_lib::names::vnet(network_id)
}

/// The names a network's segment may take, in the order they are tried. The
/// first is the one it always had, so every existing segment keeps its name;
/// the rest are further slices of a hash of the whole id, for when the first
/// is another network's (PROVIDER, 23 September 2026). Stable: the same id
/// always yields the same list, so every node and every restart agree.
pub fn vnet_candidates(network_id: &str) -> Vec<String> {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(network_id.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    let mut out = vec![vnet_for(network_id)];
    for i in 0..8 {
        let name = format!("{}{}", onv_agent_lib::names::PREFIX, &hex[i * 5..i * 5 + 5]);
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// Which segment a network has or gets, among the vnets the cluster reports:
/// the one whose alias is this network, wherever it sits; else the first free
/// candidate name. **A vnet with no alias is never joined** (the assets-by-id
/// audit of 3 October 2026): its name carries five hex digits of some
/// network's id, and adopting it under the first name put this network on
/// whatever bridge another network with those five digits had made before the
/// alias existed. It is passed over like a held name; an unused one is the
/// reaper's (`reap_unused_segments`). Measured that day: no buyer segment on
/// any provider lacked its alias, so nothing in the estate was adopted. `Err`
/// names the networks holding every candidate.
pub fn choose(vnets: &[serde_json::Value], network_id: &str) -> Result<(String, Segment), Vec<String>> {
    if let Some(v) = vnets.iter().find(|v| {
        v["alias"].as_str().map(str::trim) == Some(network_id)
    }) && let Some(name) = v["vnet"].as_str()
    {
        return Ok((name.to_string(), segment(Some(v), network_id)));
    }
    let candidates = vnet_candidates(network_id);
    let mut owners = Vec::new();
    for name in &candidates {
        match segment(vnets.iter().find(|v| v["vnet"] == name.as_str()), network_id) {
            Segment::Create => return Ok((name.clone(), Segment::Create)),
            Segment::Unowned => owners.push(format!("{name} (no alias: whose it is cannot be read)")),
            Segment::Collision(owner) => owners.push(format!("{name} ({owner})")),
            // An alias naming this network was found above.
            Segment::Ready | Segment::Pending => {}
        }
    }
    Err(owners)
}

/// The bridges a VM's configuration attaches to, from its `net<N>` keys.
pub fn bridges_of(cfg: &serde_json::Value) -> Vec<String> {
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
/// refused rather than joined. A vnet with no alias predates this, and nothing
/// can say whose it was, so it is refused too.
#[derive(Debug, PartialEq)]
pub enum Segment {
    /// No vnet of that name: create it, with the alias.
    Create,
    /// Ours and applied: nothing to do if the bridge is up.
    Ready,
    /// Ours, with a change still pending: apply.
    Pending,
    /// No alias, so nobody's that can be proved: never joined.
    Unowned,
    /// Another network's segment. Carries that network's id.
    Collision(String),
}

pub fn segment(existing: Option<&serde_json::Value>, network_id: &str) -> Segment {
    let Some(v) = existing else { return Segment::Create };
    match v.get("alias").and_then(|a| a.as_str()).map(str::trim).filter(|a| !a.is_empty()) {
        Some(owner) if owner != network_id => Segment::Collision(owner.to_string()),
        None => Segment::Unowned,
        Some(_) if v.get("state").is_some() => Segment::Pending,
        Some(_) => Segment::Ready,
    }
}
