//! What the agent verifies about itself, at start and on every pass.
//!
//! ## Why this exists
//!
//! On 10 September a buyer's endpoint answered 502 for hours. The machine was
//! healthy, its containers were healthy, the recipe had installed, the endpoint
//! row was ACTIVE, DNS resolved and the certificate was valid. The gateway VM
//! existed and was `running`. Everything anyone could see said yes.
//!
//! The overlay control plane had been rebuilt, so the gateway's peer could not
//! register — and nothing, anywhere, was asking whether it *could reach*
//! anything. Every check in the system was a presence check.
//!
//! ## The rule
//!
//! **Presence is not health.** For every network object the agent owns, there
//! are two questions and they fail independently:
//!
//! ```text
//! presence      is it configured, does it exist, is it running
//! connectivity  did a packet get somewhere and did something answer
//! ```
//!
//! Only the second is what a buyer experiences. So each is asked separately and
//! reported separately, and a `Pass` on presence never stands in for the other.
//!
//! ## Unknown is an answer
//!
//! A machine that is still booting has not failed its checks. A guest with no
//! agent has not passed them. Collapsing either into pass or fail is how a
//! monitoring surface becomes something people learn to ignore.

use omnuv_protocol::{CheckKind, CheckResult, SelfCheck};

pub fn pass(name: &str, kind: CheckKind, detail: impl Into<String>) -> SelfCheck {
    SelfCheck { name: name.into(), kind, result: CheckResult::Pass, detail: Some(detail.into()), subject: None }
}

pub fn fail(name: &str, kind: CheckKind, detail: impl Into<String>) -> SelfCheck {
    SelfCheck { name: name.into(), kind, result: CheckResult::Fail, detail: Some(detail.into()), subject: None }
}

pub fn unknown(name: &str, kind: CheckKind, detail: impl Into<String>) -> SelfCheck {
    SelfCheck { name: name.into(), kind, result: CheckResult::Unknown, detail: Some(detail.into()), subject: None }
}

pub fn about(mut c: SelfCheck, subject: impl Into<String>) -> SelfCheck {
    c.subject = Some(subject.into());
    c
}

/// Reads `netbird status` output from inside a gateway and says whether that
/// peer is actually on the overlay.
///
/// The string matched is deliberately the one the client prints, because that
/// is the fact: "Management: Connected". Inferring it from the presence of an
/// interface or a config file is how this was missed — both were there.
pub fn peer_connectivity(status_output: &str) -> SelfCheck {
    let connected = status_output
        .lines()
        .any(|l| l.trim().starts_with("Management:") && l.contains("Connected"));

    // The reason, when there is one, is the most useful sentence in the file:
    // "setup key is invalid" and "no peer auth method provided" are different
    // problems with different fixes.
    let reason = status_output
        .lines()
        .find(|l| l.trim().starts_with("Management:"))
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| "no Management line in netbird status".into());

    if connected {
        let peers = status_output
            .lines()
            .find(|l| l.trim().starts_with("Peers count:"))
            .map(|l| l.trim().to_string())
            .unwrap_or_default();
        pass("gateway.peer.connected", CheckKind::Connectivity, format!("{reason}; {peers}").trim_end_matches("; ").to_string())
    } else {
        fail("gateway.peer.connected", CheckKind::Connectivity, reason)
    }
}

/// A peer being connected to its control plane is still not the same as it
/// carrying traffic. This reads the peer count and says whether the gateway has
/// anyone to forward to.
///
/// A gateway alone on the overlay is the state we were in after the relay was
/// fixed but before the gateway rejoined: connected, and useless.
pub fn peer_reachability(status_output: &str) -> SelfCheck {
    let count = status_output
        .lines()
        .find(|l| l.trim().starts_with("Peers count:"))
        .and_then(|l| l.split(':').nth(1).map(str::trim).map(str::to_string));

    match count {
        None => unknown("gateway.peers.reachable", CheckKind::Connectivity, "no peer count reported"),
        Some(c) => {
            // "0/0 Connected" — on the overlay, with nobody to talk to.
            let connected_any = c
                .split('/')
                .next()
                .and_then(|n| n.trim().parse::<u32>().ok())
                .is_some_and(|n| n > 0);
            if connected_any {
                pass("gateway.peers.reachable", CheckKind::Connectivity, c)
            } else {
                fail(
                    "gateway.peers.reachable",
                    CheckKind::Connectivity,
                    format!("{c} — on the overlay but forwarding to nobody"),
                )
            }
        }
    }
}

/// Whether the guest reports the interface the marketplace expects it to have.
pub fn adapter_presence(name: &str, interfaces: &str) -> SelfCheck {
    if interfaces.split_whitespace().any(|w| w.trim_matches([':', ',']) == name) {
        pass("adapter.present", CheckKind::Presence, format!("{name} is up"))
    } else {
        fail("adapter.present", CheckKind::Presence, format!("{name} is absent"))
    }
}

/// One peer as `netbird status --detail` describes it.
struct Peer {
    name: String,
    relayed: bool,
}

/// Peers and how each is actually reached.
///
/// The output is a block per peer: a `name.netbird.selfhosted:` header, then
/// indented fields including `Connection type: P2P` or `Relayed`.
fn peers_in(detail: &str) -> Vec<Peer> {
    let mut out: Vec<Peer> = Vec::new();
    for line in detail.lines() {
        let t = line.trim();
        if let Some(name) = t.strip_suffix(':').filter(|n| n.contains(".netbird.")) {
            out.push(Peer {
                name: name.split('.').next().unwrap_or(name).to_string(),
                relayed: false,
            });
        } else if let Some(kind) = t.strip_prefix("Connection type:")
            && let Some(last) = out.last_mut()
        {
            last.relayed = kind.trim().eq_ignore_ascii_case("relayed");
        }
    }
    out
}

/// Whether buyer traffic between providers is crossing the platform.
///
/// **Relayed means two different things and only one is a fault.** A gateway
/// reached through the relay is cross-provider buyer traffic going through the
/// marketplace's own host — every byte twice on the most expensive link in the
/// system, which is what Edge Rule 2 exists to prevent. A *client device*
/// reached through the relay is ordinary: a laptop behind NAT often cannot
/// hole-punch, and relaying is the fallback working as designed.
///
/// Failing on the second would be a check that fires on correct behaviour,
/// which is how people learn to ignore a check.
pub fn peer_paths(detail: &str) -> SelfCheck {
    let peers = peers_in(detail);
    if peers.is_empty() {
        return unknown(
            "gateway.peers.direct",
            CheckKind::Connectivity,
            "no peer detail reported",
        );
    }

    let gateways_relayed: Vec<&str> = peers
        .iter()
        .filter(|p| p.relayed && p.name.starts_with("onv-gw-"))
        .map(|p| p.name.as_str())
        .collect();
    let clients_relayed = peers
        .iter()
        .filter(|p| p.relayed && !p.name.starts_with("onv-gw-"))
        .count();
    let direct = peers.iter().filter(|p| !p.relayed).count();

    let note = format!(
        "{direct} direct, {} relayed ({clients_relayed} of them clients, which is expected)",
        peers.len() - direct
    );

    if gateways_relayed.is_empty() {
        pass("gateway.peers.direct", CheckKind::Connectivity, note)
    } else {
        fail(
            "gateway.peers.direct",
            CheckKind::Connectivity,
            format!(
                "cross-provider traffic is being relayed through the platform via {}: {note}",
                gateways_relayed.join(", ")
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact output we saw while every other surface said healthy.
    const DISCONNECTED: &str = "\
OS: linux/amd64
Daemon version: 0.78.1
Management: Disconnected, reason: rpc error: code = NotFound desc = couldn't add peer: setup key is invalid
Signal: Disconnected
NetBird IP: N/A
Peers count: 0/0 Connected";

    const CONNECTED_ALONE: &str = "\
Management: Connected
NetBird IP: 100.93.27.247/16
Peers count: 0/0 Connected";

    const CONNECTED_WITH_PEERS: &str = "\
Management: Connected
NetBird IP: 100.93.27.247/16
Peers count: 2/2 Connected";

    #[test]
    fn a_disconnected_peer_fails_and_says_why() {
        let c = peer_connectivity(DISCONNECTED);
        assert_eq!(c.result, CheckResult::Fail);
        assert_eq!(c.kind, CheckKind::Connectivity);
        // The reason is the whole value: "setup key is invalid" and "no peer
        // auth method" need different fixes.
        assert!(c.detail.unwrap().contains("setup key is invalid"));
    }

    #[test]
    fn a_connected_peer_passes() {
        let c = peer_connectivity(CONNECTED_WITH_PEERS);
        assert_eq!(c.result, CheckResult::Pass);
    }

    /// Connected to the control plane and forwarding to nobody. This is the
    /// state that looks fine in every dashboard and carries no traffic.
    #[test]
    fn a_peer_alone_on_the_overlay_is_a_failure_not_a_pass() {
        assert_eq!(peer_connectivity(CONNECTED_ALONE).result, CheckResult::Pass);
        let reach = peer_reachability(CONNECTED_ALONE);
        assert_eq!(reach.result, CheckResult::Fail);
        assert!(reach.detail.unwrap().contains("forwarding to nobody"));
    }

    #[test]
    fn peers_present_means_reachable() {
        assert_eq!(peer_reachability(CONNECTED_WITH_PEERS).result, CheckResult::Pass);
    }

    /// Nothing to read is not a failure. A machine mid-boot has not broken.
    #[test]
    fn no_status_at_all_is_unknown_rather_than_broken() {
        assert_eq!(peer_reachability("").result, CheckResult::Unknown);
        // But a missing Management line *is* a failure of connectivity: the
        // client ran and could not say it was connected.
        assert_eq!(peer_connectivity("").result, CheckResult::Fail);
    }

    #[test]
    fn an_adapter_is_matched_exactly_not_by_prefix() {
        assert_eq!(adapter_presence("wt0", "lo eth0 wt0").result, CheckResult::Pass);
        assert_eq!(adapter_presence("wt0", "lo: eth0: wt0:").result, CheckResult::Pass);
        // `wt0` must not be satisfied by `wt00`, which is a different link.
        assert_eq!(adapter_presence("wt0", "lo eth0 wt00").result, CheckResult::Fail);
    }

    #[test]
    fn a_check_can_name_what_it_is_about() {
        let c = about(pass("gateway.vm", CheckKind::Presence, "vmid 103"), "gw-cc8d3ca7");
        assert_eq!(c.subject.as_deref(), Some("gw-cc8d3ca7"));
    }
}

#[cfg(test)]
mod peer_path_tests {
    use super::*;

    /// Real output, trimmed. Provider-to-provider is direct on the LAN; the
    /// laptop behind campus NAT relays; the platform's own relay peer relays by
    /// definition.
    const REAL: &str = "\
Peers detail:
 omnuv-relay-c4d90fd2.netbird.selfhosted:
  Status: Connected
  Connection type: Relayed
 onv-gw-55a24373.netbird.selfhosted:
  Status: Connected
  Connection type: P2P
  ICE candidate endpoints (Local/Remote): 10.200.99.1:51820/192.168.100.109:51820
 hermes.netbird.selfhosted:
  Status: Connected
  Connection type: Relayed
";

    #[test]
    fn a_relayed_laptop_is_not_a_fault() {
        let c = peer_paths(REAL);
        assert_eq!(c.result, CheckResult::Pass, "{:?}", c.detail);
        let d = c.detail.unwrap();
        assert!(d.contains("1 direct"), "{d}");
        assert!(d.contains("clients, which is expected"), "{d}");
    }

    /// The one that matters: a gateway reached through the relay means
    /// cross-provider buyer traffic is crossing the marketplace's own host —
    /// every byte twice, on the link Edge Rule 3 calls the most expensive in
    /// the system.
    #[test]
    fn a_relayed_gateway_is_a_fault_and_says_which() {
        let relayed_gw = REAL.replace(
            " onv-gw-55a24373.netbird.selfhosted:\n  Status: Connected\n  Connection type: P2P",
            " onv-gw-55a24373.netbird.selfhosted:\n  Status: Connected\n  Connection type: Relayed",
        );
        let c = peer_paths(&relayed_gw);
        assert_eq!(c.result, CheckResult::Fail);
        assert!(c.detail.unwrap().contains("onv-gw-55a24373"));
    }

    #[test]
    fn peers_and_their_paths_are_read_correctly() {
        let p = peers_in(REAL);
        assert_eq!(p.len(), 3);
        assert_eq!(p[1].name, "onv-gw-55a24373");
        assert!(!p[1].relayed);
        assert!(p[0].relayed && p[2].relayed);
    }

    /// Nothing to read is not a failure — a gateway still booting has not
    /// started relaying anything.
    #[test]
    fn no_detail_is_unknown() {
        assert_eq!(peer_paths("").result, CheckResult::Unknown);
        assert_eq!(peer_paths("Peers detail:").result, CheckResult::Unknown);
    }
}

// ---------------------------------------------------------------------------
// Links, from the overlay client's own JSON
// ---------------------------------------------------------------------------

/// What the gateway's overlay client says about itself and its peers.
///
/// The text form above answers yes/no questions — connected, relayed, adapter
/// present — and that was the strongest thing the map could draw: "both ends
/// report peers", which is a statement about paperwork. It survives a tunnel
/// that has not completed a handshake in an hour, and it cannot tell a direct
/// path from one relayed twice through the platform at 90 ms.
///
/// The JSON form carries the numbers. It is appended as a fourth section of the
/// same status file rather than replacing the text, so a gateway built before
/// this change keeps passing exactly the checks it passed yesterday and simply
/// reports no links — an upgrade that cannot regress what it does not touch.
///
/// Field names are NetBird's, verified against `client/status/status.go` at the
/// version this lab runs (0.78.1) rather than recalled: `netbirdIp`,
/// `connectionType`, `latency`, `lastWireguardHandshake`.
pub fn links_in(json: &str, gateway_id: &str, at_unix: u64) -> Vec<omnuv_protocol::LinkReport> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else { return Vec::new() };
    let Some(details) = v.get("peers").and_then(|p| p.get("details")).and_then(|d| d.as_array())
    else {
        return Vec::new();
    };
    details
        .iter()
        .filter_map(|p| {
            let peer = p.get("fqdn")?.as_str()?;
            Some(omnuv_protocol::LinkReport {
                gateway_id: gateway_id.to_string(),
                // The short name, as every other surface here spells it.
                peer: peer.split('.').next().unwrap_or(peer).to_string(),
                peer_address: p
                    .get("netbirdIp")
                    .and_then(|a| a.as_str())
                    .map(|a| a.split('/').next().unwrap_or(a).to_string()),
                relayed: p
                    .get("connectionType")
                    .and_then(|c| c.as_str())
                    .is_some_and(|c| c.eq_ignore_ascii_case("relayed")),
                rtt_ms: p.get("latency").and_then(latency_ms),
                last_handshake_unix: p
                    .get("lastWireguardHandshake")
                    .and_then(|h| h.as_str())
                    .and_then(rfc3339_unix),
                at_unix,
            })
        })
        .collect()
}

/// The gateway's own overlay address, which is *not* the address on its primary
/// NIC.
///
/// Until 11 September `overlay_address` was filled from the guest agent's first
/// IPv4 — the provider's LAN address. It looked entirely plausible, it was
/// never on the overlay, and it made the map draw an overlay link between two
/// addresses that could not reach each other that way.
pub fn overlay_address_in(json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let raw = v.get("netbirdIp")?.as_str()?;
    let addr = raw.split('/').next().unwrap_or(raw);
    (!addr.is_empty()).then(|| addr.to_string())
}

/// Go renders `time.Duration` as an integer of nanoseconds. Some builds render
/// it as `"41.2ms"`, so both are accepted and anything else is *not measured*
/// rather than zero — a link reported at 0 ms reads as instant, which is a
/// worse answer than no answer.
fn latency_ms(v: &serde_json::Value) -> Option<u32> {
    if let Some(ns) = v.as_u64() {
        return (ns > 0).then(|| (ns / 1_000_000).max(1) as u32);
    }
    let s = v.as_str()?;
    let (num, scale) = if let Some(n) = s.strip_suffix("ms") {
        (n, 1.0)
    } else if let Some(n) = s.strip_suffix("µs").or_else(|| s.strip_suffix("us")) {
        (n, 0.001)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1000.0)
    } else {
        return None;
    };
    let ms = num.parse::<f64>().ok()? * scale;
    (ms > 0.0).then(|| ms.round().max(1.0) as u32)
}

fn rfc3339_unix(s: &str) -> Option<u64> {
    // NetBird's zero time is a handshake that never happened, not one at the
    // dawn of the epoch.
    if s.starts_with("0001-01-01") {
        return None;
    }
    let t = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?;
    u64::try_from(t.unix_timestamp()).ok()
}

#[cfg(test)]
mod link_tests {
    use super::*;

    const STATUS: &str = r#"{
      "peers": {"total":2,"connected":2,"details":[
        {"fqdn":"onv-gw-abcd1234.netbird.selfhosted","netbirdIp":"100.93.1.5/16",
         "connectionType":"P2P","latency":4200000,
         "lastWireguardHandshake":"2026-09-11T10:00:00Z"},
        {"fqdn":"rmartins-laptop.netbird.selfhosted","netbirdIp":"100.93.9.9/16",
         "connectionType":"Relayed","latency":"41.2ms",
         "lastWireguardHandshake":"0001-01-01T00:00:00Z"}
      ]},
      "netbirdIp":"100.93.220.239/16"
    }"#;

    #[test]
    fn a_direct_gateway_and_a_relayed_client_are_told_apart() {
        let l = links_in(STATUS, "g1", 99);
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].peer, "onv-gw-abcd1234");
        assert!(!l[0].relayed);
        assert!(l[1].relayed);
        // Directional: both are what g1 sees.
        assert!(l.iter().all(|x| x.gateway_id == "g1" && x.at_unix == 99));
    }

    #[test]
    fn latency_is_read_in_both_shapes_go_emits() {
        let l = links_in(STATUS, "g1", 0);
        assert_eq!(l[0].rtt_ms, Some(4), "4.2 ms as nanoseconds");
        assert_eq!(l[1].rtt_ms, Some(41), "41.2ms as a string");
    }

    /// A sub-millisecond link is fast, not instant. Rounding it to zero would
    /// render as "0 ms", which reads as a broken measurement.
    #[test]
    fn a_very_fast_link_is_never_reported_as_instant() {
        let v = serde_json::json!(300_000u64); // 0.3 ms
        assert_eq!(latency_ms(&v), Some(1));
    }

    #[test]
    fn an_unmeasured_latency_stays_unmeasured() {
        assert_eq!(latency_ms(&serde_json::json!(0)), None);
        assert_eq!(latency_ms(&serde_json::json!("")), None);
        assert_eq!(latency_ms(&serde_json::json!(null)), None);
    }

    #[test]
    fn a_handshake_that_never_happened_is_not_a_handshake_in_the_year_one() {
        let l = links_in(STATUS, "g1", 0);
        assert!(l[0].last_handshake_unix.is_some());
        assert_eq!(l[1].last_handshake_unix, None);
    }

    #[test]
    fn the_gateways_own_address_comes_off_the_overlay_not_the_lan() {
        assert_eq!(overlay_address_in(STATUS).as_deref(), Some("100.93.220.239"));
    }

    /// A gateway built before this change writes three sections and no JSON.
    /// It must report no links, not fail.
    #[test]
    fn an_older_gateway_reports_no_links_rather_than_breaking() {
        assert!(links_in("", "g1", 0).is_empty());
        assert!(links_in("Peers detail:\n  none", "g1", 0).is_empty());
        assert_eq!(overlay_address_in("not json"), None);
    }
}
