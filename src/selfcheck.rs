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
