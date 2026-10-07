//! **The agent settings Core sends, and what this agent applies of them**
//! (protocol v0.28.0, contract change 6: `DesiredState::agent_settings` and
//! `Heartbeat::settings_hash`; omnuv's modular design, A8).
//!
//! Core sends, on every view, the members its settings ledger holds for its
//! agents. This agent applies the one it runs, the heartbeat interval, each
//! clamped to its own bounds (5s up to `timings.heartbeatCeiling`); a member
//! it does not run, or one Core left out, keeps this agent's own file. The
//! heartbeat answers with the protocol's `AgentSettings::hash` of what it
//! applied: Core's hash of what it sent exactly when nothing was clamped and
//! every member was one this agent runs, and a different hash, truthfully,
//! otherwise. Nothing is reported to a Core that sends no settings.

use std::time::Duration;

use omnuv_protocol::AgentSettings;

/// The shortest heartbeat interval taken from Core: Core's own floor.
pub(crate) const HEARTBEAT_FLOOR: Duration = Duration::from_secs(5);

/// What this agent runs of the settings `sent`, under its `ceiling`.
pub(crate) fn applied(sent: &AgentSettings, ceiling: Duration) -> AgentSettings {
    AgentSettings {
        heartbeat_interval_secs: sent
            .heartbeat_interval_secs
            .map(|s| s.clamp(HEARTBEAT_FLOOR.as_secs(), ceiling.as_secs().max(HEARTBEAT_FLOOR.as_secs()))),
        ..Default::default()
    }
}

/// The heartbeat's `settings_hash`: the hash of what was applied of the
/// settings Core's last view sent, or `None` when it sent none.
pub(crate) fn hash(sent: Option<&AgentSettings>, ceiling: Duration) -> Option<String> {
    sent.map(|s| applied(s, ceiling).hash())
}

/// The interval the heartbeat runs at, and, when Core's value was clamped,
/// what Core sent: Core's settings when its view carried one, else the
/// handshake's (this agent's own, for a Core before A8).
pub(crate) fn heartbeat(sent: Option<&AgentSettings>, ceiling: Duration, handshake: Duration) -> (Duration, Option<u64>) {
    match sent.and_then(|s| s.heartbeat_interval_secs) {
        Some(asked) => {
            let ran = applied(&AgentSettings { heartbeat_interval_secs: Some(asked), ..Default::default() }, ceiling)
                .heartbeat_interval_secs
                .unwrap_or(asked);
            (Duration::from_secs(ran), (ran != asked).then_some(asked))
        }
        None => (handshake, None),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use omnuv_protocol::AgentSettings;

    const CEILING: Duration = Duration::from_secs(300);

    fn sent(hb: u64) -> AgentSettings {
        AgentSettings { heartbeat_interval_secs: Some(hb), ..Default::default() }
    }

    /// **What was applied is what was sent, inside the bounds**, and the
    /// hash says so: equal to Core's hash of what it sent.
    #[test]
    fn a_heartbeat_inside_the_bounds_is_applied_and_its_hash_is_cores() {
        assert_eq!(super::hash(None, CEILING), None, "a Core that sent no settings was answered");
        assert_eq!(super::hash(Some(&sent(20)), CEILING), Some(sent(20).hash()));
        assert_eq!(super::heartbeat(Some(&sent(20)), CEILING, Duration::from_secs(30)), (Duration::from_secs(20), None));
        assert_eq!(super::heartbeat(None, CEILING, Duration::from_secs(30)), (Duration::from_secs(30), None));
    }

    /// **Out of bounds, clamped, and said**: the heartbeat runs at the
    /// bound, the clamp is returned for the log, and the hash is of the
    /// clamped value, so it differs from Core's.
    #[test]
    fn a_heartbeat_out_of_bounds_is_clamped_and_its_hash_says_so() {
        let low = Duration::from_secs(6);
        assert_eq!(super::heartbeat(Some(&sent(7)), low, Duration::from_secs(30)), (Duration::from_secs(6), Some(7)));
        let said = super::hash(Some(&sent(7)), low).unwrap();
        assert_eq!(said, sent(6).hash());
        assert_ne!(said, sent(7).hash(), "a clamped value was acknowledged as Core's");
        assert_eq!(super::heartbeat(Some(&sent(1)), CEILING, Duration::from_secs(30)), (Duration::from_secs(5), Some(1)));
    }

    /// **A member this agent does not run is not acknowledged**: Core's hash
    /// of a set carrying one differs from this agent's.
    #[test]
    fn a_member_not_run_here_is_not_acknowledged() {
        let more = AgentSettings { heartbeat_interval_secs: Some(20), environment: Some("onv-test".into()), ..Default::default() };
        assert_eq!(super::hash(Some(&more), CEILING), Some(sent(20).hash()));
        assert_ne!(super::hash(Some(&more), CEILING), Some(more.hash()));
    }
}
