//! **The agent settings Core sends, and what this agent says it applied**
//! (protocol v0.28.0, contract change 6: `DesiredState::agent_settings` and
//! `Heartbeat::settings_hash`).
//!
//! This agent applies **none** of them yet: applying them, each clamped to a
//! local bound with `None` keeping `agent.yaml`, is the next work package
//! (omnuv's modular design, A8). Until then it says so truthfully. The hash
//! it reports is the protocol's `AgentSettings::hash` of what it applied,
//! which is the empty set, so it differs from Core's hash of what it sent
//! whenever Core sent anything: exactly the answer the protocol defines for
//! "sent and not applied". Nothing is reported to a Core that sends no
//! settings, the answer for "sent none".

use omnuv_protocol::AgentSettings;

/// What this agent runs of the settings `sent`: nothing yet (A8 clamps and
/// applies each member here).
pub(crate) fn applied(_sent: &AgentSettings) -> AgentSettings {
    AgentSettings::default()
}

/// The heartbeat's `settings_hash`: the hash of what was applied of the
/// settings Core's last view sent, or `None` when it sent none.
pub(crate) fn hash(sent: Option<&AgentSettings>) -> Option<String> {
    sent.map(|s| applied(s).hash())
}

#[cfg(test)]
mod tests {
    use omnuv_protocol::AgentSettings;

    /// **A Core that sends none is told none; one that sends any is told
    /// that nothing was applied**, by the protocol's own hash, which differs
    /// from Core's hash of what it sent. An empty set sent is an empty set
    /// applied, and the two hashes agree.
    #[test]
    fn the_hash_says_what_was_applied_and_nothing_is_yet() {
        assert_eq!(super::hash(None), None, "a Core that sent no settings was answered");
        let sent = AgentSettings { heartbeat_interval_secs: Some(20), environment: Some("onv-test".into()), ..Default::default() };
        let said = super::hash(Some(&sent)).expect("a Core that sent settings is answered");
        assert_eq!(said, AgentSettings::default().hash(), "the hash is not of what was applied");
        assert_ne!(said, sent.hash(), "settings this agent does not apply were acknowledged as applied");
        assert_eq!(super::hash(Some(&AgentSettings::default())), Some(AgentSettings::default().hash()));
    }
}
