//! **This agent's hold on its provider** (lifecycle phase 7, RC12).
//!
//! An agent authenticated with its provider's bearer token and nothing else,
//! so two agents holding one token — a copied configuration, an agent moved to
//! a new host while the old one still ran — both fetched the view and both
//! acted on it: two clones of one machine, a destroy racing a start (the red
//! team's H7, "two agents take turns as newest").
//!
//! Now the handshake advertises what this agent can do ([`CAPABILITIES`]) and
//! Core answers with a session, which every later call carries in
//! [`HEADER`]. Core refuses a second agent's handshake while this one is heard
//! (409), and refuses this one for good once a later handshake superseded it
//! (409 on an ordinary call): the agent then stops, because "superseded is
//! final" (Part II §5.1).
//!
//! **Nothing here is Core's to rely on unless Core minted it.** A Core that
//! predates sessions, or runs with them switched off, answers the handshake
//! without one; this agent then sends no header and behaves as it always did.
//! That is the half of "every agent upgrades before its provider changes
//! behaviour" this side owns.

use std::sync::{Arc, RwLock};

/// The session Core minted at the last handshake, or none. Shared by every
/// clone of the Core client and by the tunnel, so a re-handshake reaches all
/// of them at once.
pub type Session = Arc<RwLock<Option<String>>>;

/// The header a session travels in: Core's `provider_api::SESSION_HEADER`.
pub const HEADER: &str = "onv-session";

/// What this agent advertises at its handshake: Core's
/// `provider_api::CAPABILITIES`, as far as this build has them.
///
/// ```text
/// session        this agent holds its provider under a session and stops
///                when superseded
/// proven-delete  "deleted" is said one complete listing after the destroy,
///                and a volume that stayed is reported as a residue
///                (`teardown`)
/// ```
pub const CAPABILITIES: &[&str] = &["session", "proven-delete"];

/// The session in force, if any.
pub fn current(session: &Session) -> Option<String> {
    session.read().unwrap_or_else(|p| p.into_inner()).clone()
}

/// What the handshake's answer said: a session, or none from a Core that
/// mints none. Replaces whatever was held, so an answer without one clears it.
pub fn take(session: &Session, answer: &serde_json::Value) -> Option<String> {
    let minted = answer.get("session").and_then(|s| s.as_str()).map(str::to_string);
    *session.write().unwrap_or_else(|p| p.into_inner()) = minted.clone();
    minted
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Core that minted a session is answered with it; one that minted none
    /// — an older Core, or sessions switched off — leaves nothing to send,
    /// even when an earlier handshake had one.
    #[test]
    fn a_session_is_held_only_as_core_answered_it() {
        let s: Session = Default::default();
        assert_eq!(take(&s, &serde_json::json!({"provider_id": "p", "session": "abc"})), Some("abc".into()));
        assert_eq!(current(&s).as_deref(), Some("abc"));
        assert_eq!(take(&s, &serde_json::json!({"provider_id": "p"})), None);
        assert_eq!(current(&s), None, "a Core that minted nothing left an old session to send");
    }
}
