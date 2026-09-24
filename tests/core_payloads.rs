//! What this agent must be able to read, from the Core that is deployed now.
//!
//! The protocol crate has its own contract tests, and they prove the bytes.
//! This proves the other half the private repository's `docs/testing.md` asks
//! for under L2 — *last released agent against current Core* — by parsing those
//! bytes with the types **this** agent actually compiles against, which is a
//! different version of the crate and is the entire point.
//!
//! A contract test that generates its fixture from its own dependency proves
//! only that a library round-trips itself. These payloads come from elsewhere
//! and are checked in; see `tests/from-core/README.md`.
//!
//! **When the two versions are the same, this is a weaker test, and says so
//! (24 September 2026).** Core and this agent both pin v0.21.0 today. What
//! runs then is that a payload Core emitted on 14 September still parses with
//! this agent's types. That is backward compatibility, and worth keeping, but
//! it is not the version gap described above. The gap exists between Core
//! moving to a newer tag and this agent following it, and that is when the
//! payload has to be recaptured from Core and this test run.

use omnuv_protocol::{DesiredState, Lifecycle};

#[test]
fn this_agent_parses_what_core_sends() {
    for (name, body) in payloads() {
        let state: DesiredState = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("{name} does not parse with this agent's types: {e}"));

        assert!(
            state.protocol_version >= omnuv_protocol::MINIMUM_PROTOCOL_VERSION,
            "{name} announces protocol {}, below the floor this agent's crate \
             declares ({}) — the handshake would be refused before this mattered",
            state.protocol_version,
            omnuv_protocol::MINIMUM_PROTOCOL_VERSION
        );
        assert_eq!(state.instances.len(), 1, "{name} carries one machine");

        // The field is `intent` in Rust and `lifecycle` on the wire.
        //
        // **This test does not catch that field being renamed, and measuring
        // said so.** Renaming it in the fixture passes here, because the crate
        // this agent pins carries `alias = "intent"` and reads either name. The
        // agent that would actually break is one on protocol 5, which knows
        // only `lifecycle` — and protocol 5 is inside the supported floor, so
        // those agents are real. That case belongs to the protocol crate's
        // golden payloads, which are written from the v0.12.0 declarations and
        // do fail on the rename.
        //
        // What this file covers is the half those cannot: that the types this
        // agent *actually compiles against* parse bytes produced by a newer
        // crate. A renamed **value** does fail here, because an alias on the
        // field says nothing about the variants.
        assert_eq!(
            state.instances[0].intent,
            Lifecycle::Running,
            "{name}'s machine should be Running"
        );
        assert_eq!(state.instances[0].vcpus, 4);
        assert_eq!(state.instances[0].memory_mib, 16384);
    }
}

/// Every checked-in payload, with its name. Panics on an empty directory: a
/// contract test that silently exercises nothing is worse than one that fails,
/// because it reports success.
fn payloads() -> Vec<(String, String)> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/from-core");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("tests/from-core is readable") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        out.push((
            path.file_name().unwrap().to_string_lossy().into_owned(),
            std::fs::read_to_string(&path).expect("payload"),
        ));
    }
    assert!(!out.is_empty(), "tests/from-core holds no payloads, so this asserted nothing");
    out
}
