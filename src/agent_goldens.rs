//! **The goldens, read by this agent, from a v0.27 Core and a v0.28 Core**
//! (omnuv's modular design, A7).
//!
//! `tests/from-core/` holds what each Core writes, copied byte for byte from
//! where it is generated (`tests/from-core/README.md` names each source and
//! its digest):
//!
//! ```text
//! fakecore/         omnuv's fake Core, written by the v0.27.0 serializer
//! protocol-v0.27/   omnuv-protocol's goldens of what v0.27 peers send
//! protocol-v0.28/   the same with every v0.28.0 field present
//! ```
//!
//! Each Core-to-agent payload goes through the functions the agent itself
//! reads it with (`heard_handshake`, `heard_view`, `refusal_code`,
//! `refusal`), never a parallel parse. Each agent-to-Core message the agent
//! writes is read back with the **released v0.27.0 types** (`v027`), which
//! is what a Core that has not moved reads, and held to the v0.28 golden's
//! keys, which is what one that has moved expects.

use super::*;

fn golden(path: &str) -> String {
    let file = format!("{}/tests/from-core/{path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{file}: {e}"))
}

fn json(path: &str) -> serde_json::Value {
    serde_json::from_str(&golden(path)).unwrap_or_else(|e| panic!("{path} is not JSON: {e}"))
}

fn core() -> Core {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Core::new("https://api.omnuv.com", &omnuv_protocol::Redacted::from("t".to_string())).expect("a client")
}

/// The keys of a JSON object, sorted.
fn keys(v: &serde_json::Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
    k.sort();
    k
}

/// **Every view either Core writes is read, and read for what is new.** The
/// three Cores' views parse with this agent's types; each worker sent built
/// is known built through `heard_view`, from the v0.27 bytes (Core's own
/// `"built": true` beside the protocol's fields) and the v0.28 ones alike;
/// the settings a v0.28 Core sends are held, and none from a v0.27 one.
#[test]
fn every_cores_view_is_read_as_the_agent_reads_it() {
    for (path, settings) in [
        ("fakecore/desired_state_full.json", false),
        ("fakecore/desired_state_empty.json", false),
        ("protocol-v0.27/desired-state.json", false),
        ("protocol-v0.28/desired-state.json", true),
    ] {
        let view: DesiredState = serde_json::from_str(&golden(path)).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert!(speaks(view.protocol_version), "{path} is stamped {}, outside this agent's range", view.protocol_version);
        for i in &view.instances {
            assert_ne!(i.intent, Lifecycle::Unknown, "{path}: {} has a destination this agent does not know", i.id);
        }
        let core = core();
        core.heard_view(&view);
        let raw = json(path);
        for (n, w) in view.inference_workers.iter().enumerate() {
            let sent = raw["inference_workers"][n]["built"].as_bool().unwrap_or(false);
            let known = crate::poison::lock(&core.built, "built").built(view.version, &w.id);
            assert_eq!(known, (!view.unchanged).then_some(sent), "{path}: worker {} built", w.id);
        }
        let held = crate::poison::lock(&core.settings, "settings").clone();
        assert_eq!(held.is_some(), settings, "{path}: agent settings held {held:?}");
        let sent_hash = crate::settings::hash(held.as_ref(), std::time::Duration::from_secs(300));
        assert_eq!(sent_hash.is_some(), settings, "{path}: a settings hash for settings never sent");
    }
}

/// **The catalogue's family decides a template's shape** (`os_family`,
/// v0.28.0), and a catalogue that says none, a v0.27 Core's, leaves this
/// provider's own list deciding. The v0.28 golden's Windows image, which no
/// list here names, is held to the Windows shape; the v0.27 one's is not.
#[tokio::test]
async fn the_catalogues_family_decides_a_templates_shape() {
    let mock = crate::pvemock::Mock::start(|_, _, _| (404, serde_json::Value::Null)).await;
    let px = mock.client();
    for (path, windows) in [("protocol-v0.28/desired-state.json", true), ("protocol-v0.27/desired-state.json", false)] {
        let view: DesiredState = serde_json::from_str(&golden(path)).expect("a view");
        px.hear_catalogue(&view.images);
        let id = &view.images[0].id;
        let shape = px.template_shape(id);
        assert_eq!(shape == crate::images::TemplateShape::Windows, windows, "{path}: {id} held to {shape:?}");
    }
    // A family a newer Core adds reads as not said: the list decides.
    let mut newer = json("protocol-v0.28/desired-state.json");
    newer["images"][0]["os_family"] = serde_json::json!("plan9");
    let view: DesiredState = serde_json::from_value(newer).expect("an unknown family does not refuse the view");
    px.hear_catalogue(&view.images);
    assert_eq!(px.template_shape("windows-11-gaming"), crate::images::TemplateShape::Linux);
    let listed = mock.client().with_windows_images(["windows-11-gaming".to_string()].into());
    listed.hear_catalogue(&view.images);
    assert_eq!(listed.template_shape("windows-11-gaming"), crate::images::TemplateShape::Windows);
    // And the catalogue outranks the list, in both directions.
    let mut linux = json("protocol-v0.28/desired-state.json");
    linux["images"][0]["os_family"] = serde_json::json!("linux");
    listed.hear_catalogue(&serde_json::from_value::<DesiredState>(linux).expect("a view").images);
    assert_eq!(listed.template_shape("windows-11-gaming"), crate::images::TemplateShape::Linux);
}

/// **Every handshake answer is read as a handshake reads it**: the period,
/// the session, the report interval, and what Core serves, which only a
/// v0.28 Core says; so only there is a 404 from a served route an outage.
#[test]
fn every_cores_handshake_answer_is_read_as_the_handshake_reads_it() {
    for (path, session, served) in [
        ("protocol-v0.27/handshake-accepted.json", true, None),
        ("protocol-v0.27/handshake-accepted-plain.json", false, None),
        ("protocol-v0.28/handshake-accepted.json", true, Some(true)),
    ] {
        let core = core();
        let (secs, minted) = heard_handshake(&core, &json(path));
        assert_eq!(secs, 30, "{path}");
        assert_eq!(minted.is_some(), session, "{path}: session {minted:?}");
        assert!(core.report.said(), "{path}: the report period was not heard");
        assert_eq!(core.serves(omnuv_protocol::ROUTE_SCRUBS), served, "{path}");
        assert_eq!(core.serves(omnuv_protocol::ROUTE_HEARTBEAT), served, "{path}");
    }
}

/// **Every refusal body is read for its code, and decides by the table**:
/// a v0.27 Core's has none, and its 403 is refused as it always was; the
/// v0.28 golden's `admission_pending` waits; the fake's version refusal at
/// the handshake is final, as a 426 there always was.
#[test]
fn every_cores_refusal_is_read_for_its_code() {
    let means = |path: &str, route: &str, status: u16| {
        let code = refusal_code(golden(path).as_bytes());
        (code, refusal(&anyhow::Error::from(CoreAnswered { path: route.into(), status, code })))
    };
    assert_eq!(means("protocol-v0.27/refusal.json", "/provider/v1/desired-state?known=3", 403), (None, Refusal::Refused));
    assert_eq!(
        means("protocol-v0.28/refusal.json", "/provider/v1/desired-state?known=3", 403),
        (Some(omnuv_protocol::RefusalCode::AdmissionPending), Refusal::Wait)
    );
    assert_eq!(
        means("protocol-v0.28/refusal.json", HANDSHAKE, 403),
        (Some(omnuv_protocol::RefusalCode::AdmissionPending), Refusal::Wait)
    );
    assert_eq!(means("fakecore/version_refusal_body.json", HANDSHAKE, 426), (None, Refusal::Final));
}

/// The scrub exchange, as v0.27 Core writes it, read by this agent's types,
/// and the fake's artefact and frames by the protocol's.
#[test]
fn the_scrub_exchange_the_artefact_and_the_frames_are_read() {
    let wants: crate::scrub::Wants = serde_json::from_str(&golden("protocol-v0.27/scrubs-wants.json")).expect("wants");
    assert_eq!(wants.scrubs.len(), 1);
    let answer: crate::scrub::Answer = serde_json::from_str(&golden("protocol-v0.27/scrubs-answer.json")).expect("answer");
    assert_eq!(answer.results.len(), 2);
    let a: omnuv_protocol::ImageArtefact = serde_json::from_str(&golden("fakecore/image_artefact.json")).expect("artefact");
    assert_eq!(a.os_family, None, "a v0.27 artefact said a family");
    for f in [
        "frame_request", "frame_cancel", "frame_ping", "frame_reconcile", "frame_console_open", "frame_console_resize",
        "frame_console_data",
    ] {
        serde_json::from_str::<omnuv_protocol::TunnelFrame>(&golden(&format!("fakecore/{f}.json")))
            .unwrap_or_else(|e| panic!("{f}: {e}"));
    }
}

/// **The names this agent speaks are the contract's**: each header, route
/// and capability as `names.json` spells them, which is how Core spells
/// them. These were hand copies on both sides until v0.28.0.
#[test]
fn the_headers_routes_and_capabilities_are_the_contracts() {
    let names = json("protocol-v0.28/names.json");
    for (key, ours) in [
        ("session", crate::session::HEADER),
        ("run_lease", crate::lease::HEADER),
        ("restore", crate::restore::HEADER),
        ("restore_detected", crate::restore::DETECTED_HEADER),
        ("report_interval", crate::report::HEADER),
    ] {
        assert_eq!(names["headers"][key].as_str(), Some(ours), "header {key}");
    }
    assert_eq!(names["routes"]["scrubs"].as_str(), Some(crate::scrub::PATH));
    assert_eq!(names["routes"]["handshake"].as_str(), Some(HANDSHAKE));
    let mut contract: Vec<String> = serde_json::from_value(names["capabilities"].clone()).expect("capabilities");
    let mut ours: Vec<String> = crate::session::CAPABILITIES.iter().map(|c| c.to_string()).collect();
    contract.sort();
    ours.sort();
    assert_eq!(ours, contract, "this agent advertises capabilities the contract does not name, or misses one");
}

/// **What this agent says at its handshake, read by both Cores**: the
/// v0.28 golden's keys exactly, read by the v0.28 type with `refusal_codes`
/// set, and a superset of the v0.27 golden's, so a v0.27 Core finds every
/// key it reads.
#[test]
fn the_handshake_is_the_goldens_shape() {
    let ours = handshake_body(omnuv_protocol::RuntimeKind::Proxmox).expect("a handshake");
    assert_eq!(keys(&ours), keys(&json("protocol-v0.28/handshake.json")));
    let v27 = keys(&json("protocol-v0.27/handshake.json"));
    assert!(v27.iter().all(|k| ours.get(k).is_some()), "a key a v0.27 Core reads is missing: {ours}");
    let typed: omnuv_protocol::Handshake = serde_json::from_value(ours).expect("the v0.28 type");
    assert!(typed.refusal_codes, "the handshake does not say this agent reads refusal codes");
    assert_eq!(typed.drivers.compute, vec!["proxmox".to_string()]);
}

/// **The heartbeat, read by both Cores.** Before any view it says what it
/// always said and what is new without settings; after a v0.28 view it says
/// `settings_hash` too. A v0.27 Core reads every one with its own type; each
/// key, and each component's, is one the v0.28 golden has.
#[test]
fn the_heartbeat_is_read_by_both_cores() {
    let golden = json("protocol-v0.28/heartbeat.json");
    let settings: omnuv_protocol::AgentSettings =
        serde_json::from_value(json("protocol-v0.28/desired-state.json")["agent_settings"].clone()).expect("settings");
    for sent in [None, Some(&settings)] {
        let body = heartbeat_body("0123456789ab", sent, std::time::Duration::from_secs(300));
        let old: v027::Heartbeat = serde_json::from_value(body.clone()).expect("a v0.27 Core reads the heartbeat");
        assert_eq!(old.config_hash.as_deref(), Some("0123456789ab"));
        let new: omnuv_protocol::Heartbeat = serde_json::from_value(body.clone()).expect("a v0.28 Core reads it");
        assert_eq!(new.settings_hash.is_some(), sent.is_some(), "{body}");
        assert_eq!(new.components[0].name, "onv-provider");
        assert_eq!(new.components[0].config_hash.as_deref(), Some("0123456789ab"));
        for k in keys(&body) {
            assert!(golden.get(&k).is_some(), "{k} is not a key the v0.28 golden has");
        }
        for c in body["components"].as_array().expect("components") {
            for k in keys(c) {
                assert!(golden["components"][0].get(&k).is_some(), "component key {k} is not the golden's");
            }
        }
    }
}

/// **A typed report, read by both Cores**: every destroy outcome, the lost
/// words and the image refusal, typed as the words say and readable by a
/// v0.27 Core, which ignores the type and reads the words as it always has.
#[test]
fn a_typed_report_is_read_by_both_cores() {
    use crate::teardown::Gone;
    let residue = vec!["local-lvm:vm-123-disk-0".to_string(), "local:123/vm-123-cloudinit.qcow2".to_string()];
    let status = |message: String, outcome: Option<omnuv_protocol::StatusOutcome>, residue: Vec<String>| InstanceStatus {
        id: "55555555-5555-5555-5555-555555555555".into(),
        rebooted_token: None,
        state: InstanceState::Stopped,
        retryable: None,
        waiting_on: None,
        local_id: None,
        node: None,
        console_password_generation: None,
        private_ip: None,
        adapters: Vec::new(),
        diagnostics: None,
        message: Some(message),
        recipe_progress: None,
        ready_to_start: None,
        outcome,
        residue,
    };
    let mut cases: Vec<InstanceStatus> = [Gone::Proven, Gone::Residue(residue), Gone::NotYet("a listing".into())]
        .iter()
        .map(|g| {
            let (o, r) = crate::teardown::outcome(g);
            status(crate::teardown::said(g), o, r)
        })
        .collect();
    cases.push(status(crate::instance::LOST.into(), Some(omnuv_protocol::StatusOutcome::Lost), Vec::new()));
    let no_image = crate::instance::ImageNotOffered { image: "ubuntu-26.04".into() }.to_string();
    cases.push(status(no_image, Some(omnuv_protocol::StatusOutcome::ImageNotOffered), Vec::new()));
    assert_eq!(
        omnuv_protocol::StatusOutcome::from_worker_words(crate::worker::LOST_WORKER),
        Some((omnuv_protocol::StatusOutcome::Lost, Vec::new())),
        "a lost worker's words no longer say lost"
    );
    for s in cases {
        let words = s.message.clone().unwrap_or_default();
        assert_eq!(
            omnuv_protocol::StatusOutcome::from_instance_words(&words),
            s.outcome.map(|o| (o, s.residue.clone())),
            "the type and the words disagree: {words}"
        );
        let body = serde_json::to_value(&s).expect("a status");
        let old: v027::InstanceStatus = serde_json::from_value(body.clone()).expect("a v0.27 Core reads it");
        assert_eq!(old.message.as_deref(), Some(words.as_str()), "a v0.27 Core lost the words");
        let new: InstanceStatus = serde_json::from_value(body).expect("a v0.28 Core reads it");
        assert_eq!((new.outcome, new.residue), (s.outcome, s.residue));
    }
}
