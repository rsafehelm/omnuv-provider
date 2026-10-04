//! **Which claimed guests Core has no idea about (CORE-38).**
//!
//! The report iterates desired state and says so: a machine Core never asked
//! about cannot appear in it, and its absence from the report is not evidence
//! of anything. So a guest whose `instances` row vanished — a lost delete, a
//! teardown that dropped the row before the agent confirmed — kept running on
//! hardware nobody believed was in use, with its GPU, and nothing in the
//! estate compared the two sides.
//!
//! This is that comparison, from the side that can see the hypervisor. It
//! **reports and decides nothing**: a guest carrying our claim and absent from
//! desired state is a finding for a person, never a deletion. Removing it on
//! this evidence alone would turn one truncated desired-state response into
//! the loss of every machine on the provider.
//!
//! Three answers, on the checks channel the report already carries:
//!
//! ```text
//! guest.unclaimed   fail      one per key, subject = its key tag (the
//!                             hypervisor's handle, which Core's unknown_guests
//!                             and adopt-unknown.yml key on), naming every
//!                             unasked guest carrying it, and saying the
//!                             adoption refuses a key more than one carries;
//!                             compared by the whole id its stamp names,
//!                             never by the tag
//! guests.surveyed   pass      the listing worked; says how many were compared
//! guests.surveyed   unknown   the listing failed — could not look, which is
//!                             never the same as nothing there
//! ```

use omnuv_protocol::{CheckKind, CheckResult, DesiredState, SelfCheck};

/// One guest as the hypervisor lists it, reduced to what the comparison needs.
#[derive(Debug, Clone)]
pub struct ClaimedGuest {
    pub node: String,
    pub vmid: u32,
    pub tags: String,
    /// The first line of its description, read only for a guest carrying a
    /// claim: the clone's stamp, naming the whole id (`names::stamped`).
    pub stamp: Option<String>,
}

/// The claim a guest's tags carry, of the two this survey compares.
pub fn claim_of(tags: &str) -> Option<&'static str> {
    let tokens: Vec<&str> = tags.split(&[';', ','][..]).map(str::trim).collect();
    [crate::names::TAG_INSTANCE, crate::names::TAG_WORKER]
        .into_iter()
        .find(|c| tokens.contains(c))
}

/// The checks this survey contributes to a report.
pub fn checks(guests: Result<&[ClaimedGuest], String>, desired: &DesiredState) -> Vec<SelfCheck> {
    let guests = match guests {
        Ok(g) => g,
        Err(e) => {
            return vec![SelfCheck {
                name: "guests.surveyed".into(),
                kind: CheckKind::Presence,
                result: CheckResult::Unknown,
                detail: Some(format!("the guests could not be listed, so none was compared: {e}")),
                subject: None,
            }];
        }
    };
    // **By the whole id** (the assets-by-id audit of 3 October 2026): a
    // guest is asked for when its stamp names a machine Core asked for under
    // its claim. Twelve hex digits in a tag matched a twin as well — a guest
    // made for another id that shares them — and hid it from this survey.
    let wanted: Vec<String> = desired
        .instances
        .iter()
        .map(|s| crate::names::stamped(crate::names::TAG_INSTANCE, &s.id))
        .chain(
            desired
                .inference_workers
                .iter()
                .map(|s| crate::names::stamped(crate::names::TAG_WORKER, &s.id)),
        )
        .collect();

    // The key tag each guest carries (`names::short_tag`), when it carries one.
    fn key_of(tags: &str) -> Option<String> {
        tags.split(&[';', ','][..])
            .map(str::trim)
            .find(|t| t.starts_with("onv-") && t.len() == 16 && t[4..].bytes().all(|b| b.is_ascii_hexdigit()))
            .map(str::to_string)
    }

    let mut out = Vec::new();
    // One report per subject, in the order the guests were listed: Core keeps
    // one row per subject, so two checks under one key left one guest unseen.
    let mut reports: Vec<(String, Vec<String>)> = Vec::new();
    let (mut compared, mut older) = (0usize, 0usize);
    for g in guests {
        let Some(claim) = claim_of(&g.tags) else {
            // An earlier generation's claim cannot be keyed against this
            // desired state. Counted and said, rather than compared wrongly.
            if crate::instance::is_legacy_marketplace_tag(&g.tags) {
                older += 1;
            }
            continue;
        };
        compared += 1;
        // The stamp's words name the kind too ("Omnuv instance <id>"), so a
        // worker's stamp never matches an instance Core asked for.
        let asked_for = g.stamp.as_deref().is_some_and(|s| wanted.iter().any(|w| w == s));
        if !asked_for {
            let subject = key_of(&g.tags).unwrap_or_else(|| format!("vmid-{}", g.vmid));
            let line = format!(
                "VM {} on {} carries the {claim} claim, and Core's desired state names no such machine \
                 (its stamp reads {:?})",
                g.vmid,
                g.node,
                g.stamp.as_deref().unwrap_or("")
            );
            match reports.iter_mut().find(|(s, _)| *s == subject) {
                Some((_, lines)) => lines.push(line),
                None => reports.push((subject, vec![line])),
            }
        }
    }
    for (subject, lines) in reports {
        // **A shared key is refused, never adopted.** The key is twelve hex
        // digits of the id (`names::short_tag` says why it stays short), so
        // two machines can carry one. `adopt-unknown.yml` decides a guest by
        // this key and refuses one that more than one guest carries, asked
        // for or not; the report says so rather than invite it.
        let carriers: Vec<u32> =
            guests.iter().filter(|g| key_of(&g.tags).as_deref() == Some(subject.as_str())).map(|g| g.vmid).collect();
        let mut detail = lines.join("; ");
        if carriers.len() > 1 {
            detail.push_str(&format!(
                "; {} guests carry the key {subject} (VM {}), so adopt-unknown.yml refuses it: \
                 each is decided by its whole id, by a person",
                carriers.len(),
                carriers.iter().map(u32::to_string).collect::<Vec<_>>().join(", VM ")
            ));
        }
        out.push(SelfCheck {
            name: "guest.unclaimed".into(),
            kind: CheckKind::Presence,
            result: CheckResult::Fail,
            detail: Some(detail),
            subject: Some(subject),
        });
    }
    out.push(SelfCheck {
        name: "guests.surveyed".into(),
        kind: CheckKind::Presence,
        result: CheckResult::Pass,
        detail: Some(format!(
            "{compared} claimed guest(s) compared with desired state{}",
            if older > 0 {
                format!("; {older} carry an earlier generation's claim and were not compared")
            } else {
                String::new()
            }
        )),
        subject: None,
    });
    out
}

/// **What each machine's drive refresh did this pass (gap 4, 25 September
/// 2026).**
///
/// A machine that already exists has its generated cloud-init brought up to
/// date on every pass, and a failure there was printed and nothing else: it is
/// retried, so a transient one heals, and a lasting one lived only in the
/// agent's own journal where nobody was looking. It is a check now, on the
/// channel the report already carries — reported and deciding nothing, like
/// every other check here.
///
/// ```text
/// instance.cloud_init   fail   one per machine whose refresh failed, subject = its whole id
/// instances.refreshed   pass   how many were refreshed, said every pass
/// ```
///
/// Emptied by `drain` at the end of the pass that filled it, so the checks
/// describe that pass and a machine Core stopped asking about stops being
/// mentioned. Cloned with the driver, which is why the outcomes are behind an
/// `Arc`.
/// One machine's id, and why its refresh failed when it did.
type Refreshed = (String, Option<String>);

#[derive(Clone, Default)]
pub struct Refreshes {
    outcomes: std::sync::Arc<std::sync::Mutex<Vec<Refreshed>>>,
}

impl Refreshes {
    /// One machine's outcome: `Err` carries the failure as it was printed.
    pub fn record(&self, id: &str, outcome: Result<(), String>) {
        crate::poison::lock(&self.outcomes, "cloud-init refreshes")
            .push((id.to_string(), outcome.err()));
    }

    /// The checks this pass's refreshes contribute, and empties the store.
    pub fn drain(&self) -> Vec<SelfCheck> {
        let outcomes: Vec<Refreshed> =
            std::mem::take(&mut *crate::poison::lock(&self.outcomes, "cloud-init refreshes"));
        if outcomes.is_empty() {
            return Vec::new();
        }
        let failed = outcomes.iter().filter(|(_, e)| e.is_some()).count();
        let mut out: Vec<SelfCheck> = outcomes
            .iter()
            .filter_map(|(id, e)| {
                e.as_ref().map(|why| SelfCheck {
                    name: "instance.cloud_init".into(),
                    kind: CheckKind::Presence,
                    result: CheckResult::Fail,
                    detail: Some(format!(
                        "this machine's first-boot drive could not be brought up to date, \
                         so a generator change has not reached it: {why}"
                    )),
                    // The whole id, never twelve digits of it (the assets-by-id
                    // audit): Core links a subject that parses as a uuid to
                    // the resource it names.
                    subject: Some(id.to_string()),
                })
            })
            .collect();
        out.push(SelfCheck {
            name: "instances.refreshed".into(),
            kind: CheckKind::Presence,
            result: if failed == 0 { CheckResult::Pass } else { CheckResult::Fail },
            detail: Some(format!(
                "{} of {} machine(s) had their first-boot drive brought up to date",
                outcomes.len() - failed,
                outcomes.len()
            )),
            subject: None,
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Core's own wire shape, from the fixture the contract tests use, with
    /// its instances replaced by the ids a test names.
    fn desired(instances: &[&str]) -> DesiredState {
        let mut d: DesiredState =
            serde_json::from_str(include_str!("../tests/from-core/desired-state.json")).expect("the fixture");
        let template = d.instances[0].clone();
        d.inference_workers.clear();
        d.instances = instances
            .iter()
            .map(|id| {
                let mut spec = template.clone();
                spec.id = id.to_string();
                spec
            })
            .collect();
        d
    }

    fn guest(vmid: u32, tags: &str) -> ClaimedGuest {
        ClaimedGuest { node: "pve1".into(), vmid, tags: tags.into(), stamp: None }
    }

    /// A guest as a clone for `id` leaves it: the claim's tags and its stamp.
    fn made_for(vmid: u32, claim: &str, id: &str) -> ClaimedGuest {
        ClaimedGuest { stamp: Some(crate::names::stamped(claim, id)), ..guest(vmid, &crate::names::tags(claim, id, Some("test"))) }
    }

    /// **Both directions** (gap 4). A pass where every drive refresh worked
    /// says so and names no machine; one where a refresh failed says which.
    /// A pass that refreshed nothing says nothing, rather than a pass with
    /// nothing wrong: this is a check that must not read as running when it
    /// is not.
    #[test]
    fn a_refresh_is_reported_both_ways() {
        let store = Refreshes::default();
        assert!(store.drain().is_empty(), "a pass with no machines invented a check");

        store.record(ASKED, Ok(()));
        let green = store.drain();
        assert_eq!(green.len(), 1, "{green:?}");
        assert_eq!(green[0].name, "instances.refreshed");
        assert_eq!(green[0].result, CheckResult::Pass);
        assert!(green[0].detail.as_deref().unwrap().contains("1 of 1"));

        store.record(ASKED, Ok(()));
        store.record(GONE, Err("the hypervisor said no".into()));
        let red = store.drain();
        let failed: Vec<_> = red.iter().filter(|c| c.name == "instance.cloud_init").collect();
        assert_eq!(failed.len(), 1, "{red:?}");
        assert_eq!(failed[0].subject.as_deref(), Some(GONE), "the subject is not the whole id");
        assert!(failed[0].detail.as_deref().unwrap().contains("the hypervisor said no"));
        let summary = red.iter().find(|c| c.name == "instances.refreshed").expect("a summary");
        assert_eq!(summary.result, CheckResult::Fail);
        assert!(summary.detail.as_deref().unwrap().contains("1 of 2"));
        assert!(store.drain().is_empty(), "the store was not emptied by the pass that read it");
    }

    const ASKED: &str = "3f2a1b4c-5d6e-4f70-8192-a3b4c5d6e7f8";
    const GONE: &str = "0a0b0c0d-0e0f-4011-8213-141516171819";

    /// **Both directions.** A guest Core asked about is not reported; one it did
    /// not is, by its key; and nobody else's guest is ours to mention.
    #[test]
    fn a_claimed_guest_core_did_not_ask_about_is_reported_and_nothing_else_is() {
        let guests = [
            made_for(100, crate::names::TAG_INSTANCE, ASKED),
            made_for(101, crate::names::TAG_INSTANCE, GONE),
            guest(102, "onv-test"),            // an environment tag is not a claim
            guest(103, ""),                    // the provider's own
            guest(104, "onv-dev;omnuv-lab"),   // a build rig
        ];
        let found = checks(Ok(&guests), &desired(&[ASKED]));
        let unclaimed: Vec<_> = found.iter().filter(|c| c.name == "guest.unclaimed").collect();
        assert_eq!(unclaimed.len(), 1, "{found:?}");
        assert_eq!(unclaimed[0].result, CheckResult::Fail);
        assert_eq!(unclaimed[0].subject.as_deref(), Some(crate::names::short_tag(GONE).as_str()));
        assert!(unclaimed[0].detail.as_deref().unwrap().contains("VM 101"));
        let surveyed = found.iter().find(|c| c.name == "guests.surveyed").expect("a summary");
        assert_eq!(surveyed.result, CheckResult::Pass);
        assert!(surveyed.detail.as_deref().unwrap().starts_with("2 claimed"), "{surveyed:?}");
    }

    /// A worker's claim is keyed against workers, not instances: the same key
    /// under the other claim is not the machine Core asked for.
    #[test]
    fn a_claim_is_matched_by_its_kind_as_well_as_its_key() {
        let guests = [made_for(200, crate::names::TAG_WORKER, ASKED)];
        let found = checks(Ok(&guests), &desired(&[ASKED]));
        assert!(found.iter().any(|c| c.name == "guest.unclaimed"), "a worker was taken for an instance: {found:?}");
        // And an instance's tags over a worker's stamp of the same id.
        let crossed = [ClaimedGuest { stamp: Some(crate::names::stamped(crate::names::TAG_WORKER, ASKED)),
                                      ..made_for(201, crate::names::TAG_INSTANCE, ASKED) }];
        let found = checks(Ok(&crossed), &desired(&[ASKED]));
        assert!(found.iter().any(|c| c.name == "guest.unclaimed"), "a worker's stamp was taken for an instance: {found:?}");
    }

    /// **A twin is not the machine Core asked for** (the assets-by-id audit of
    /// 3 October 2026). `TWIN` shares `ASKED`'s first twelve hex digits, so
    /// its guest carries the same tag; only the stamp tells them apart. A
    /// guest whose stamp is missing proves nothing and is reported too.
    #[test]
    fn a_guest_is_asked_for_by_its_whole_id_not_its_tag() {
        const TWIN: &str = "3f2a1b4c-5d6e-4fff-8fff-ffffffffffff";
        assert_eq!(crate::names::short_tag(TWIN), crate::names::short_tag(ASKED), "the fixture must share the tag");
        let guests = [
            made_for(100, crate::names::TAG_INSTANCE, ASKED),
            made_for(101, crate::names::TAG_INSTANCE, TWIN),
            ClaimedGuest { stamp: None, ..made_for(102, crate::names::TAG_INSTANCE, ASKED) },
        ];
        let found = checks(Ok(&guests), &desired(&[ASKED]));
        // All three carry one key, so the two not asked for are one report.
        let unclaimed: Vec<_> = found.iter().filter(|c| c.name == "guest.unclaimed").collect();
        assert_eq!(unclaimed.len(), 1, "{found:?}");
        let detail = unclaimed[0].detail.as_deref().unwrap();
        assert!(detail.contains("VM 101 on") && detail.contains("VM 102 on"), "{detail:?}");
        assert!(!detail.contains("VM 100 on"), "the machine Core asked for was reported: {detail:?}");
        assert!(detail.contains(TWIN), "the twin's report does not name the id it carries");
    }

    /// **One key, one report, naming every guest that carries it** (the
    /// assets-by-id audit of 3 October 2026). The subject is the twelve-hex
    /// key tag, and Core keeps one row per subject: two unclaimed guests
    /// sharing it, reported as two checks, became one row naming whichever
    /// came last, so one machine of the two hid. And a shared key is not a
    /// handle `adopt-unknown.yml` may decide by: it refuses a tag more than
    /// one guest carries, and the report says so rather than invite it.
    #[test]
    fn guests_sharing_a_key_are_one_report_that_names_them_all_and_refuses_adoption() {
        const TWIN: &str = "0a0b0c0d-0e0f-4fff-8fff-ffffffffffff";
        assert_eq!(crate::names::short_tag(TWIN), crate::names::short_tag(GONE), "the fixture must share the tag");
        let guests = [
            made_for(101, crate::names::TAG_INSTANCE, GONE),
            made_for(102, crate::names::TAG_INSTANCE, TWIN),
            made_for(103, crate::names::TAG_INSTANCE, ASKED),
        ];
        let found = checks(Ok(&guests), &desired(&[ASKED]));
        let unclaimed: Vec<_> = found.iter().filter(|c| c.name == "guest.unclaimed").collect();
        assert_eq!(unclaimed.len(), 1, "one key reported more than once, so Core keeps one of them: {found:?}");
        let detail = unclaimed[0].detail.as_deref().unwrap();
        assert_eq!(unclaimed[0].subject.as_deref(), Some(crate::names::short_tag(GONE).as_str()));
        for needle in ["VM 101", "VM 102", GONE, TWIN, "refuses"] {
            assert!(detail.contains(needle), "{needle:?} missing from {detail:?}");
        }
        // A key only one guest carries reads as it always did.
        let lone = checks(Ok(&guests[..1]), &desired(&[ASKED]));
        let lone = lone.iter().find(|c| c.name == "guest.unclaimed").unwrap().detail.as_deref().unwrap();
        assert!(!lone.contains("refuses"), "{lone:?}");
    }

    /// **Could not look is not nothing there.** A failed listing yields one
    /// `unknown`, and no `pass` that would read as a clean survey.
    #[test]
    fn a_listing_that_failed_says_so() {
        let found = checks(Err("403 Permission check failed".into()), &desired(&[ASKED]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].result, CheckResult::Unknown);
        assert!(found[0].detail.as_deref().unwrap().contains("could not be listed"));
    }

    /// An earlier generation's claim is counted and said, not compared wrongly
    /// and not silently dropped.
    #[test]
    fn an_older_claim_is_counted_rather_than_guessed_at() {
        let guests = [guest(300, "omnuv-instance;omnuv-3f2a1b4c5d6e")];
        let found = checks(Ok(&guests), &desired(&[]));
        assert!(!found.iter().any(|c| c.name == "guest.unclaimed"), "{found:?}");
        let surveyed = found.iter().find(|c| c.name == "guests.surveyed").unwrap();
        assert!(surveyed.detail.as_deref().unwrap().contains("1 carry an earlier generation's claim"));
    }

    /// **The listing, against the Proxmox API's own shape.** Every guest on
    /// every online node, with its tags — and one node that cannot be listed
    /// fails the whole survey, because four nodes out of five would read as a
    /// clean pass.
    #[tokio::test]
    async fn the_survey_covers_every_node_or_says_it_could_not() {
        let listing = |fail_second: bool, unreadable_stamp: bool| {
            move |method: &str, path: &str, _: &str| match (method, path) {
                ("GET", "/nodes") => (200, serde_json::json!([
                    {"node": "pve1", "status": "online"},
                    {"node": "pve2", "status": "online"},
                    {"node": "pve3", "status": "offline"},
                ])),
                ("GET", "/nodes/pve1/qemu") => (200, serde_json::json!([
                    {"vmid": 100, "status": "running", "tags": "onv-instance;onv-0a0b0c0d0e0f"},
                    {"vmid": 101, "status": "stopped"},
                ])),
                ("GET", "/nodes/pve2/qemu") if fail_second => (403, serde_json::json!(null)),
                ("GET", "/nodes/pve2/qemu") => (200, serde_json::json!([
                    {"vmid": 200, "status": "running", "tags": "onv-worker;onv-111122223333"},
                ])),
                ("GET", "/nodes/pve1/qemu/100/config") => (200, serde_json::json!({
                    "description": "Omnuv instance 0a0b0c0d-0e0f-4011-8213-141516171819\nManaged by onv-provider. Do not edit."})),
                ("GET", "/nodes/pve2/qemu/200/config") if unreadable_stamp => (500, serde_json::json!(null)),
                ("GET", "/nodes/pve2/qemu/200/config") => (200, serde_json::json!({})),
                _ => (404, serde_json::json!(null)),
            }
        };
        let mock = crate::pvemock::Mock::start(listing(false, false)).await;
        let guests = mock.client().guests().await.expect("the survey");
        let seen: Vec<(String, u32)> = guests.iter().map(|g| (g.node.clone(), g.vmid)).collect();
        assert_eq!(seen, [("pve1".into(), 100), ("pve1".into(), 101), ("pve2".into(), 200)]);
        assert_eq!(guests[1].tags, "", "a guest with no tags is listed, untagged");
        assert_eq!(guests[0].stamp.as_deref(), Some("Omnuv instance 0a0b0c0d-0e0f-4011-8213-141516171819"));
        assert_eq!(guests[2].stamp, None, "a claimed guest with no description has no stamp");
        assert!(!mock.called("GET", "/nodes/pve1/qemu/101/config"), "an unclaimed guest's configuration was read");
        assert!(!mock.called("GET", "/nodes/pve3/qemu"), "an offline node was asked");

        let mock = crate::pvemock::Mock::start(listing(true, false)).await;
        assert!(mock.client().guests().await.is_err(), "a node that could not be listed was left out silently");

        let mock = crate::pvemock::Mock::start(listing(false, true)).await;
        assert!(mock.client().guests().await.is_err(), "a claimed guest whose stamp could not be read was compared anyway");
    }
}
