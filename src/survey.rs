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
//! guest.unclaimed   fail      one per guest, subject = its key tag
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
    let wanted: Vec<(&str, String)> = desired
        .instances
        .iter()
        .map(|s| (crate::names::TAG_INSTANCE, crate::names::short_tag(&s.id)))
        .chain(
            desired
                .inference_workers
                .iter()
                .map(|s| (crate::names::TAG_WORKER, crate::names::short_tag(&s.id))),
        )
        .collect();

    let mut out = Vec::new();
    let (mut compared, mut older) = (0usize, 0usize);
    for g in guests {
        let tokens: Vec<&str> = g.tags.split(&[';', ','][..]).map(str::trim).collect();
        let claim = [crate::names::TAG_INSTANCE, crate::names::TAG_WORKER]
            .into_iter()
            .find(|c| tokens.contains(c));
        let Some(claim) = claim else {
            // An earlier generation's claim cannot be keyed against this
            // desired state. Counted and said, rather than compared wrongly.
            if crate::instance::is_legacy_marketplace_tag(&g.tags) {
                older += 1;
            }
            continue;
        };
        compared += 1;
        let asked_for = wanted
            .iter()
            .any(|(kind, key)| *kind == claim && tokens.contains(&key.as_str()));
        if !asked_for {
            let key = tokens
                .iter()
                .find(|t| t.starts_with("onv-") && t.len() == 16 && t[4..].bytes().all(|b| b.is_ascii_hexdigit()))
                .map(|t| t.to_string());
            out.push(SelfCheck {
                name: "guest.unclaimed".into(),
                kind: CheckKind::Presence,
                result: CheckResult::Fail,
                detail: Some(format!(
                    "VM {} on {} carries the {claim} claim, and Core's desired state names no such machine",
                    g.vmid, g.node
                )),
                subject: Some(key.unwrap_or_else(|| format!("vmid-{}", g.vmid))),
            });
        }
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
/// instance.cloud_init   fail   one per machine whose refresh failed, subject = its key tag
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
                    subject: Some(crate::names::short_tag(id)),
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
        ClaimedGuest { node: "pve1".into(), vmid, tags: tags.into() }
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
        assert_eq!(failed[0].subject.as_deref(), Some(crate::names::short_tag(GONE).as_str()));
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
            guest(100, &crate::names::tags(crate::names::TAG_INSTANCE, ASKED, Some("test"))),
            guest(101, &crate::names::tags(crate::names::TAG_INSTANCE, GONE, Some("test"))),
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
        let guests = [guest(200, &crate::names::tags(crate::names::TAG_WORKER, ASKED, None))];
        let found = checks(Ok(&guests), &desired(&[ASKED]));
        assert!(found.iter().any(|c| c.name == "guest.unclaimed"), "a worker was taken for an instance: {found:?}");
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
        let listing = |fail_second: bool| {
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
                _ => (404, serde_json::json!(null)),
            }
        };
        let mock = crate::pvemock::Mock::start(listing(false)).await;
        let guests = mock.client().guests().await.expect("the survey");
        let seen: Vec<(String, u32)> = guests.iter().map(|g| (g.node.clone(), g.vmid)).collect();
        assert_eq!(seen, [("pve1".into(), 100), ("pve1".into(), 101), ("pve2".into(), 200)]);
        assert_eq!(guests[1].tags, "", "a guest with no tags is listed, untagged");
        assert!(!mock.called("GET", "/nodes/pve3/qemu"), "an offline node was asked");

        let mock = crate::pvemock::Mock::start(listing(true)).await;
        assert!(mock.client().guests().await.is_err(), "a node that could not be listed was left out silently");
    }
}
