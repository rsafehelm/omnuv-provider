//! **A card that held a started tenancy is scrubbed before it is sold again**
//! (lifecycle phase 9: RC7, TD5 and D11 of omnuv's
//! `docs/reports/2026-09-26-allocation-to-teardown.html`; Core's `scrubs.rs`
//! and migration 0230).
//!
//! Core holds such a card in `scrubbing` and names it here, with its node, the
//! scrub image for its model and an attempt number. For each, this agent:
//!
//! ```text
//! clone     the scrub image's template, into the marketplace's pool, stamped
//!           "Omnuv card scrub <id>" and tagged onv-scrub, with the card passed
//!           through (its mapping, as a worker's), no NIC, and a small slice
//! start     through the start gate (S3): nothing on the node may hold a device
//!           of the card's IOMMU group
//! read      /run/onv/scrub.json through the guest agent (VM.GuestAgent.FileRead,
//!           one known file, as the recipe and workload reports), each pass,
//!           until the program says clean or failed, the guest stops, or its
//!           uptime passes timings.scrubGuestDeadline
//! remove    stop it, and destroy it with its own disks only (Client::destroy)
//! report    POST /provider/v1/scrubs: clean or failed, for (scrub, attempt),
//!           with what the program measured. Only after the guest is gone, so
//!           the card Core puts back on sale is free when it does
//! ```
//!
//! **Its own routes, not the view**, and so no protocol change: the scrub is
//! not a buyer's machine. The shapes are pinned against Core's by a test on
//! each side (`the_wire_is_cores` here, `the_wire_is_the_agents` there) until
//! the protocol carries them.
//!
//! **Level-triggered.** Core lists every scrub nobody has reported, on every
//! ask; an outcome is kept here until Core has answered for it, and reported
//! again until then. A scrub guest of an attempt Core no longer lists, or of a
//! scrub it no longer lists at all, is removed: it carries the scrub's whole
//! claim, in the marketplace's pool, and nothing else wants it. Only on a list
//! Core actually answered: a failed ask removes nothing.
//!
//! **What an agent restart costs.** Outcomes are held in memory. One read and
//! not yet acknowledged when the agent stops is lost with it, and the scrub is
//! simply run again on the next pass: the card is held throughout, so a lost
//! outcome costs a pass, never a sale.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// **What this agent advertises when it can scrub a card**: Core's
/// `scrubs::CAPABILITY`.
pub const CAPABILITY: &str = "card-scrub";

/// The claim a scrub guest carries, and the word its stamp uses.
pub const TAG: &str = onv_agent_lib::names::TAG_SCRUB;

/// Where the scrub program leaves its verdict in the guest (`onv-scrub.c`).
pub const REPORT: &str = "/run/onv/scrub.json";

/// Core's routes, both ways.
pub const PATH: &str = "/provider/v1/scrubs";

/// One scrub Core wants run: Core's `scrubs::Wanted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wanted {
    pub id: String,
    pub attempt: i32,
    /// The card, as this agent's inventory named it.
    pub card: String,
    pub node: String,
    pub model: String,
    /// The scrub image's catalogue id.
    pub image: String,
}

#[derive(Debug, Deserialize)]
pub struct Wants {
    #[serde(default)]
    pub scrubs: Vec<Wanted>,
}

/// The typed outcome of one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Clean,
    Failed,
}

/// One attempt's outcome, as this agent reports it: Core's `scrubs::Said`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Said {
    pub id: String,
    pub attempt: i32,
    pub outcome: Outcome,
    pub detail: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct Report<'a> {
    pub scrubs: &'a [Said],
}

/// What Core made of one reported attempt: Core's `scrubs::Recorded`.
#[derive(Debug, Clone, Deserialize)]
pub struct Recorded {
    pub id: String,
    pub attempt: i32,
    pub result: String,
}

#[derive(Debug, Deserialize)]
pub struct Answer {
    #[serde(default)]
    pub results: Vec<Recorded>,
}

/// Outcomes read and not yet answered for by Core, by (scrub, attempt).
#[derive(Debug, Default)]
pub struct Held(pub BTreeMap<(String, i32), Said>);

impl Held {
    /// Forgets every outcome Core has concluded on. `held` (a restore holds
    /// the provider) is the one word that keeps it: Core recorded nothing.
    pub fn answered(&mut self, answer: &[Recorded]) {
        for r in answer.iter().filter(|r| r.result != "held") {
            self.0.remove(&(r.id.clone(), r.attempt));
        }
    }
}

/// What the scrub program writes (`deployment/ansible/files/scrub/onv-scrub.c`).
#[derive(Debug, Clone, Deserialize)]
pub struct GuestReport {
    pub status: String,
    #[serde(default)]
    pub stage: String,
    #[serde(default)]
    pub uptime_s: u64,
    #[serde(default)]
    pub cards: u64,
    #[serde(default)]
    pub total_mib: u64,
    #[serde(default)]
    pub covered_mib: u64,
    #[serde(default)]
    pub residue_mib: u64,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub seconds: f64,
    #[serde(default)]
    pub persistent: serde_json::Value,
    #[serde(default)]
    pub detail: String,
}

impl GuestReport {
    fn measured(&self) -> serde_json::Value {
        serde_json::json!({
            "stage": self.stage,
            "uptime_s": self.uptime_s,
            "cards": self.cards,
            "total_mib": self.total_mib,
            "covered_mib": self.covered_mib,
            "residue_mib": self.residue_mib,
            "verified": self.verified,
            "seconds": self.seconds,
            "persistent": self.persistent,
            "detail": self.detail,
        })
    }
}

/// What one look at a scrub guest concludes.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// Still scrubbing, within its deadline: look again next pass.
    Wait,
    /// Finished, one way or the other: remove the guest, then report.
    Done(Outcome, serde_json::Value),
}

/// **One look at a scrub guest**: what its program said, whether it runs, and
/// how long it has been up. The program's word is the verdict; the agent adds
/// only the two failures the program cannot say: it stopped first, or it ran
/// past `timings.scrubGuestDeadline` (by the guest's own uptime, so an agent
/// restart neither extends nor shortens it).
pub fn step(report: Option<&GuestReport>, running: bool, uptime_s: u64, deadline: onv_agent_lib::dur::Dur) -> Step {
    match report.map(|r| r.status.as_str()) {
        Some("clean") => return Step::Done(Outcome::Clean, report.map(GuestReport::measured).unwrap_or_default()),
        Some("failed") => return Step::Done(Outcome::Failed, report.map(GuestReport::measured).unwrap_or_default()),
        _ => {}
    }
    let mut detail = report.map(GuestReport::measured).unwrap_or_else(|| serde_json::json!({}));
    if !running {
        detail["detail"] = "the scrub guest stopped before its program reported".into();
        return Step::Done(Outcome::Failed, detail);
    }
    if uptime_s >= deadline.as_secs() {
        detail["detail"] = format!(
            "the scrub guest ran {uptime_s}s without a verdict, past timings.scrubGuestDeadline ({deadline})"
        )
        .into();
        return Step::Done(Outcome::Failed, detail);
    }
    Step::Wait
}

/// The attempt a scrub guest was made for: the line `attempt <n>` after its
/// stamp.
pub fn attempt_of(config: &serde_json::Value) -> Option<i32> {
    config
        .get("description")
        .and_then(|d| d.as_str())
        .and_then(|d| d.lines().skip(1).find_map(|l| l.trim().strip_prefix("attempt ")))
        .and_then(|n| n.trim().parse().ok())
}

/// The scrub a guest's stamp names: the whole id on its first line.
pub fn scrub_of(config: &serde_json::Value) -> Option<String> {
    let first = config.get("description").and_then(|d| d.as_str()).and_then(|d| d.lines().next())?;
    first.strip_prefix(&onv_agent_lib::names::stamped(TAG, "")).map(str::to_string).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use onv_agent_lib::dur::Dur;

    fn report(status: &str) -> GuestReport {
        serde_json::from_value(serde_json::json!({
            "status": status, "stage": "done", "uptime_s": 95, "cards": 1, "total_mib": 24576,
            "covered_mib": 24200, "residue_mib": 18000, "verified": status == "clean", "seconds": 41.5,
            "persistent": {"vbios": "94.02.42.00.01", "inforom": "G001.0000.03.03", "ecc": "N/A", "serial": ""},
            "detail": ""
        }))
        .unwrap()
    }

    /// **The program's word is the verdict**, and the agent adds only what
    /// the program cannot say: that its guest stopped first, or ran past the
    /// deadline. Still scrubbing inside it is a wait, never a failure.
    #[test]
    fn a_guest_is_done_when_its_program_says_or_when_it_cannot() {
        let deadline = Dur::mins(20);
        let clean = step(Some(&report("clean")), true, 100, deadline);
        assert!(matches!(&clean, Step::Done(Outcome::Clean, d) if d["covered_mib"] == 24200 && d["residue_mib"] == 18000), "{clean:?}");
        assert!(matches!(step(Some(&report("failed")), true, 100, deadline), Step::Done(Outcome::Failed, _)));
        assert_eq!(step(Some(&report("running")), true, 100, deadline), Step::Wait);
        assert_eq!(step(None, true, 100, deadline), Step::Wait, "a guest still booting is not a failure");
        let late = step(Some(&report("running")), true, 1200, deadline);
        assert!(matches!(&late, Step::Done(Outcome::Failed, d) if d["detail"].as_str().unwrap().contains("scrubGuestDeadline")), "{late:?}");
        let stopped = step(None, false, 0, deadline);
        assert!(matches!(&stopped, Step::Done(Outcome::Failed, d) if d["detail"].as_str().unwrap().contains("stopped")), "{stopped:?}");
        // A verdict read before the stop is still the verdict.
        assert!(matches!(step(Some(&report("clean")), false, 0, deadline), Step::Done(Outcome::Clean, _)));
    }

    /// **The wire is Core's** (`scrubs::tests::the_wire_is_the_agents` pins
    /// the same bytes): what Core lists deserializes here, and what this
    /// agent says is what Core reads.
    #[test]
    fn the_wire_is_cores() {
        let w: Wants = serde_json::from_str(
            r#"{"scrubs":[{"id":"6f1c2f2e-58a4-4b43-9b0a-0d7b6c3c1d11","attempt":1,"card":"0000:01:00.0",
                "node":"pluto","model":"GA102 [GeForce RTX 3090]","image":"scrub-nvidia"}]}"#,
        )
        .unwrap();
        assert_eq!((w.scrubs[0].attempt, w.scrubs[0].image.as_str()), (1, "scrub-nvidia"));
        let said = [Said {
            id: "6f1c2f2e-58a4-4b43-9b0a-0d7b6c3c1d11".into(),
            attempt: 2,
            outcome: Outcome::Failed,
            detail: serde_json::json!({"detail": "the guest never reported", "seconds": 1200.0}),
        }];
        assert_eq!(
            serde_json::to_value(Report { scrubs: &said }).unwrap(),
            serde_json::json!({"scrubs":[{"id":"6f1c2f2e-58a4-4b43-9b0a-0d7b6c3c1d11","attempt":2,"outcome":"failed",
                "detail":{"detail":"the guest never reported","seconds":1200.0}}]})
        );
        let mut held = Held::default();
        held.0.insert(("a".into(), 1), said[0].clone());
        held.0.insert(("b".into(), 1), said[0].clone());
        held.answered(&[
            Recorded { id: "a".into(), attempt: 1, result: "clean".into() },
            Recorded { id: "b".into(), attempt: 1, result: "held".into() },
        ]);
        assert_eq!(held.0.keys().cloned().collect::<Vec<_>>(), vec![("b".to_string(), 1)], "held is kept, the rest forgotten");
    }

    #[test]
    fn a_stamp_names_its_scrub_and_its_attempt() {
        let id = "6f1c2f2e-58a4-4b43-9b0a-0d7b6c3c1d11";
        let config = serde_json::json!({"description": format!("{}\nattempt 3", onv_agent_lib::names::description(TAG, id))});
        assert_eq!((scrub_of(&config).as_deref(), attempt_of(&config)), (Some(id), Some(3)));
        let config = serde_json::json!({"description": onv_agent_lib::names::description(TAG, id)});
        assert_eq!((scrub_of(&config).as_deref(), attempt_of(&config)), (Some(id), None), "no attempt line, no attempt");
        // An instance's stamp is not a scrub's.
        let other = serde_json::json!({"description": onv_agent_lib::names::description(onv_agent_lib::names::TAG_INSTANCE, id)});
        assert_eq!(scrub_of(&other), None);
    }

}
