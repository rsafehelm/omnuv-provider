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

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::proxmox::Client;

/// **What this agent advertises when it can scrub a card**: Core's
/// `scrubs::CAPABILITY`.
pub const CAPABILITY: &str = "card-scrub";

/// The claim a scrub guest carries, and the word its stamp uses.
pub const TAG: &str = crate::names::TAG_SCRUB;

/// Where the scrub program leaves its verdict in the guest (`onv-scrub.c`).
pub const REPORT: &str = "/run/onv/scrub.json";

/// Core's routes, both ways.
pub const PATH: &str = "/provider/v1/scrubs";

/// The scrub guest's slice: the card, and enough of a machine to boot the
/// driver and hold one chunk of the card in host memory at a time.
const CORES: u32 = 2;
const MEMORY_MIB: u64 = 4096;

const NO_FORM: &[(String, String)] = &[];

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
pub struct Held(BTreeMap<(String, i32), Said>);

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
pub fn step(report: Option<&GuestReport>, running: bool, uptime_s: u64, deadline: crate::dur::Dur) -> Step {
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
fn attempt_of(config: &serde_json::Value) -> Option<i32> {
    config
        .get("description")
        .and_then(|d| d.as_str())
        .and_then(|d| d.lines().skip(1).find_map(|l| l.trim().strip_prefix("attempt ")))
        .and_then(|n| n.trim().parse().ok())
}

/// The scrub a guest's stamp names: the whole id on its first line.
fn scrub_of(config: &serde_json::Value) -> Option<String> {
    let first = config.get("description").and_then(|d| d.as_str()).and_then(|d| d.lines().next())?;
    first.strip_prefix(&crate::names::stamped(TAG, "")).map(str::to_string).filter(|s| !s.is_empty())
}

/// Whether a PCI assignment (`hostpci<n>`'s value) names this card: its
/// mapping, or its address.
fn assigns(value: &str, card: &str) -> bool {
    let mapping = format!("mapping={}", crate::worker::mapping_name(card));
    value.split(',').any(|p| p.trim() == mapping) || crate::proxmox::pci_slot(value) == crate::proxmox::pci_slot(card)
}

/// Where a scrub is built from, on this provider.
pub struct Setup<'a> {
    pub storage: &'a str,
    pub snippet_dir: &'a str,
    /// Image id to local template, as `ProxmoxRuntime::template_for`.
    pub template_for: &'a (dyn Fn(&str) -> Option<u32> + Sync),
}

impl Client {
    /// **One pass over the scrubs Core wants.** Returns what to report: the
    /// outcomes held for scrubs still wanted. Each scrub's error is said and
    /// the others go on; nothing here fails the pass.
    pub(crate) async fn scrub_pass(&self, wants: &[Wanted], held: &mut Held, setup: &Setup<'_>) -> Vec<Said> {
        for w in wants {
            if held.0.contains_key(&(w.id.clone(), w.attempt)) {
                continue;
            }
            match self.scrub_one(w, setup).await {
                Ok(Some(said)) => {
                    held.0.insert((w.id.clone(), w.attempt), said);
                }
                Ok(None) => {}
                Err(e) => eprintln!("scrub {} (card {} on {}): {e:#}", w.id, w.card, w.node),
            }
        }
        if let Err(e) = self.sweep_scrub_guests(wants).await {
            eprintln!("scrub: leftover scrub guests not looked at: {e:#}");
        }
        let wanted: BTreeSet<(String, i32)> = wants.iter().map(|w| (w.id.clone(), w.attempt)).collect();
        held.0.retain(|k, _| wanted.contains(k));
        held.0.values().cloned().collect()
    }

    /// One scrub, one step: start its guest, look at it, or finish it.
    async fn scrub_one(&self, w: &Wanted, setup: &Setup<'_>) -> anyhow::Result<Option<Said>> {
        let found = self.claimed_guests(TAG, &w.id).await?;
        let one = match found.as_slice() {
            [] => {
                self.start_scrub(w, setup).await?;
                return Ok(None);
            }
            [one] => one.clone(),
            many => {
                let named: Vec<String> = many.iter().map(|c| format!("vm {} on {}", c.vm.vmid, c.node)).collect();
                anyhow::bail!("{} guests carry this scrub's claim ({}); none is used or removed", many.len(), named.join(", "));
            }
        };
        let (node, vmid) = (one.node.as_str(), one.vm.vmid);
        let config: serde_json::Value = self.get_json(&format!("/nodes/{node}/qemu/{vmid}/config")).await?;
        if scrub_of(&config).as_deref() != Some(w.id.as_str()) {
            anyhow::bail!("vm {vmid} on {node} carries this scrub's tag but not its whole stamp; it is left alone");
        }
        if attempt_of(&config) != Some(w.attempt) {
            // An earlier attempt's guest: its verdict is not this attempt's.
            self.remove_scrub_guest(node, vmid, &config).await?;
            return Ok(None);
        }
        let now: serde_json::Value = self.get_json(&format!("/nodes/{node}/qemu/{vmid}/status/current")).await?;
        let running = now.get("status").and_then(|s| s.as_str()) == Some("running");
        let uptime = now.get("uptime").and_then(serde_json::Value::as_u64).unwrap_or(0);
        let report = if running {
            self.read_guest_file(node, vmid, REPORT).await.and_then(|c| serde_json::from_str::<GuestReport>(&c).ok())
        } else {
            None
        };
        match step(report.as_ref(), running, uptime, self.timings.scrub_guest_deadline) {
            Step::Wait => Ok(None),
            Step::Done(outcome, mut detail) => {
                self.remove_scrub_guest(node, vmid, &config).await?;
                detail["guest_uptime_s"] = uptime.into();
                crate::audit::record("card.scrub", "core", &w.id,
                    if outcome == Outcome::Clean { "clean" } else { "failed" },
                    Some(&format!("card {} on {node}, attempt {}, vm {vmid}", w.card, w.attempt)));
                Ok(Some(Said { id: w.id.clone(), attempt: w.attempt, outcome, detail }))
            }
        }
    }

    /// **The scrub guest, built and started**: the card's scrub image cloned
    /// into the marketplace's pool, stamped and claimed, the card passed
    /// through and the NIC taken away, then started through the gate.
    async fn start_scrub(&self, w: &Wanted, setup: &Setup<'_>) -> anyhow::Result<()> {
        let template = (setup.template_for)(&w.image)
            .ok_or_else(|| anyhow::anyhow!("this provider holds no template for scrub image {}", w.image))?;
        let nodes = self.create_nodes().await?;
        anyhow::ensure!(nodes.iter().any(|n| n == &w.node), "the card's node {} is not one this agent places on", w.node);
        let node = w.node.as_str();
        // **Nothing else may be configured with the card**: not a buyer's
        // machine that outlived its claim, not an owner's stopped guest. The
        // gate checks running guests' IOMMU groups at the start; this checks
        // every configuration first, so a scrub never takes a card somebody
        // still names.
        let guests: Vec<crate::worker::VmRef> = self.get_json(&format!("/nodes/{node}/qemu")).await?;
        for g in &guests {
            let config: serde_json::Value = self.get_json(&format!("/nodes/{node}/qemu/{}/config", g.vmid)).await?;
            let names_card = config.as_object().is_some_and(|m| {
                m.iter().any(|(k, v)| k.starts_with("hostpci") && v.as_str().is_some_and(|v| assigns(v, &w.card)))
            });
            if names_card {
                anyhow::bail!("vm {} on {node} is still configured with card {}; the scrub waits", g.vmid, w.card);
            }
        }

        let _allocating = self.alloc.clone().lock_owned().await;
        let vmid: u32 = self.get_json::<String>("/cluster/nextid").await?.parse()?;
        let journal = crate::pending::dir(setup.snippet_dir);
        let mut pending = crate::pending::PendingClone {
            vmid,
            id: w.id.clone(),
            node: node.to_string(),
            upid: None,
            claim: TAG.to_string(),
            stage: crate::pending::Stage::Cloning, volids: Vec::new(),
        };
        crate::pending::write(&journal, &pending)?;
        let description = format!("{}\nattempt {}", crate::names::description(TAG, &w.id), w.attempt);
        let upid: String = self
            .post_form(
                &format!("/nodes/{node}/qemu/{template}/clone"),
                &[
                    ("newid".to_string(), vmid.to_string()),
                    ("name".to_string(), crate::names::scrub(&w.id)),
                    ("description".to_string(), description.clone()),
                    ("full".to_string(), "1".to_string()),
                    ("storage".to_string(), setup.storage.to_string()),
                    // The marketplace's own pool, where the file-read grant
                    // lives, as a worker's.
                    ("pool".to_string(), crate::join::GATEWAY_POOL.to_string()),
                ],
            )
            .await?;
        pending.upid = Some(upid.clone());
        crate::pending::write(&journal, &pending)?;
        match self.task_end(node, &upid, Self::clone_polls(None, self.timings.clone_budget_max)).await {
            crate::proxmox::TaskEnd::Ended(Ok(())) => self.journal_clone_volumes(&journal, &mut pending).await,
            crate::proxmox::TaskEnd::Ended(Err(exit)) => {
                self.abandon_clone(&journal, &pending, "scrub").await;
                anyhow::bail!("the clone of scrub image {} failed: {exit}", w.image);
            }
            crate::proxmox::TaskEnd::Unknown(why) => {
                anyhow::bail!("the clone of {vmid} has not been seen to finish ({why}); it stays recorded, and a later pass settles it");
            }
        }
        let finished: anyhow::Result<()> = async {
            let answer = self
                .post_form::<serde_json::Value>(
                    &format!("/nodes/{node}/qemu/{vmid}/config"),
                    &[("tags".to_string(), crate::names::tags(TAG, &w.id, self.environment.as_deref()))],
                )
                .await?;
            self.settle(node, answer).await?;
            let config: Vec<(String, String)> = vec![
                ("cores".into(), CORES.to_string()),
                ("memory".into(), MEMORY_MIB.to_string()),
                ("cpu".into(), "host".into()),
                ("machine".into(), "q35".into()),
                ("agent".into(), "enabled=1".into()),
                // **No NIC.** The scrub reads a tenant's leftovers (it counts
                // them) and needs nothing from any network; its report leaves
                // through the hypervisor.
                ("delete".into(), "net0".into()),
                ("hostpci0".into(), format!("mapping={},pcie=1,rombar=0", crate::worker::mapping_name(&w.card))),
                ("description".into(), description.clone()),
            ];
            let answer = self.post_form::<serde_json::Value>(&format!("/nodes/{node}/qemu/{vmid}/config"), &config).await?;
            self.settle(node, answer).await?;
            crate::pending::remove(&journal, vmid);
            self.start_when_ready(node, vmid).await
        }
        .await;
        if let Err(e) = finished {
            self.abandon_clone(&journal, &pending, "scrub").await;
            return Err(e);
        }
        crate::audit::record("card.scrub", "core", &w.id, "started",
            Some(&format!("card {} on {node}, attempt {}, vm {vmid}", w.card, w.attempt)));
        Ok(())
    }

    /// **A scrub guest, gone**: stopped (so the destroy is not counted
    /// against the hour's cap on destroying running machines, TD9, which is
    /// for buyers' machines), then destroyed with the disks its configuration
    /// names and no others.
    async fn remove_scrub_guest(&self, node: &str, vmid: u32, config: &serde_json::Value) -> anyhow::Result<()> {
        if self.live_status(node, vmid).await? != "stopped" {
            let upid: String = self.post_form(&format!("/nodes/{node}/qemu/{vmid}/status/stop"), NO_FORM).await?;
            self.wait_task(node, &upid).await?;
        }
        self.destroy(&crate::teardown::Doomed {
            node: node.to_string(),
            vmid,
            volids: crate::teardown::disk_volids(config),
        })
        .await
    }

    /// **Scrub guests nothing wants any more**: every guest carrying the scrub
    /// claim, in the marketplace's pool, whose whole stamp names a scrub Core
    /// no longer lists. Core ended it (a waiver, a fence), or this agent lost
    /// its outcome. Anything short of all three is left alone.
    async fn sweep_scrub_guests(&self, wants: &[Wanted]) -> anyhow::Result<()> {
        #[derive(Deserialize)]
        struct ClusterVm {
            node: String,
            vmid: u32,
            #[serde(default)]
            tags: Option<String>,
            #[serde(default)]
            pool: Option<String>,
        }
        let wanted: BTreeSet<&str> = wants.iter().map(|w| w.id.as_str()).collect();
        let vms: Vec<ClusterVm> = self.get_json("/cluster/resources?type=vm").await?;
        for v in vms.into_iter().filter(|v| {
            v.pool.as_deref() == Some(crate::join::GATEWAY_POOL)
                && v.tags.as_deref().is_some_and(|t| t.split(';').any(|x| x == TAG))
        }) {
            let config: serde_json::Value = self.get_json(&format!("/nodes/{}/qemu/{}/config", v.node, v.vmid)).await?;
            let Some(id) = scrub_of(&config) else { continue };
            if wanted.contains(id.as_str()) || !v.tags.as_deref().is_some_and(|t| t.split(';').any(|x| x == crate::names::short_tag(&id))) {
                continue;
            }
            eprintln!("scrub {id}: vm {} on {} is no longer wanted; removing it", v.vmid, v.node);
            self.remove_scrub_guest(&v.node, v.vmid, &config).await?;
            crate::audit::record("card.scrub", "core", &id, "removed", Some(&format!("vm {} on {}, no longer wanted", v.vmid, v.node)));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dur::Dur;

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
        let config = serde_json::json!({"description": format!("{}\nattempt 3", crate::names::description(TAG, id))});
        assert_eq!((scrub_of(&config).as_deref(), attempt_of(&config)), (Some(id), Some(3)));
        let config = serde_json::json!({"description": crate::names::description(TAG, id)});
        assert_eq!((scrub_of(&config).as_deref(), attempt_of(&config)), (Some(id), None), "no attempt line, no attempt");
        // An instance's stamp is not a scrub's.
        let other = serde_json::json!({"description": crate::names::description(crate::names::TAG_INSTANCE, id)});
        assert_eq!(scrub_of(&other), None);
        assert!(assigns("mapping=onv-gpu-0000-01-00-0,pcie=1,rombar=0", "0000:01:00.0"));
        assert!(assigns("0000:01:00,pcie=1", "0000:01:00.0"));
        assert!(!assigns("mapping=onv-gpu-0000-02-00-0,pcie=1", "0000:01:00.0"));
    }

    /// Routes a scrub's life through the fake Proxmox: `guest` is what sits
    /// at VM 300 (None: nothing yet), and what its program says.
    fn pve(guest: Option<(&'static str, Option<&'static str>)>, attempt: i32)
        -> impl Fn(&str, &str, &str) -> (u16, serde_json::Value) + Send + Sync + 'static {
        const ID: &str = "6f1c2f2e-58a4-4b43-9b0a-0d7b6c3c1d11";
        // Stopped once it has been asked to stop, as a node says.
        let stopped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        move |method: &str, path: &str, _body: &str| {
            use std::sync::atomic::Ordering;
            if method == "POST" && path == "/nodes/n1/qemu/300/status/stop" {
                stopped.store(true, Ordering::SeqCst);
            }
            if let Some(ok) = crate::pvemock::task_ok(path) {
                return ok;
            }
            let desc = format!("{}\nattempt {attempt}", crate::names::stamped(TAG, ID));
            match (method, path) {
                ("GET", "/cluster/resources?type=vm") => match guest {
                    Some(_) => (200, serde_json::json!([{"node": "n1", "vmid": 300, "pool": "onv",
                        "tags": crate::names::tags(TAG, ID, None), "status": "running"}])),
                    None => (200, serde_json::json!([])),
                },
                ("GET", "/nodes") => (200, serde_json::json!([{"node": "n1", "status": "online"}])),
                ("GET", "/nodes/n1/qemu") => (200, serde_json::json!(if guest.is_some() {
                    serde_json::json!([{"vmid": 300, "tags": crate::names::tags(TAG, ID, None)}])
                } else {
                    serde_json::json!([{"vmid": 101}])
                })),
                ("GET", "/nodes/n1/qemu/101/config") => (200, serde_json::json!({"hostpci0": "mapping=onv-gpu-0000-02-00-0,pcie=1"})),
                ("GET", "/nodes/n1/qemu/300/config") => (200, serde_json::json!({"description": desc, "scsi0": "local-zfs:vm-300-disk-0,size=12G"})),
                ("GET", "/nodes/n1/qemu/300/status/current") => {
                    let now = if stopped.load(Ordering::SeqCst) { "stopped" } else { guest.map(|g| g.0).unwrap_or("stopped") };
                    (200, serde_json::json!({"status": now, "uptime": 90}))
                }
                ("GET", p) if p.starts_with("/nodes/n1/qemu/300/agent/file-read") => match guest.and_then(|g| g.1) {
                    Some(status) => (200, serde_json::json!({"content": serde_json::json!({
                        "status": status, "stage": "done", "total_mib": 24576, "covered_mib": 24200,
                        "residue_mib": 18000, "verified": true, "seconds": 41.5, "persistent": {"vbios": "94.02"}}).to_string()})),
                    None => (500, serde_json::json!(null)),
                },
                ("GET", "/cluster/nextid") => (200, serde_json::json!("300")),
                ("POST", p) if p.ends_with("/clone") => (200, serde_json::json!("UPID:n1:clone")),
                ("POST", p) if p.ends_with("/status/stop") || p.ends_with("/status/start") => (200, serde_json::json!("UPID:n1:power")),
                ("POST", p) if p.ends_with("/config") => (200, serde_json::Value::Null),
                ("DELETE", p) if p.starts_with("/nodes/n1/qemu/300") => (200, serde_json::json!("UPID:n1:destroy")),
                _ => crate::pvemock::gate_clear(method, path).unwrap_or((404, serde_json::Value::Null)),
            }
        }
    }

    fn wanted(attempt: i32) -> Wanted {
        Wanted {
            id: "6f1c2f2e-58a4-4b43-9b0a-0d7b6c3c1d11".into(),
            attempt,
            card: "0000:01:00.0".into(),
            node: "n1".into(),
            model: "GA102 [GeForce RTX 3090]".into(),
            image: "scrub-nvidia".into(),
        }
    }

    fn setup(dir: &std::path::Path) -> (String, impl Fn(&str) -> Option<u32>) {
        (dir.to_string_lossy().to_string(), |image: &str| (image == "scrub-nvidia").then_some(9003))
    }

    /// **A held card with no scrub guest gets one**: cloned from its scrub
    /// image into the marketplace's pool, stamped and claimed, the card passed
    /// through by its mapping and the NIC deleted, and started. Nothing is
    /// reported yet. Before phase 9 nothing did any of it.
    #[tokio::test]
    async fn a_scrub_is_started_with_the_card_and_no_nic() {
        let mock = crate::pvemock::Mock::start(pve(None, 1)).await;
        let dir = tempfile::tempdir().unwrap();
        let (snippets, template_for) = setup(dir.path());
        let s = Setup { storage: "local-zfs", snippet_dir: &snippets, template_for: &template_for };
        let mut held = Held::default();
        let said = mock.client().scrub_pass(&[wanted(1)], &mut held, &s).await;
        assert!(said.is_empty(), "{said:?}");
        let clone = mock.body_of("POST", "/nodes/n1/qemu/9003/clone").expect("the scrub image was cloned");
        assert!(clone.contains("pool=onv") && clone.contains("Omnuv+card+scrub+6f1c2f2e"), "{clone}");
        let calls = mock.calls.lock().unwrap().clone();
        let config = calls.iter().filter(|c| c.method == "POST" && c.path == "/nodes/n1/qemu/300/config")
            .map(|c| c.body.clone()).collect::<Vec<_>>().join("&");
        assert!(config.contains("tags=onv-scrub%3Bonv-6f1c2f2e58a4"), "{config}");
        assert!(config.contains("delete=net0") && config.contains("hostpci0=mapping%3Donv-gpu-0000-01-00-0"), "{config}");
        assert!(config.contains("attempt+1"), "{config}");
        assert!(mock.called("POST", "/nodes/n1/qemu/300/status/start"), "the scrub guest was not started");
    }

    /// **A finished scrub is removed, then reported**: its program's clean
    /// verdict is read through the guest agent, the guest is stopped and
    /// destroyed with its own disks, and only then is the outcome returned for
    /// Core. The same outcome is reported again until Core answers for it.
    #[tokio::test]
    async fn a_finished_scrub_is_removed_before_it_is_reported() {
        let mock = crate::pvemock::Mock::start(pve(Some(("running", Some("clean"))), 1)).await;
        let dir = tempfile::tempdir().unwrap();
        let (snippets, template_for) = setup(dir.path());
        let s = Setup { storage: "local-zfs", snippet_dir: &snippets, template_for: &template_for };
        let mut held = Held::default();
        let client = mock.client();
        let said = client.scrub_pass(&[wanted(1)], &mut held, &s).await;
        assert_eq!(said.len(), 1, "{said:?}");
        assert_eq!((said[0].outcome, said[0].attempt, said[0].detail["covered_mib"].as_u64()), (Outcome::Clean, 1, Some(24200)));
        let calls = mock.calls.lock().unwrap().clone();
        let stop = calls.iter().position(|c| c.path == "/nodes/n1/qemu/300/status/stop").expect("stopped");
        let destroy = calls.iter().position(|c| c.method == "DELETE" && c.path.starts_with("/nodes/n1/qemu/300?purge=1&destroy-unreferenced-disks=0"))
            .expect("destroyed with its own disks only");
        assert!(stop < destroy);
        assert!(!mock.called("POST", "/nodes/n1/qemu/9003/clone"), "a second scrub was started");
        // Held until Core answers: the next pass reports it again, and looks
        // at no guest for it.
        let again = client.scrub_pass(&[wanted(1)], &mut held, &s).await;
        assert_eq!(again, said);
        held.answered(&[Recorded { id: wanted(1).id, attempt: 1, result: "clean".into() }]);
        assert!(client.scrub_pass(&[], &mut held, &s).await.is_empty());
    }

    /// **An earlier attempt's guest is not this attempt's verdict**: Core
    /// runs a failed scrub again as attempt 2; the guest left from attempt 1
    /// is removed, and its program's word is not reported for 2.
    #[tokio::test]
    async fn an_earlier_attempts_guest_is_removed_not_believed() {
        let mock = crate::pvemock::Mock::start(pve(Some(("running", Some("clean"))), 1)).await;
        let dir = tempfile::tempdir().unwrap();
        let (snippets, template_for) = setup(dir.path());
        let s = Setup { storage: "local-zfs", snippet_dir: &snippets, template_for: &template_for };
        let mut held = Held::default();
        let said = mock.client().scrub_pass(&[wanted(2)], &mut held, &s).await;
        assert!(said.is_empty(), "attempt 1's clean was reported for attempt 2: {said:?}");
        assert!(mock.calls.lock().unwrap().iter().any(|c| c.method == "DELETE" && c.path.starts_with("/nodes/n1/qemu/300")));
    }

    /// **A scrub guest Core no longer wants is removed**, and one still
    /// scrubbing inside its deadline is left to finish.
    #[tokio::test]
    async fn a_scrub_guest_nothing_wants_is_removed_and_a_working_one_left() {
        let mock = crate::pvemock::Mock::start(pve(Some(("running", Some("running"))), 1)).await;
        let dir = tempfile::tempdir().unwrap();
        let (snippets, template_for) = setup(dir.path());
        let s = Setup { storage: "local-zfs", snippet_dir: &snippets, template_for: &template_for };
        let mut held = Held::default();
        let client = mock.client();
        assert!(client.scrub_pass(&[wanted(1)], &mut held, &s).await.is_empty());
        assert!(!mock.calls.lock().unwrap().iter().any(|c| c.method == "DELETE"), "a working scrub was removed");
        assert!(client.scrub_pass(&[], &mut held, &s).await.is_empty());
        assert!(mock.calls.lock().unwrap().iter().any(|c| c.method == "DELETE" && c.path.starts_with("/nodes/n1/qemu/300")),
            "a scrub guest nothing wants was left");
    }
}
