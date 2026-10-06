//! **A card's scrub, the half that speaks to Proxmox**: cloning, starting,
//! reading and removing the scrub guest. What Core wants, what the guest
//! reports and the step one look concludes moved to `onv_scrub::scrub` with no
//! behaviour change (omnuv's modular design, work package A1b), and are
//! imported here under the names they always had.

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::proxmox::Client;

pub use onv_scrub::scrub::*;

/// The scrub guest's slice: the card, and enough of a machine to boot the
/// driver and hold one chunk of the card in host memory at a time.
const CORES: u32 = 2;
const MEMORY_MIB: u64 = 4096;

const NO_FORM: &[(String, String)] = &[];

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
            if wanted.contains(id.as_str()) || !v.tags.as_deref().is_some_and(|t| crate::names::carries_key(t, &id)) {
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

    /// A PCI assignment names a card by its mapping or by its address,
    /// and another card's mapping is not this one.
    #[test]
    fn a_card_is_assigned_by_its_mapping_or_its_address() {
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
