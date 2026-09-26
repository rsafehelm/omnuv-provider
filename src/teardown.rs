//! **What a delete may destroy** (lifecycle phase 7: RC4, TD8 — licence (a)).
//!
//! A delete found its machine by the first guest in the cluster listing that
//! carried the claim tag and twelve hex digits of the id, and destroyed it.
//! Three things could sit there that are not the machine, and the report's
//! red team found each (Part II §6.3, §7.4 H2 and H3):
//!
//! ```text
//! a copy        the host owner cloned our guest, tags and all; the delete took
//!               whichever the listing named first (the model's G_oneMatch)
//! a collision   another machine's id shares its first twelve hex digits; the
//!               tag matches and the machine is somebody else's
//! a stale view  the view the pass started from said Absent; Core has since
//!               moved on (the model's G_reread)
//! ```
//!
//! and the destroy call itself could reach disks that were never the
//! machine's: Proxmox's `destroy-unreferenced-disks` removes every volume
//! whose name carries the VMID, and a VMID is the lowest free number,
//! reserved by nothing — so a volume somebody else made at that number is
//! "unreferenced" and ours to lose.
//!
//! **Licence (a)**, as the report words it (RC4): the agent destroys only
//! *the one guest with the whole claim of an attempt that a fresh view names
//! Absent, if no live attempt shares its tag*. So:
//!
//! ```text
//! one        exactly one guest in the cluster carries the claim; two or more
//!            are refused, named, and none is destroyed
//! whole      its description's first line is this machine's stamp, the whole
//!            id (`names::stamped`), not twelve digits of it
//! unshared   no live machine in Core's view carries the same tag
//! fresh      the view is re-read just before the destroy and still says Absent
//! disks      purge=1, destroy-unreferenced-disks=0: the disks that go are
//!            the ones the config names, never the ones the VMID does
//! ```
//!
//! A refusal is an error the report carries in the machine's own words, so
//! Core keeps the claim and the operator sees why. Nothing here escalates by
//! destroying.

use crate::proxmox::Client;
use crate::worker::VmRef;

const NO_FORM: &[(String, String)] = &[];

/// A delete that licence (a) does not allow: named for the operator, never a
/// destroy. The claim stays held.
#[derive(Debug)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "not destroyed: {}", self.0)
    }
}

impl std::error::Error for Refused {}

/// One guest carrying a machine's claim, and where.
#[derive(Debug, Clone)]
pub(crate) struct Claimed {
    pub node: String,
    pub vm: VmRef,
}

/// The one guest licence (a) allows a delete to destroy, and the volumes its
/// own configuration names — the only disks that go with it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Doomed {
    pub node: String,
    pub vmid: u32,
    pub running: bool,
    pub volids: Vec<String>,
}

/// What licence (a) allows for one machine's delete.
#[derive(Debug)]
pub(crate) enum Licence {
    /// Nothing carries the claim, in the cluster listing and every online
    /// node's own.
    Nothing,
    /// The one guest with the whole claim.
    Destroy(Doomed),
}

/// **The volumes a guest's configuration names**: every disk slot's volume
/// id (`storage:name`), the cloud-init drive and detached `unusedN` disks
/// included, and never an ISO or an empty drive. What a destroy may take,
/// and what a later listing must show gone.
pub(crate) fn disk_volids(config: &serde_json::Value) -> Vec<String> {
    const SLOTS: &[&str] = &["scsi", "virtio", "sata", "ide", "unused", "efidisk", "tpmstate"];
    let Some(fields) = config.as_object() else { return Vec::new() };
    let mut out: Vec<String> = fields
        .iter()
        .filter(|(k, _)| {
            SLOTS.iter().any(|slot| {
                k.strip_prefix(slot).is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
            })
        })
        .filter_map(|(_, v)| v.as_str())
        .filter_map(|v| v.split(',').next())
        .filter(|volid| volid.contains(':') && !volid.contains(":iso/") && *volid != "none")
        .map(str::to_string)
        .collect();
    out.sort();
    out.dedup();
    out
}

impl Client {
    /// **Every guest carrying this claim**, across the cluster: the kind tag
    /// and the id tag, both, as whole tokens. All of them, not the first —
    /// "which one" is licence (a)'s question, and a listing that stopped at
    /// the first could never ask it.
    ///
    /// None in the cluster listing is confirmed against every online node's
    /// live listing, as `find_tagged_vm_anywhere` does (PROVIDER-5): a miss is
    /// the dangerous answer, and a node that cannot be read means absence
    /// cannot be concluded.
    pub(crate) async fn claimed_guests(&self, kind: &str, id: &str) -> anyhow::Result<Vec<Claimed>> {
        #[derive(serde::Deserialize)]
        struct ClusterVm {
            node: String,
            vmid: u32,
            #[serde(default)]
            tags: Option<String>,
            #[serde(default)]
            status: Option<String>,
        }
        let id_tag = crate::names::short_tag(id);
        let tagged = |tags: Option<&str>| {
            tags.is_some_and(|t| t.split(';').any(|x| x == kind) && t.split(';').any(|x| x == id_tag))
        };
        let vms: Vec<ClusterVm> = self.get_json("/cluster/resources?type=vm").await?;
        let found: Vec<Claimed> = vms
            .into_iter()
            .filter(|v| tagged(v.tags.as_deref()))
            .map(|v| Claimed { node: v.node, vm: VmRef { vmid: v.vmid, tags: v.tags, status: v.status } })
            .collect();
        if !found.is_empty() {
            return Ok(found);
        }
        let nodes: Vec<serde_json::Value> = self.get_json("/nodes").await?;
        let mut live = Vec::new();
        for n in nodes.iter().filter(|n| n["status"].as_str() == Some("online")) {
            let Some(node) = n["node"].as_str() else { continue };
            let vms: Vec<VmRef> = self.get_json(&format!("/nodes/{node}/qemu")).await.map_err(|e| {
                anyhow::anyhow!("{node} could not be listed, so this machine's absence cannot be concluded: {e}")
            })?;
            live.extend(
                vms.into_iter()
                    .filter(|v| tagged(v.tags.as_deref()))
                    .map(|vm| Claimed { node: node.to_string(), vm }),
            );
        }
        Ok(live)
    }

    /// **Licence (a)**: the one guest a delete of `id` may destroy, or
    /// nothing there, or a [`Refused`] naming why neither can be said.
    /// `live_tags` are the id tags of every machine and worker Core's view
    /// still wants (intent not Absent), this one excluded.
    pub(crate) async fn licence(&self, kind: &str, id: &str, live_tags: &[String]) -> anyhow::Result<Licence> {
        let found = self.claimed_guests(kind, id).await?;
        let one = match found.as_slice() {
            [] => return Ok(Licence::Nothing),
            [one] => one.clone(),
            many => {
                let named: Vec<String> = many.iter().map(|c| format!("vm {} on {}", c.vm.vmid, c.node)).collect();
                return Err(Refused(format!(
                    "{} guests carry this machine's claim ({}); none is destroyed, and the operator decides which, if any, is it",
                    many.len(),
                    named.join(", ")
                ))
                .into());
            }
        };
        let tag = crate::names::short_tag(id);
        if live_tags.iter().any(|t| *t == tag) {
            return Err(Refused(format!(
                "vm {} carries tag {tag}, which a machine Core still wants shares; it is not destroyed",
                one.vm.vmid
            ))
            .into());
        }
        let config: serde_json::Value =
            self.get_json(&format!("/nodes/{}/qemu/{}/config", one.node, one.vm.vmid)).await?;
        let first = config.get("description").and_then(|d| d.as_str()).and_then(|d| d.lines().next());
        if first != Some(crate::names::stamped(kind, id).as_str()) {
            return Err(Refused(format!(
                "vm {} on {} carries this machine's tag but not its whole id (its stamp reads {:?}); it is not destroyed",
                one.vm.vmid,
                one.node,
                first.unwrap_or("")
            ))
            .into());
        }
        Ok(Licence::Destroy(Doomed {
            node: one.node,
            vmid: one.vm.vmid,
            running: one.vm.status.as_deref() == Some("running"),
            volids: disk_volids(&config),
        }))
    }

    /// **The destroy licence (a) allowed**: stopped first and the stop waited
    /// for, then destroyed with `purge=1` (backup jobs, replication and HA
    /// entries go with it) and `destroy-unreferenced-disks=0`, said rather
    /// than left to a default, so no volume goes for carrying the VMID.
    pub(crate) async fn destroy(&self, d: &Doomed) -> anyhow::Result<()> {
        let (node, vmid) = (d.node.as_str(), d.vmid);
        if d.running {
            let upid: String = self.post_form(&format!("/nodes/{node}/qemu/{vmid}/status/stop"), NO_FORM).await?;
            self.wait_task(node, &upid).await?;
        }
        let upid: String = self
            .delete_task(&format!("/nodes/{node}/qemu/{vmid}?purge=1&destroy-unreferenced-disks=0"))
            .await?;
        self.wait_task(node, &upid).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0a1b2c3d-4e5f-4a0b-8c1d-2e3f4a5b6c7d";
    /// Another machine whose id shares ID's first twelve hex digits.
    const TWIN: &str = "0a1b2c3d-4e5f-4fff-8fff-ffffffffffff";

    /// The volumes a config names, and the nearest things it must ignore.
    #[test]
    fn the_disks_that_go_are_the_ones_the_config_names() {
        let config = serde_json::json!({
            "scsi0": "local-lvm:vm-9001-disk-0,size=32G",
            "scsi1": "zfs-fast:vm-9001-disk-1,backup=0",
            "efidisk0": "local-lvm:vm-9001-disk-2,efitype=4m",
            "ide2": "local-lvm:vm-9001-cloudinit,media=cdrom",
            "unused0": "local-lvm:vm-9001-disk-3",
            "ide0": "local:iso/ubuntu.iso,media=cdrom",
            "sata1": "none,media=cdrom",
            "scsihw": "virtio-scsi-single",
            "net0": "virtio=BC:24:11:00:00:01,bridge=onvnat0",
            "description": "Omnuv instance x\nlocal-lvm:vm-9001-disk-9",
        });
        assert_eq!(
            disk_volids(&config),
            vec![
                "local-lvm:vm-9001-cloudinit",
                "local-lvm:vm-9001-disk-0",
                "local-lvm:vm-9001-disk-2",
                "local-lvm:vm-9001-disk-3",
                "zfs-fast:vm-9001-disk-1",
            ]
        );
    }

    /// A Proxmox holding `guests` (vmid, tags, description) on n1, and
    /// answering every task as finished.
    async fn host(guests: Vec<(u32, String, String)>) -> crate::pvemock::Mock {
        crate::pvemock::Mock::start(move |method, path, _| {
            if let Some(ok) = crate::pvemock::task_ok(path) {
                return ok;
            }
            match (method, path) {
                ("GET", "/cluster/resources?type=vm") => (
                    200,
                    serde_json::json!(guests
                        .iter()
                        .map(|(vmid, tags, _)| serde_json::json!({"node": "n1", "vmid": vmid, "tags": tags, "status": "stopped"}))
                        .collect::<Vec<_>>()),
                ),
                ("GET", "/nodes") => (200, serde_json::json!([{"node": "n1", "status": "online"}])),
                ("GET", "/nodes/n1/qemu") => (200, serde_json::json!([])),
                ("DELETE", _) => (200, serde_json::json!("UPID:n1:destroy")),
                ("GET", p) if p.ends_with("/config") => {
                    let vmid: u32 = p.split('/').nth(4).and_then(|v| v.parse().ok()).unwrap_or(0);
                    let d = guests.iter().find(|g| g.0 == vmid).map(|g| g.2.clone()).unwrap_or_default();
                    (200, serde_json::json!({"description": d, "scsi0": format!("local-lvm:vm-{vmid}-disk-0,size=8G")}))
                }
                _ => (404, serde_json::Value::Null),
            }
        })
        .await
    }

    fn ours(vmid: u32, id: &str) -> (u32, String, String) {
        (vmid, crate::names::tags(crate::names::TAG_INSTANCE, id, Some("test")), crate::names::description(crate::names::TAG_INSTANCE, id))
    }

    fn destroyed(mock: &crate::pvemock::Mock) -> Vec<String> {
        mock.calls.lock().unwrap().iter().filter(|c| c.method == "DELETE").map(|c| c.path.clone()).collect()
    }

    /// **Decoys survive a delete** (the roadmap's pass for row 7). Each
    /// guest below looks like the machine being deleted and is not proven to
    /// be it; each delete is refused and destroys nothing. The control, last:
    /// the machine itself, alone, is destroyed — by the volumes its config
    /// names, never by its VMID.
    #[tokio::test]
    async fn decoys_survive_a_delete() {
        let snippets = std::env::temp_dir().join(format!("onv-decoys-{}", std::process::id()));
        let dir = snippets.join("snippets");
        std::fs::create_dir_all(&dir).unwrap();
        let dir = dir.to_string_lossy().to_string();
        let yes = || async { Ok(true) };

        // A copy: the host owner cloned our guest, tags and stamp and all.
        let copy = host(vec![ours(9001, ID), ours(9002, ID)]).await;
        let e = copy.client().delete_instance("n1", ID, &dir, &[], yes()).await.expect_err("a copy was taken for the machine");
        assert!(e.downcast_ref::<Refused>().is_some(), "{e}");
        assert!(destroyed(&copy).is_empty(), "a guest was destroyed while two carried the claim: {:?}", destroyed(&copy));

        // A collision: the tag matches, the whole id in the stamp does not.
        let twin = host(vec![ours(9003, TWIN)]).await;
        let e = twin.client().delete_instance("n1", ID, &dir, &[], yes()).await.expect_err("the twin was taken");
        assert!(e.to_string().contains("whole id"), "{e}");
        assert!(destroyed(&twin).is_empty(), "{:?}", destroyed(&twin));

        // A live machine in Core's view shares the tag.
        let shared = host(vec![ours(9004, ID)]).await;
        let live = vec![crate::names::short_tag(TWIN)];
        let e = shared.client().delete_instance("n1", ID, &dir, &live, yes()).await.expect_err("a shared tag");
        assert!(e.downcast_ref::<Refused>().is_some(), "{e}");
        assert!(destroyed(&shared).is_empty());

        // A fresh view no longer names it Absent.
        let stale = host(vec![ours(9005, ID)]).await;
        let e = stale.client().delete_instance("n1", ID, &dir, &[], async { Ok(false) }).await.expect_err("a stale view");
        assert!(e.downcast_ref::<Refused>().is_some(), "{e}");
        assert!(destroyed(&stale).is_empty());

        // The machine itself, alone: destroyed, and by what its config names.
        let alone = host(vec![ours(9006, ID)]).await;
        alone.client().delete_instance("n1", ID, &dir, &[], yes()).await.expect("the machine is destroyed");
        assert_eq!(destroyed(&alone), vec!["/nodes/n1/qemu/9006?purge=1&destroy-unreferenced-disks=0".to_string()]);
        let _ = std::fs::remove_dir_all(&snippets);
    }
}
