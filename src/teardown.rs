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
///
/// **No power state here.** It carried the cluster listing's `status` until
/// the regression of 26 September: that listing is pvestatd's cache, a guest
/// started a moment ago reads `stopped` in it, the stop was skipped on that
/// word, and Proxmox refused to destroy a running guest. Whether to stop is
/// asked of the node when the destroy is made (`Client::destroy`), so nothing
/// that reads this can trust a stale one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Doomed {
    pub node: String,
    pub vmid: u32,
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

/// **The VMID a volume's name carries**, as Proxmox names what it allocates:
/// `vm-<id>-…`, `base-<id>-…`, `subvol-<id>-…`, `basevol-<id>-…`, and a
/// directory storage's `<id>/vm-<id>-disk-0.qcow2`. None for a name that
/// carries none (an ISO, an import).
pub(crate) fn volume_vmid(volid: &str) -> Option<u32> {
    let name = volid.split_once(':').map(|(_, n)| n).unwrap_or(volid);
    if let Some((dir, _)) = name.split_once('/') {
        return dir.parse().ok();
    }
    ["vm-", "base-", "subvol-", "basevol-"].iter().find_map(|prefix| {
        let rest = name.strip_prefix(prefix)?;
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        (!digits.is_empty() && rest[digits.len()..].starts_with('-')).then(|| digits.parse().ok()).flatten()
    })
}

/// Every volume a guest's configuration names, a container's included
/// (`rootfs`, `mpN`): what a leftover volume must not be before it is removed.
fn named_volids(config: &serde_json::Value) -> Vec<String> {
    let mut out = disk_volids(config);
    if let Some(fields) = config.as_object() {
        out.extend(
            fields
                .iter()
                .filter(|(k, _)| {
                    k.as_str() == "rootfs"
                        || k.strip_prefix("mp").is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
                })
                .filter_map(|(_, v)| v.as_str())
                .filter_map(|v| v.split(',').next())
                .filter(|volid| volid.contains(':'))
                .map(str::to_string),
        );
    }
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
        if live_tags.contains(&tag) {
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
        Ok(Licence::Destroy(Doomed { node: one.node, vmid: one.vm.vmid, volids: disk_volids(&config) }))
    }

    /// **A guest's power state as its node says it now**: `status/current`,
    /// which asks qemu-server whether the process runs — the same check
    /// Proxmox's own destroy makes before it refuses. Never the cluster
    /// listing's `status`, which lags a start by up to pvestatd's interval.
    /// A paused guest reads `running`, and is stopped like one.
    pub(crate) async fn live_status(&self, node: &str, vmid: u32) -> anyhow::Result<String> {
        let now: serde_json::Value = self.get_json(&format!("/nodes/{node}/qemu/{vmid}/status/current")).await?;
        now.get("status")
            .and_then(|s| s.as_str())
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("vm {vmid} on {node}: its node gave no power state, so it is not destroyed"))
    }

    /// **The destroy licence (a) allowed**: stopped first if its node says it
    /// is not stopped now, the stop waited for and the node asked again, then
    /// destroyed with `purge=1` (backup jobs, replication and HA entries go
    /// with it) and `destroy-unreferenced-disks=0`, said rather than left to a
    /// default, so no volume goes for carrying the VMID. A guest its node
    /// still calls running after the stop is not destroyed on this pass.
    pub(crate) async fn destroy(&self, d: &Doomed) -> anyhow::Result<()> {
        let (node, vmid) = (d.node.as_str(), d.vmid);
        if self.live_status(node, vmid).await? != "stopped" {
            let upid: String = self.post_form(&format!("/nodes/{node}/qemu/{vmid}/status/stop"), NO_FORM).await?;
            self.wait_task(node, &upid).await?;
            let after = self.live_status(node, vmid).await?;
            if after != "stopped" {
                return Err(Refused(format!(
                    "vm {vmid} on {node} is still {after} after its stop; it is not destroyed on this pass"
                ))
                .into());
            }
        }
        let upid: String = self
            .delete_task(&format!("/nodes/{node}/qemu/{vmid}?purge=1&destroy-unreferenced-disks=0"))
            .await?;
        self.wait_task(node, &upid).await
    }
}

// ---------------------------------------------------------------------------
// A delete is proven one listing later (RC1, S5, TD3), and remembered (RC5, TD2)
// ---------------------------------------------------------------------------
//
// The delete reported "deleted" the moment the destroy task said OK, and that
// word is the proof Core ends a claim on. Proxmox drops a config even when
// freeing a disk fails, and one user found one or two disks left per six
// destroys, all under TASK OK (the report's [63], [72]): the claim ended, the
// card was sold again, and the disk stayed on the host counted by nobody.
//
// Now the destroy writes a tombstone first, and "deleted" is said only by a
// later pass, on a listing that began after the destroy and found nothing of
// the machine: no guest carrying its claim anywhere, its node answering, none
// of the volumes its config named left in their storages, no task running for
// its VMID, no HA resource, its snippets gone (Part II §6.3). A volume that
// stays after it was asked to go is a residue: the compute claim may end, the
// disk stays counted, and the volumes are named — never dropped.

/// What a delete can say about a machine, on this pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Gone {
    /// deleted(k): a complete listing after the destroy found nothing of it.
    Proven,
    /// Deleted with residue: nothing of it runs or is configured, and these
    /// volumes stayed after they were asked to go.
    Residue(Vec<String>),
    /// Not proven: what blocks the proof, in words. Nothing may be released.
    NotYet(String),
}

/// **The word Core ends a claim on**, as each outcome says it.
///
/// `deleted` is the word every agent has sent; `deleted; residue <volid>…` is
/// new (lifecycle phase 7) and deliberately not `deleted`: a Core that
/// predates it reads it as no proof and keeps the claim, which is safe.
/// **A fourth untyped string on this wire** (after the handshake, `deleted`
/// and the image refusal): Core's `claims::residue_of` is the one parser, and
/// both sides pin the grammar in tests. A typed reason code is queued for the
/// next protocol release.
pub(crate) fn said(gone: &Gone) -> String {
    match gone {
        Gone::Proven => "deleted".to_string(),
        Gone::Residue(volids) => format!("deleted; residue {}", volids.join(" ")),
        Gone::NotYet(why) => format!("not proven gone: {why}"),
    }
}

/// **The agent's record of a machine it destroyed** (RC5, TD2; the model's
/// G_agentTomb). Written before the destroy is asked for, so an agent stopped
/// inside one still owes the proof; kept after the proof, so a machine this
/// agent answered deleted for is never built again under the same id.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Tombstone {
    pub id: String,
    pub claim: String,
    /// Where the guest was, when there was one. None: nothing of it was ever
    /// found here, and the tombstone records only the answer.
    #[serde(default)]
    pub node: Option<String>,
    #[serde(default)]
    pub vmid: Option<u32>,
    /// The volumes its config named when the destroy was decided.
    #[serde(default)]
    pub volids: Vec<String>,
    /// When the destroy task was seen to finish. None: decided, not seen.
    #[serde(default)]
    pub destroyed_at: Option<i64>,
    /// When a listing proved it gone, residue or not.
    #[serde(default)]
    pub proven_at: Option<i64>,
    /// Volumes that stayed after they were asked to go.
    #[serde(default)]
    pub residue: Vec<String>,
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Where tombstones live: beside the clone journal, one file per id.
pub(crate) fn tombstones(snippet_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(snippet_dir).parent().unwrap_or(std::path::Path::new("/var/lib/onv")).join("tombstones")
}

fn tomb_file(dir: &std::path::Path, id: &str) -> std::path::PathBuf {
    let safe: String = id.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).collect();
    dir.join(format!("{safe}.json"))
}

pub(crate) fn read_tomb(dir: &std::path::Path, id: &str) -> Option<Tombstone> {
    let raw = std::fs::read(tomb_file(dir, id)).ok()?;
    match serde_json::from_slice(&raw) {
        Ok(t) => Some(t),
        Err(e) => {
            // Unreadable is not absent: the id is treated as tombstoned, so
            // nothing is built under it, and the operator is told.
            eprintln!("tombstone for {id} unreadable, kept: {e}");
            Some(Tombstone {
                id: id.to_string(),
                claim: String::new(),
                node: None,
                vmid: None,
                volids: Vec::new(),
                destroyed_at: None,
                proven_at: None,
                residue: Vec::new(),
            })
        }
    }
}

/// Written before what it describes happens: a failure here stops the destroy.
pub(crate) fn write_tomb(dir: &std::path::Path, t: &Tombstone) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let raw = serde_json::to_vec(t)?;
    crate::names::write_private(&tomb_file(dir, &t.id).to_string_lossy(), &raw, 0o600)
        .map_err(|e| anyhow::anyhow!("recording the tombstone of {}: {e}", t.id))
}

/// Every tombstone that parses, for the pass that retries residues.
pub(crate) fn list_tombs(dir: &std::path::Path) -> Vec<Tombstone> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut out: Vec<Tombstone> = entries
        .flatten()
        .filter_map(|e| std::fs::read(e.path()).ok())
        .filter_map(|raw| serde_json::from_slice(&raw).ok())
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// **Never built again** (G_agentTomb): an id this agent destroyed, or
/// answered deleted for, is refused a create, with the reason.
pub(crate) fn built_again(snippet_dir: &str, id: &str) -> Option<String> {
    read_tomb(&tombstones(snippet_dir), id).map(|_| {
        "this machine was deleted on this provider and its tombstone is kept; it is not built again under the same id"
            .to_string()
    })
}

impl Client {
    /// **Tears one machine or worker down and says what can be proven**:
    /// licence (a) for what may be destroyed, a tombstone before the destroy,
    /// and the proof only on a later listing. The caller has checked the
    /// clone journal and removed the snippets.
    pub(crate) async fn tear_down(
        &self,
        kind: &str,
        id: &str,
        snippet_dir: &str,
        snippets: &[String],
        live_tags: &[String],
        reread: impl std::future::Future<Output = anyhow::Result<bool>>,
    ) -> anyhow::Result<Gone> {
        let dir = tombstones(snippet_dir);
        let held = read_tomb(&dir, id);
        if let Some(t) = &held
            && t.destroyed_at.is_some()
        {
            // The destroy was seen to finish on an earlier pass: this listing
            // is the one that may prove it.
            return self.prove(&dir, t.clone(), snippets).await;
        }
        let doomed = match self.licence(kind, id, live_tags).await? {
            crate::teardown::Licence::Nothing => {
                // Nothing carries the claim, on a complete listing made after
                // this pass read the Absent: a machine never built here, or one
                // destroyed without its tombstone seen. Recorded, and proven by
                // the same listing a destroy's would be.
                let t = held.unwrap_or(Tombstone {
                    id: id.to_string(),
                    claim: kind.to_string(),
                    node: None,
                    vmid: None,
                    volids: Vec::new(),
                    destroyed_at: None,
                    proven_at: None,
                    residue: Vec::new(),
                });
                let t = Tombstone { destroyed_at: Some(t.destroyed_at.unwrap_or_else(now)), ..t };
                write_tomb(&dir, &t)?;
                return self.prove(&dir, t, snippets).await;
            }
            crate::teardown::Licence::Destroy(d) => d,
        };
        if !reread.await? {
            return Err(Refused(format!(
                "vm {}: Core's view, read again just before the destroy, no longer names this machine Absent",
                doomed.vmid
            ))
            .into());
        }
        let mut t = Tombstone {
            id: id.to_string(),
            claim: kind.to_string(),
            node: Some(doomed.node.clone()),
            vmid: Some(doomed.vmid),
            volids: doomed.volids.clone(),
            destroyed_at: None,
            proven_at: None,
            residue: Vec::new(),
        };
        // Merged with what an earlier, unconfirmed destroy recorded: a volume
        // named then is still this machine's to account for.
        if let Some(old) = held {
            for v in old.volids {
                if !t.volids.contains(&v) {
                    t.volids.push(v);
                }
            }
        }
        write_tomb(&dir, &t)?;
        self.destroy(&doomed).await?;
        t.destroyed_at = Some(now());
        write_tomb(&dir, &t)?;
        Ok(Gone::NotYet(format!(
            "vm {} was destroyed on {}; the next complete listing proves it gone",
            doomed.vmid, doomed.node
        )))
    }

    /// **The proof, on this pass's listing** (§6.3). Each condition that fails
    /// is a blocker, named; only the volumes may fail alone, and then it is a
    /// residue. A volume still there is asked to go once per pass, and only
    /// when no configuration names it.
    async fn prove(&self, dir: &std::path::Path, mut t: Tombstone, snippets: &[String]) -> anyhow::Result<Gone> {
        let mut blockers = Vec::new();
        let left = self.claimed_guests(&t.claim, &t.id).await?;
        if !left.is_empty() {
            let named: Vec<String> = left.iter().map(|c| format!("vm {} on {}", c.vm.vmid, c.node)).collect();
            blockers.push(format!("{} still carries its claim", named.join(", ")));
        }
        let nodes: Vec<serde_json::Value> = self.get_json("/nodes").await?;
        let online = |n: &str| nodes.iter().any(|x| x["node"].as_str() == Some(n) && x["status"].as_str() == Some("online"));
        let mut residue = Vec::new();
        if let (Some(node), Some(vmid)) = (t.node.clone(), t.vmid) {
            if !online(&node) {
                // An offline node holding k's disk blocks k (the roadmap's
                // cost for this phase): nothing on it can be listed.
                blockers.push(format!("node {node}, which held vm {vmid} and its disks, does not answer"));
            } else {
                let active: Vec<serde_json::Value> = self.get_json(&format!("/nodes/{node}/tasks?source=active")).await?;
                if active.iter().any(|a| a["id"].as_str() == Some(vmid.to_string().as_str())) {
                    blockers.push(format!("a task for vm {vmid} is still running on {node}"));
                }
                let ha: Vec<serde_json::Value> = self.get_json("/cluster/ha/resources").await?;
                if ha.iter().any(|r| r["sid"].as_str() == Some(format!("vm:{vmid}").as_str())) {
                    blockers.push(format!("vm {vmid} is still an HA resource"));
                }
                for volid in &t.volids {
                    match self.volume_left(&node, volid).await {
                        Ok(false) => {}
                        Ok(true) => residue.push(volid.clone()),
                        Err(e) => blockers.push(format!("{volid} could not be looked for: {e}")),
                    }
                }
            }
        }
        for s in snippets {
            if std::path::Path::new(s).exists() {
                blockers.push(format!("its snippet {s} is still there"));
            }
        }
        if !blockers.is_empty() {
            return Ok(Gone::NotYet(blockers.join("; ")));
        }
        t.proven_at.get_or_insert_with(now);
        t.residue = residue.clone();
        write_tomb(dir, &t)?;
        if residue.is_empty() {
            crate::audit::record("teardown.proven", "agent", &t.id, "deleted", t.vmid.map(|v| v.to_string()).as_deref());
            Ok(Gone::Proven)
        } else {
            crate::audit::record("teardown.proven", "agent", &t.id, "residue", Some(&residue.join(" ")));
            Ok(Gone::Residue(residue))
        }
    }

    /// Whether a volume a destroyed machine's config named is still in its
    /// storage, after asking it to go once more if no configuration names it.
    async fn volume_left(&self, node: &str, volid: &str) -> anyhow::Result<bool> {
        let Some((storage, _)) = volid.split_once(':') else { return Ok(false) };
        let content_path = format!("/nodes/{node}/storage/{storage}/content");
        let present = |listed: &[serde_json::Value]| listed.iter().any(|c| c["volid"].as_str() == Some(volid));
        let listed: Vec<serde_json::Value> = self.get_json(&content_path).await?;
        if !present(&listed) {
            return Ok(false);
        }
        // **Named by any guest's configuration, anywhere: not ours to take.**
        // Every guest in the cluster, VM or container, since a shared storage
        // is reachable from every node. A configuration that cannot be read
        // (its node offline, say) is not "names nothing": the volume is left,
        // and stays a residue for the operator, rather than blocking the proof.
        #[derive(serde::Deserialize)]
        struct Guest {
            node: String,
            vmid: u32,
            #[serde(default, rename = "type")]
            kind: Option<String>,
        }
        let guests: Vec<Guest> = self.get_json("/cluster/resources?type=vm").await?;
        // **A number some guest holds now is not ours to judge** (the
        // regression review of 26 September). A volume's name carries the
        // VMID it was made for, and a VMID is the lowest free number: once
        // the machine was destroyed, the next clone takes it and makes its
        // disks under the same names — and a full clone writes them into its
        // configuration only when the copy ends. So a volume named for a VMID
        // a guest holds is never removed, whether or not a configuration names
        // it yet; it stays a residue for the operator.
        if let Some(held) = volume_vmid(volid).and_then(|n| guests.iter().find(|g| g.vmid == n)) {
            eprintln!(
                "{volid}: its number is vm {}'s on {} now, so whose it is cannot be told; it is not removed",
                held.vmid, held.node
            );
            return Ok(true);
        }
        for g in &guests {
            let kind = if g.kind.as_deref() == Some("lxc") { "lxc" } else { "qemu" };
            let config: serde_json::Value = match self.get_json(&format!("/nodes/{}/{kind}/{}/config", g.node, g.vmid)).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{volid}: guest {} on {} could not be read, so it is not removed: {e}", g.vmid, g.node);
                    return Ok(true);
                }
            };
            if named_volids(&config).iter().any(|v| v == volid) {
                eprintln!("{volid}: guest {} names it now; it is not removed, and it stays a residue", g.vmid);
                return Ok(true);
            }
        }
        let asked: anyhow::Result<serde_json::Value> =
            self.delete_task(&format!("{content_path}/{}", crate::proxmox::urlencode(volid))).await;
        match asked {
            Ok(serde_json::Value::String(upid)) => {
                if let Err(e) = self.wait_task(node, &upid).await {
                    eprintln!("{volid}: its removal failed: {e}");
                }
            }
            Ok(_) => {}
            Err(e) => eprintln!("{volid}: could not be removed: {e}"),
        }
        let again: Vec<serde_json::Value> = self.get_json(&content_path).await?;
        Ok(present(&again))
    }

    /// **Tombstones are reaped by time, after a look** (R1's rule 10; D13).
    /// A tombstone proven longer ago than `keep`, with no residue, goes — but
    /// only once a listing made now finds nothing carrying its claim: the
    /// clock that concludes "nothing can come back for this" re-observes
    /// first (TD11). A guest that carries it keeps the tombstone, and says so.
    pub(crate) async fn reap_tombstones(&self, snippet_dir: &str, keep: crate::dur::Dur) -> usize {
        let dir = tombstones(snippet_dir);
        let cutoff = now() - keep.as_secs() as i64;
        let mut reaped = 0;
        for t in list_tombs(&dir) {
            if !t.residue.is_empty() || t.proven_at.is_none_or(|p| p > cutoff) {
                continue;
            }
            match self.claimed_guests(&t.claim, &t.id).await {
                Ok(left) if left.is_empty() => {
                    if let Err(e) = std::fs::remove_file(tomb_file(&dir, &t.id)) {
                        eprintln!("tombstone {}: not removed: {e}", t.id);
                        continue;
                    }
                    crate::audit::record("teardown.tombstone", "agent", &t.id, "reaped", None);
                    reaped += 1;
                }
                Ok(left) => eprintln!(
                    "tombstone {}: past its horizon, and {} guest(s) carry its claim; kept",
                    t.id,
                    left.len()
                ),
                Err(e) => eprintln!("tombstone {}: past its horizon, and the listing failed; kept: {e}", t.id),
            }
        }
        reaped
    }

    /// **Residues are retried every pass** (RC9), whether or not Core still
    /// sends the machine: once Core ended the compute claim on a residue, the
    /// machine leaves the view, and nothing else would look again. Answers a
    /// self-check naming what is left, so the provider's board shows it.
    pub(crate) async fn retry_residues(&self, snippet_dir: &str) -> Option<omnuv_protocol::SelfCheck> {
        use omnuv_protocol::{CheckKind, CheckResult, SelfCheck};
        let dir = tombstones(snippet_dir);
        let mut left = Vec::new();
        for mut t in list_tombs(&dir).into_iter().filter(|t| !t.residue.is_empty()) {
            let Some(node) = t.node.clone() else { continue };
            let mut still = Vec::new();
            for volid in &t.residue {
                match self.volume_left(&node, volid).await {
                    Ok(false) => {}
                    Ok(true) | Err(_) => still.push(volid.clone()),
                }
            }
            if still != t.residue {
                t.residue = still.clone();
                if let Err(e) = write_tomb(&dir, &t) {
                    eprintln!("tombstone {}: {e}", t.id);
                }
            }
            left.extend(still.into_iter().map(|v| format!("{v} (machine {})", t.id)));
        }
        Some(SelfCheck {
            name: "teardown.residue".into(),
            kind: CheckKind::Presence,
            result: if left.is_empty() { CheckResult::Pass } else { CheckResult::Fail },
            detail: (!left.is_empty()).then(|| format!("volumes left by deleted machines: {}", left.join(", "))),
            subject: None,
        })
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

    /// The number a volume's name carries, and the nearest names that carry
    /// none.
    #[test]
    fn a_volume_says_which_number_it_was_made_for() {
        assert_eq!(volume_vmid("local-lvm:vm-9101-disk-0"), Some(9101));
        assert_eq!(volume_vmid("local-lvm:vm-9101-cloudinit"), Some(9101));
        assert_eq!(volume_vmid("zfs:base-9000-disk-1"), Some(9000));
        assert_eq!(volume_vmid("local-zfs:subvol-300-disk-0"), Some(300));
        assert_eq!(volume_vmid("local:9101/vm-9101-disk-0.qcow2"), Some(9101));
        for none in ["local:iso/ubuntu.iso", "local:import/onv-x.qcow2", "local-lvm:vm-disk-0", "local-lvm:vm-12x-disk-0", "vm9101"] {
            assert_eq!(volume_vmid(none), None, "{none}");
        }
    }

    /// A container's volumes are named too, so a leftover one of ours that a
    /// container mounts is never removed.
    #[test]
    fn a_containers_volumes_are_named_too() {
        let config = serde_json::json!({
            "rootfs": "local-lvm:subvol-300-disk-0,size=8G",
            "mp0": "local-lvm:vm-9101-disk-0,mp=/data",
            "mpx": "local-lvm:not-a-slot",
        });
        assert_eq!(
            named_volids(&config),
            vec!["local-lvm:subvol-300-disk-0".to_string(), "local-lvm:vm-9101-disk-0".to_string()]
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
                ("GET", p) if p.ends_with("/status/current") => (200, serde_json::json!({"status": "stopped"})),
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

    /// A host whose guests and volumes change as the agent acts: what a
    /// destroy removes, what it leaves (Proxmox drops a config even when
    /// freeing a disk fails), whether a volume's removal is refused, and
    /// whether the node answers.
    #[derive(Default)]
    struct Host {
        /// vmid, tags, description, the volumes its config names.
        guests: Vec<(u32, String, String, Vec<String>)>,
        volumes: Vec<String>,
        offline: bool,
        destroy_leaves_disks: bool,
        volume_delete_fails: bool,
    }

    async fn stateful(host: std::sync::Arc<std::sync::Mutex<Host>>) -> crate::pvemock::Mock {
        crate::pvemock::Mock::start(move |method, path, _| {
            if let Some(ok) = crate::pvemock::task_ok(path) {
                return ok;
            }
            let mut h = host.lock().unwrap();
            let listed = |h: &Host| {
                serde_json::json!(h.guests.iter().map(|g| serde_json::json!({"node": "n1", "vmid": g.0, "tags": g.1, "status": "stopped"})).collect::<Vec<_>>())
            };
            match (method, path) {
                ("GET", "/cluster/resources?type=vm") => (200, listed(&h)),
                ("GET", "/nodes/n1/qemu") => (200, listed(&h)),
                ("GET", "/nodes") => (200, serde_json::json!([{"node": "n1", "status": if h.offline { "offline" } else { "online" }}])),
                ("GET", "/nodes/n1/tasks?source=active") | ("GET", "/cluster/ha/resources") => (200, serde_json::json!([])),
                ("GET", p) if p.starts_with("/nodes/n1/qemu/") && p.ends_with("/status/current") => {
                    let vmid: u32 = p.split('/').nth(4).and_then(|v| v.parse().ok()).unwrap_or(0);
                    match h.guests.iter().any(|g| g.0 == vmid) {
                        true => (200, serde_json::json!({"status": "stopped"})),
                        false => (500, crate::pvemock::refusal(&format!("Configuration file 'nodes/n1/qemu-server/{vmid}.conf' does not exist"))),
                    }
                }
                ("GET", p) if p.starts_with("/nodes/n1/qemu/") && p.ends_with("/config") => {
                    let vmid: u32 = p.split('/').nth(4).and_then(|v| v.parse().ok()).unwrap_or(0);
                    match h.guests.iter().find(|g| g.0 == vmid) {
                        Some(g) => {
                            let mut c = serde_json::json!({"description": g.2});
                            for (i, v) in g.3.iter().enumerate() {
                                c[format!("scsi{i}")] = serde_json::json!(format!("{v},size=8G"));
                            }
                            (200, c)
                        }
                        None => (500, serde_json::Value::Null),
                    }
                }
                ("DELETE", p) if p.starts_with("/nodes/n1/qemu/") => {
                    let vmid: u32 = p.split('/').nth(4).and_then(|v| v.split('?').next()).and_then(|v| v.parse().ok()).unwrap_or(0);
                    if let Some(i) = h.guests.iter().position(|g| g.0 == vmid) {
                        let g = h.guests.remove(i);
                        if !h.destroy_leaves_disks {
                            h.volumes.retain(|v| !g.3.contains(v));
                        }
                    }
                    (200, serde_json::json!("UPID:n1:destroy"))
                }
                ("GET", p) if p.starts_with("/nodes/n1/storage/") && p.ends_with("/content") => {
                    let storage = p.split('/').nth(4).unwrap_or_default().to_string();
                    let here: Vec<serde_json::Value> = h
                        .volumes
                        .iter()
                        .filter(|v| v.starts_with(&format!("{storage}:")))
                        .map(|v| serde_json::json!({"volid": v}))
                        .collect();
                    (200, serde_json::json!(here))
                }
                ("DELETE", p) if p.starts_with("/nodes/n1/storage/") => {
                    if h.volume_delete_fails {
                        return (500, serde_json::Value::Null);
                    }
                    let volid = p.rsplit('/').next().unwrap_or_default().replace("%3A", ":");
                    h.volumes.retain(|v| *v != volid);
                    (200, serde_json::Value::Null)
                }
                _ => (404, serde_json::Value::Null),
            }
        })
        .await
    }

    const DISK: &str = "local-lvm:vm-9101-disk-0";
    const CLOUDINIT: &str = "local-lvm:vm-9101-cloudinit";
    /// A volume at the machine's VMID that its config never named: somebody
    /// else's, which no delete of this machine may take.
    const FOREIGN: &str = "local-lvm:vm-9101-disk-7";

    fn machine() -> std::sync::Arc<std::sync::Mutex<Host>> {
        let (vmid, tags, stamp) = ours(9101, ID);
        std::sync::Arc::new(std::sync::Mutex::new(Host {
            guests: vec![(vmid, tags, stamp, vec![DISK.to_string(), CLOUDINIT.to_string()])],
            volumes: vec![DISK.to_string(), CLOUDINIT.to_string(), FOREIGN.to_string()],
            ..Default::default()
        }))
    }

    fn state_dir(name: &str) -> (std::path::PathBuf, String) {
        let root = std::env::temp_dir().join(format!("onv-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("snippets");
        std::fs::create_dir_all(&dir).unwrap();
        (root, dir.to_string_lossy().to_string())
    }

    async fn pass(mock: &crate::pvemock::Mock, dir: &str) -> Gone {
        mock.client().delete_instance("n1", ID, dir, &[], async { Ok(true) }).await.expect("a pass")
    }

    fn deletes(mock: &crate::pvemock::Mock) -> Vec<String> {
        destroyed(mock)
    }

    /// **A delete is proven one listing later** (RC1, TD3). The pass that
    /// destroys says only that; the next pass's complete listing says
    /// `deleted`; every pass after says it again and destroys nothing. The
    /// volume at the machine's VMID that its config never named survives.
    #[tokio::test]
    async fn a_delete_is_proven_one_listing_later() {
        let (root, dir) = state_dir("proven-later");
        let host = machine();
        let mock = stateful(host.clone()).await;

        let first = pass(&mock, &dir).await;
        assert!(matches!(&first, Gone::NotYet(why) if why.contains("was destroyed")), "{first:?}");
        assert_ne!(said(&first), "deleted", "the destroy's own pass said deleted");
        assert_eq!(deletes(&mock), vec!["/nodes/n1/qemu/9101?purge=1&destroy-unreferenced-disks=0".to_string()]);

        assert_eq!(pass(&mock, &dir).await, Gone::Proven);
        assert_eq!(said(&Gone::Proven), "deleted");
        assert_eq!(pass(&mock, &dir).await, Gone::Proven, "a proof said again changed");
        assert_eq!(deletes(&mock).len(), 1, "something else was deleted: {:?}", deletes(&mock));
        assert_eq!(host.lock().unwrap().volumes, vec![FOREIGN.to_string()], "a volume the config never named was taken");
        assert!(built_again(&dir, ID).is_some(), "a proven machine may be built again under its id");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **A left volume gives a residue** (the roadmap's pass for row 7). The
    /// destroy finishes OK and leaves both disks; asked to go, they refuse.
    /// The proof names them — never `deleted` — and they are retried every
    /// pass until they go, the provider's board saying so meanwhile.
    #[tokio::test]
    async fn a_left_volume_is_a_residue() {
        let (root, dir) = state_dir("residue");
        let host = machine();
        {
            let mut h = host.lock().unwrap();
            h.destroy_leaves_disks = true;
            h.volume_delete_fails = true;
        }
        let mock = stateful(host.clone()).await;
        assert!(matches!(pass(&mock, &dir).await, Gone::NotYet(_)));
        let second = pass(&mock, &dir).await;
        assert_eq!(second, Gone::Residue(vec![CLOUDINIT.to_string(), DISK.to_string()]));
        assert_eq!(said(&second), format!("deleted; residue {CLOUDINIT} {DISK}"));
        assert!(
            mock.calls.lock().unwrap().iter().any(|c| c.method == "DELETE" && c.path.contains("/storage/local-lvm/content/")),
            "the left volumes were never asked to go"
        );
        let check = mock.client().retry_residues(&dir).await.expect("a check");
        assert_eq!(check.result, omnuv_protocol::CheckResult::Fail);
        assert!(check.detail.as_deref().unwrap_or_default().contains(DISK), "{check:?}");

        // They go when they can: the residue closes, and the board says so.
        host.lock().unwrap().volume_delete_fails = false;
        let check = mock.client().retry_residues(&dir).await.expect("a check");
        assert_eq!(check.result, omnuv_protocol::CheckResult::Pass, "{check:?}");
        assert_eq!(host.lock().unwrap().volumes, vec![FOREIGN.to_string()]);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **An offline node holding k's disk blocks k** (the roadmap's cost for
    /// row 7): nothing on it can be listed, so nothing is proven, and the
    /// claim stays held until it answers.
    #[tokio::test]
    async fn an_offline_node_holding_the_disk_blocks_the_proof() {
        let (root, dir) = state_dir("offline-node");
        let host = machine();
        let mock = stateful(host.clone()).await;
        assert!(matches!(pass(&mock, &dir).await, Gone::NotYet(_)));
        host.lock().unwrap().offline = true;
        let blocked = pass(&mock, &dir).await;
        assert!(matches!(&blocked, Gone::NotYet(why) if why.contains("does not answer")), "{blocked:?}");
        host.lock().unwrap().offline = false;
        assert_eq!(pass(&mock, &dir).await, Gone::Proven);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Nothing ever built here: the pass's own complete listing proves it,
    /// and the answer is remembered like a destroy's.
    #[tokio::test]
    async fn a_machine_never_built_here_is_proven_by_one_listing() {
        let (root, dir) = state_dir("never-built");
        let host = std::sync::Arc::new(std::sync::Mutex::new(Host::default()));
        let mock = stateful(host).await;
        assert_eq!(pass(&mock, &dir).await, Gone::Proven);
        assert!(deletes(&mock).is_empty());
        assert!(built_again(&dir, ID).is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **A worker is an attempt as a machine is** (lifecycle phase 7): its
    /// delete goes through the same licence, the same tombstone and the same
    /// proof one listing later, a left volume included.
    #[tokio::test]
    async fn a_worker_delete_is_proven_one_listing_later() {
        let (root, dir) = state_dir("worker-proven");
        let tags = crate::names::tags(crate::names::TAG_WORKER, ID, Some("test"));
        let stamp = crate::names::description(crate::names::TAG_WORKER, ID);
        let host = std::sync::Arc::new(std::sync::Mutex::new(Host {
            guests: vec![(9101, tags, stamp, vec![DISK.to_string()])],
            volumes: vec![DISK.to_string()],
            destroy_leaves_disks: true,
            volume_delete_fails: true,
            ..Default::default()
        }));
        let mock = stateful(host.clone()).await;
        let pass = || async { mock.client().delete_inference_worker(ID, &dir, &[], async { Ok(true) }).await.expect("a pass") };
        assert!(matches!(pass().await, Gone::NotYet(_)), "the destroy's own pass proved the worker gone");
        assert_eq!(pass().await, Gone::Residue(vec![DISK.to_string()]));
        assert!(built_again(&dir, ID).is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **A tombstone past its horizon goes, after a look** (R1's rule 10,
    /// D13; re-observe before concluding). Four tombstones: an old one with
    /// nothing left carrying its claim goes; an old one whose claim a guest
    /// still carries stays; a recent one stays; an old one with a residue
    /// stays.
    #[tokio::test]
    async fn a_tombstone_past_its_horizon_goes_only_after_a_look() {
        let (root, dir) = state_dir("tomb-reap");
        let tombs = tombstones(&dir);
        let long_ago = now() - 40 * 24 * 3600;
        let tomb = |id: &str, proven_at: i64, residue: Vec<String>| Tombstone {
            id: id.to_string(),
            claim: crate::names::TAG_INSTANCE.to_string(),
            node: Some("n1".into()),
            vmid: Some(9101),
            volids: Vec::new(),
            destroyed_at: Some(proven_at),
            proven_at: Some(proven_at),
            residue,
        };
        write_tomb(&tombs, &tomb(ID, long_ago, vec![])).unwrap();
        write_tomb(&tombs, &tomb(TWIN_ELSEWHERE, long_ago, vec![])).unwrap();
        write_tomb(&tombs, &tomb(RECENT, now() - 3600, vec![])).unwrap();
        write_tomb(&tombs, &tomb(LEFT, long_ago, vec![DISK.to_string()])).unwrap();
        // A guest still carries TWIN_ELSEWHERE's claim.
        let (vmid, tags, stamp) = ours(9200, TWIN_ELSEWHERE);
        let host = std::sync::Arc::new(std::sync::Mutex::new(Host {
            guests: vec![(vmid, tags, stamp, vec![])],
            ..Default::default()
        }));
        let mock = stateful(host).await;
        let reaped = mock.client().reap_tombstones(&dir, crate::dur::Dur::hours(30 * 24)).await;
        assert_eq!(reaped, 1);
        let left: Vec<String> = list_tombs(&tombs).into_iter().map(|t| t.id).collect();
        let mut want = vec![TWIN_ELSEWHERE.to_string(), RECENT.to_string(), LEFT.to_string()];
        want.sort();
        assert_eq!(left, want, "the wrong tombstones went");
        let _ = std::fs::remove_dir_all(&root);
    }

    const TWIN_ELSEWHERE: &str = "1b2c3d4e-5f60-4a0b-8c1d-2e3f4a5b6c7d";
    const RECENT: &str = "2c3d4e5f-6071-4a0b-8c1d-2e3f4a5b6c7d";
    const LEFT: &str = "3d4e5f60-7182-4a0b-8c1d-2e3f4a5b6c7d";

    /// A host whose cluster listing lags the node, as `/cluster/resources`
    /// does (pvestatd refreshes it every 10 s): guest 9301 reads `stopped`
    /// there while the node's own status says `running`, because it was
    /// started a moment ago. Proxmox refuses to destroy a running guest with a
    /// 500 whose reason says so, as it did on nuc0 on 26 September.
    async fn lagging(stop_takes: bool) -> (crate::pvemock::Mock, std::sync::Arc<std::sync::atomic::AtomicBool>) {
        use std::sync::atomic::{AtomicBool, Ordering};
        let running = std::sync::Arc::new(AtomicBool::new(true));
        let exists = std::sync::Arc::new(AtomicBool::new(true));
        let (live, there) = (running.clone(), exists.clone());
        let (_, tags, stamp) = ours(9301, ID);
        let mock = crate::pvemock::Mock::start(move |method, path, _| {
            if let Some(ok) = crate::pvemock::task_ok(path) {
                return ok;
            }
            let listed = || {
                if there.load(Ordering::SeqCst) {
                    // Stale: the listing has not caught up with the start.
                    serde_json::json!([{"node": "n1", "vmid": 9301, "tags": tags, "status": "stopped"}])
                } else {
                    serde_json::json!([])
                }
            };
            match (method, path) {
                ("GET", "/cluster/resources?type=vm") | ("GET", "/nodes/n1/qemu") => (200, listed()),
                ("GET", "/nodes") => (200, serde_json::json!([{"node": "n1", "status": "online"}])),
                ("GET", "/nodes/n1/qemu/9301/config") => {
                    (200, serde_json::json!({"description": stamp, "scsi0": "local-lvm:vm-9301-disk-0,size=8G"}))
                }
                ("GET", "/nodes/n1/qemu/9301/status/current") => (
                    200,
                    serde_json::json!({"status": if live.load(Ordering::SeqCst) { "running" } else { "stopped" }}),
                ),
                ("POST", "/nodes/n1/qemu/9301/status/stop") => {
                    if stop_takes {
                        live.store(false, Ordering::SeqCst);
                    }
                    (200, serde_json::json!("UPID:n1:stop"))
                }
                ("DELETE", "/nodes/n1/qemu/9301?purge=1&destroy-unreferenced-disks=0") => {
                    if live.load(Ordering::SeqCst) {
                        return (500, crate::pvemock::refusal("VM 9301 is running - destroy failed"));
                    }
                    there.store(false, Ordering::SeqCst);
                    (200, serde_json::json!("UPID:n1:destroy"))
                }
                _ => (404, serde_json::Value::Null),
            }
        })
        .await;
        (mock, running)
    }

    /// Method and path of every call that changes something, in order.
    fn acts(mock: &crate::pvemock::Mock) -> Vec<String> {
        mock.calls.lock().unwrap().iter().filter(|c| c.method != "GET").map(|c| format!("{} {}", c.method, c.path)).collect()
    }

    /// **A guest started a moment ago is stopped before it is destroyed**
    /// (the regression of 26 September on nuc0). Core named the machine
    /// Absent in the second its create finished; the cluster listing still
    /// said `stopped`, the stop was skipped on that word, and Proxmox refused
    /// the destroy of a running guest. The destroy asks the node, now.
    #[tokio::test]
    async fn a_guest_started_a_moment_ago_is_stopped_before_it_is_destroyed() {
        let (root, dir) = state_dir("started-just-now");
        let (mock, running) = lagging(true).await;
        let gone = mock.client().delete_instance("n1", ID, &dir, &[], async { Ok(true) }).await;
        assert!(matches!(&gone, Ok(Gone::NotYet(why)) if why.contains("was destroyed")), "{gone:?}");
        assert_eq!(
            acts(&mock),
            vec![
                "POST /nodes/n1/qemu/9301/status/stop".to_string(),
                "DELETE /nodes/n1/qemu/9301?purge=1&destroy-unreferenced-disks=0".to_string(),
            ],
            "the running guest was not stopped first"
        );
        assert!(!running.load(std::sync::atomic::Ordering::SeqCst));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **A guest the stop did not stop is not destroyed**: the node still
    /// says it runs, so the destroy is not asked for, and the delete says why.
    #[tokio::test]
    async fn a_guest_still_running_after_its_stop_is_not_destroyed() {
        let (root, dir) = state_dir("stop-did-not-take");
        let (mock, _) = lagging(false).await;
        let e = mock.client().delete_instance("n1", ID, &dir, &[], async { Ok(true) }).await.expect_err("destroyed while running");
        assert!(e.to_string().contains("running"), "{e:#}");
        assert!(
            !acts(&mock).iter().any(|a| a.starts_with("DELETE")),
            "a destroy was asked for while the node said the guest runs: {:?}",
            acts(&mock)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **A volume name a new guest took is not ours to remove** (the class of
    /// the regression: a record trusted after the world moved). A deleted
    /// machine's tombstone names `vm-9101-disk-0`; its VMID was given to the
    /// next clone, whose disk took the same name, and whose configuration does
    /// not name it yet (a full clone writes its disks into the configuration
    /// when the copy ends). The volume survives the proof and the retries.
    #[tokio::test]
    async fn a_volume_name_a_new_guest_took_is_not_removed() {
        let (root, dir) = state_dir("vmid-reused");
        let host = machine();
        let mock = stateful(host.clone()).await;
        assert!(matches!(pass(&mock, &dir).await, Gone::NotYet(_)));
        {
            // The destroy took both disks; the next clone takes VMID 9101 and
            // allocates the same first disk name, not yet in its config.
            let mut h = host.lock().unwrap();
            assert_eq!(h.volumes, vec![FOREIGN.to_string()]);
            h.guests.push((9101, String::new(), "a clone in progress".into(), vec![]));
            h.volumes.push(DISK.to_string());
        }
        let proven = pass(&mock, &dir).await;
        assert!(host.lock().unwrap().volumes.contains(&DISK.to_string()), "the new guest's disk was removed: {proven:?}");
        let _ = mock.client().retry_residues(&dir).await;
        assert!(host.lock().unwrap().volumes.contains(&DISK.to_string()), "a retry removed the new guest's disk");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **Proxmox's reason travels with a refusal** (the regression's log said
    /// only "500 Internal Server Error"). A destroy, a read and a form call
    /// that Proxmox refuses each carry its reason, from the status line and
    /// the body, and never the token.
    #[tokio::test]
    async fn a_refusal_says_what_proxmox_said() {
        let mock = crate::pvemock::Mock::start(|method, path, _| match (method, path) {
            ("DELETE", "/nodes/n1/qemu/100") => (500, crate::pvemock::refusal("VM 100 is running - destroy failed")),
            ("GET", "/cluster/resources?type=vm") => (500, crate::pvemock::refusal("cluster not ready - no quorum?")),
            ("POST", "/nodes/n1/qemu/100/status/start") => (500, crate::pvemock::refusal("VM 100 already running")),
            ("GET", "/version") => (403, crate::pvemock::refusal("Permission check failed (onv@pve!agent, Sys.Audit)")),
            _ => (404, serde_json::Value::Null),
        })
        .await;
        let px = mock.client();
        let e = px.delete_task::<String>("/nodes/n1/qemu/100").await.expect_err("refused").to_string();
        assert!(e.contains("VM 100 is running - destroy failed"), "the destroy's refusal lost its reason: {e}");
        let e = px.get_json::<serde_json::Value>("/cluster/resources?type=vm").await.expect_err("refused").to_string();
        assert!(e.contains("no quorum"), "the read's refusal lost its reason: {e}");
        let e = px
            .post_form::<serde_json::Value>("/nodes/n1/qemu/100/status/start", &[] as &[(String, String)])
            .await
            .expect_err("refused")
            .to_string();
        assert!(e.contains("VM 100 already running"), "the form call's refusal lost its reason: {e}");
        let e = px.get_json::<serde_json::Value>("/version").await.expect_err("refused").to_string();
        assert!(e.contains("Permission check failed") && e.contains("Sys.Audit"), "{e}");
        assert!(!e.contains("onv@pve!agent") && !e.contains("secret"), "the token reached the message: {e}");
    }
}
