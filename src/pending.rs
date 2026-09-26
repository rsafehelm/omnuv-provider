//! **A clone this agent started and has not finished (PROVIDER-1, 22 September
//! 2026).** Proxmox's clone takes no tags, so a machine is untagged from the
//! moment it exists until the create path puts its claim on. The wait for the
//! clone sat before the rollback scope: one failed status read, a clone past
//! the ten-minute cap, or a restart mid-clone returned early, and left a full
//! disk no sweep recognises. The next pass, finding nothing tagged, cloned
//! again.
//!
//! So the intent is written down before the clone is asked for, the task id
//! beside it once Proxmox answers, and the entry is removed when there is
//! nothing left owed. An entry left behind is work this agent never saw
//! finish; `InstanceDriver::recover_pending` settles it.
//!
//! One JSON file per VMID, under `<state>/pending-clones`, beside the snippet
//! directory: the agent's service may write there, and nothing else reads it.
//!
//! ## What a record means, and when it goes (26 September 2026)
//!
//! A record used to live from the clone request until the machine was built
//! **and started**, and was settled only at the start of the next create. Four
//! defects came out of that one sentence, and they are one family: *the
//! journal was settled at create time only*. It is settled on every reconcile
//! pass now, before anything is created or deleted, and it says which of two
//! things is owed:
//!
//! ```text
//! Cloning     a clone was asked for and this agent has not seen the machine
//!             become a complete one. Settling it takes away what was made.
//! Abandoned   the create gave up, and the destroy was asked for and not seen
//!             to succeed. Settling it asks again.
//! ```
//!
//! **A complete machine is one that is configured, not one that is running.**
//! The record goes the moment the last configuring call has settled, before
//! the start — the start is convergence, which every later pass does anyway,
//! and an agent stopped inside it used to leave a record that the next create
//! read as a leftover clone and destroyed. That is RC4, a running machine
//! destroyed without Core saying Absent, found by the lifecycle model's family
//! A2 and never met on hardware.

use std::path::{Path, PathBuf};

/// What a record says is owed. See the module's note.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// A clone was asked for; this agent has not seen it become a machine it
    /// can find by its tag. The default, and what every record written before
    /// this field existed means.
    #[default]
    Cloning,
    /// The rollback is owed. Written *before* the destroy is asked for, so an
    /// agent stopped inside a rollback still owes it, and kept until the
    /// machine is seen to be gone.
    Abandoned,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingClone {
    pub vmid: u32,
    /// The marketplace id of the machine it is for.
    pub id: String,
    pub node: String,
    /// Proxmox's task id, once the clone request was answered.
    #[serde(default)]
    pub upid: Option<String>,
    /// The claim the machine is to carry: an instance's or a worker's. A
    /// record from before workers were journalled is an instance's.
    #[serde(default = "instance_claim")]
    pub claim: String,
    /// What is owed. A record from before this field is a clone's.
    #[serde(default)]
    pub stage: Stage,
}

impl PendingClone {
    /// The same record, with the rollback owed.
    pub fn abandoned(&self) -> Self {
        Self { stage: Stage::Abandoned, ..self.clone() }
    }

    /// What a report says this record is waiting on.
    pub fn waiting_on(&self) -> String {
        match self.stage {
            Stage::Cloning => format!("the clone of vm {} to finish", self.vmid),
            Stage::Abandoned => format!("vm {} to be taken away", self.vmid),
        }
    }
}

fn instance_claim() -> String {
    crate::names::TAG_INSTANCE.to_string()
}

pub fn dir(snippet_dir: &str) -> PathBuf {
    Path::new(snippet_dir).parent().unwrap_or(Path::new("/var/lib/onv")).join("pending-clones")
}

fn file(dir: &Path, vmid: u32) -> PathBuf {
    dir.join(format!("{vmid}.json"))
}

/// Written before anything it describes happens, so a failure here stops
/// the clone rather than leaving it unrecorded.
pub fn write(dir: &Path, entry: &PendingClone) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let raw = serde_json::to_vec(entry)?;
    crate::names::write_private(&file(dir, entry.vmid).to_string_lossy(), &raw, 0o600)
        .map_err(|e| anyhow::anyhow!("recording the pending clone of {}: {e}", entry.vmid))
}

pub fn remove(dir: &Path, vmid: u32) {
    if let Err(e) = std::fs::remove_file(file(dir, vmid))
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("pending clone {vmid}: record not removed: {e}");
    }
}

/// Every entry that parses. One that does not is reported and left, because
/// deleting what cannot be read would lose the only record of a clone.
pub fn list(dir: &Path) -> Vec<PendingClone> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut out = Vec::new();
    for e in entries.flatten() {
        match std::fs::read(e.path()).map_err(anyhow::Error::from).and_then(|raw| Ok(serde_json::from_slice(&raw)?)) {
            Ok(entry) => out.push(entry),
            Err(err) => eprintln!("pending clone record {} unreadable: {err}", e.path().display()),
        }
    }
    out.sort_by_key(|p: &PendingClone| p.vmid);
    out
}

/// **What is owed for one machine** — the check a create and a delete both
/// make before they conclude anything (gaps 1 and 2, 25 September 2026).
///
/// A create whose earlier clone is still running must not start a second one,
/// and a delete that finds nothing carrying the claim must not report the
/// machine gone: a clone is untagged until the create finishes, and a rollback
/// that failed leaves a shell. The lowest VMID, so an answer is stable when
/// more than one record names the same machine.
pub fn owed_for(dir: &Path, id: &str) -> Option<PendingClone> {
    list(dir).into_iter().find(|p| p.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_is_written_read_and_removed() {
        let dir = std::env::temp_dir().join(format!("onv-pending-{}", std::process::id()));
        let entry = PendingClone {
            vmid: 9301,
            id: "i-1".into(),
            node: "n1".into(),
            upid: None,
            claim: instance_claim(),
            stage: Stage::Cloning,
        };
        write(&dir, &entry).unwrap();
        let with_task = PendingClone { upid: Some("UPID:n1:clone".into()), ..entry.clone() };
        write(&dir, &with_task).unwrap();
        assert_eq!(list(&dir), vec![with_task.clone()]);
        assert_eq!(owed_for(&dir, "i-1"), Some(with_task));
        assert_eq!(owed_for(&dir, "i-2"), None, "another machine's record was taken for this one's");
        remove(&dir, 9301);
        assert!(list(&dir).is_empty());
        remove(&dir, 9301);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A record written before the claim was recorded is an instance's, and
    /// one written before the stage was is a clone's — the reading that keeps
    /// an agent upgraded mid-create settling what the old one left.
    #[test]
    fn an_older_record_is_an_instances() {
        let old: PendingClone = serde_json::from_str(r#"{"vmid":1,"id":"i","node":"n","upid":null}"#).unwrap();
        assert_eq!(old.claim, crate::names::TAG_INSTANCE);
        assert_eq!(old.stage, Stage::Cloning);
    }

    /// The stage is a value on the wire, not only in memory.
    #[test]
    fn a_stage_survives_the_file() {
        let dir = std::env::temp_dir().join(format!("onv-pending-stage-{}", std::process::id()));
        let entry = PendingClone {
            vmid: 9302,
            id: "i-2".into(),
            node: "n1".into(),
            upid: Some("UPID:n1:clone".into()),
            claim: instance_claim(),
            stage: Stage::Cloning,
        };
        write(&dir, &entry).unwrap();
        write(&dir, &entry.abandoned()).unwrap();
        assert_eq!(list(&dir)[0].stage, Stage::Abandoned);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
