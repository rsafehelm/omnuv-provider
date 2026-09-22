//! **A clone this agent started and has not finished (PROVIDER-1, 22 September
//! 2026).** Proxmox's clone takes no tags, so a machine is untagged from the
//! moment it exists until the create path puts its claim on. The wait for the
//! clone sat before the rollback scope: one failed status read, a clone past
//! the ten-minute cap, or a restart mid-clone returned early, and left a full
//! disk no sweep recognises. The next pass, finding nothing tagged, cloned
//! again.
//!
//! So the intent is written down before the clone is asked for, the task id
//! beside it once Proxmox answers, and the entry is removed only when the
//! machine is claimed and built, or rolled back. An entry left behind is a
//! clone whose end this agent never saw; `InstanceDriver::recover_pending`
//! settles it on a later create.
//!
//! One JSON file per VMID, under `<state>/pending-clones`, beside the snippet
//! directory: the agent's service may write there, and nothing else reads it.

use std::path::{Path, PathBuf};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_is_written_read_and_removed() {
        let dir = std::env::temp_dir().join(format!("onv-pending-{}", std::process::id()));
        let entry = PendingClone { vmid: 9301, id: "i-1".into(), node: "n1".into(), upid: None, claim: instance_claim() };
        write(&dir, &entry).unwrap();
        let with_task = PendingClone { upid: Some("UPID:n1:clone".into()), ..entry.clone() };
        write(&dir, &with_task).unwrap();
        assert_eq!(list(&dir), vec![with_task]);
        remove(&dir, 9301);
        assert!(list(&dir).is_empty());
        remove(&dir, 9301);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A record written before the claim was recorded is an instance's.
    #[test]
    fn an_older_record_is_an_instances() {
        let old: PendingClone = serde_json::from_str(r#"{"vmid":1,"id":"i","node":"n","upid":null}"#).unwrap();
        assert_eq!(old.claim, crate::names::TAG_INSTANCE);
    }
}
