//! **A reboot is performed once per token (PROVIDER-4, 22 September 2026).**
//!
//! Core asks for a reboot with an identity — `reboot_token` — because it has no
//! noun for "restart" (R3: a verb is used only where no noun exists, and then it
//! carries an identity so it is applied exactly once). The agent performed it,
//! echoed the token, and kept no memory of having done so. So a reboot whose
//! wait failed, or whose report was lost or dropped, was performed again on the
//! next pass, with the token still in desired state: a buyer's machine
//! restarted twice for one request, which is exactly what the identity exists
//! to prevent.
//!
//! One JSON file per machine under `<state>/reboots`, beside the pending-clone
//! journal, written **before** the reboot is asked for:
//!
//! ```text
//! asked   the request was sent; whether it happened is not yet seen
//! done    it happened; the token is echoed until Core stops sending it
//! ```
//!
//! An `asked` record is settled by observation — the guest's uptime is shorter
//! than the time since the request — and never by asking again. At most once:
//! a reboot that may not have happened is reported as unconfirmed by Core's own
//! deadline, which is honest; one performed twice cannot be taken back.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Reboot {
    pub token: String,
    /// Unix seconds, from this host's clock, when the request was sent.
    pub asked_at: u64,
    pub done: bool,
}

pub fn dir(snippet_dir: &str) -> PathBuf {
    Path::new(snippet_dir).parent().unwrap_or(Path::new("/var/lib/onv")).join("reboots")
}

fn path(dir: &Path, id: &str) -> PathBuf {
    // An id is a uuid from Core; anything else is not a file name we write.
    let safe: String = id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
    dir.join(format!("{safe}.json"))
}

pub fn read(dir: &Path, id: &str) -> Option<Reboot> {
    let text = std::fs::read_to_string(path(dir, id)).ok()?;
    serde_json::from_str(&text).ok()
}

/// Written through a temporary file and a rename, so a crash mid-write leaves
/// the old record or the new one, never half of either.
pub fn write(dir: &Path, id: &str, r: &Reboot) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let target = path(dir, id);
    let tmp = target.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(r)?)?;
    std::fs::rename(&tmp, &target)?;
    Ok(())
}

pub fn remove(dir: &Path, id: &str) {
    let _ = std::fs::remove_file(path(dir, id));
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether an `asked` reboot is seen to have happened: the guest has been up
/// for less time than has passed since the request. The slack covers the two
/// clocks' reading moments, not a guess about boot time.
pub fn happened(r: &Reboot, uptime_secs: Option<u64>, now: u64) -> bool {
    matches!(uptime_secs, Some(up) if up <= now.saturating_sub(r.asked_at) + 5)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_survives_and_an_id_cannot_leave_its_directory() {
        let dir = std::env::temp_dir().join(format!("onv-reboots-{}", std::process::id()));
        let r = Reboot { token: "t-1".into(), asked_at: 100, done: false };
        write(&dir, "../../etc/passwd", &r).unwrap();
        assert!(dir.join("etcpasswd.json").exists(), "the id was not confined to the journal");
        assert_eq!(read(&dir, "../../etc/passwd"), Some(r));
        remove(&dir, "../../etc/passwd");
        assert_eq!(read(&dir, "../../etc/passwd"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Up for less time than since the request: it happened. Up for longer, or
    /// the uptime unknown: not seen — which is never taken as "do it again".
    #[test]
    fn a_reboot_is_seen_by_the_guests_uptime_and_only_by_it() {
        let r = Reboot { token: "t".into(), asked_at: 1_000, done: false };
        assert!(happened(&r, Some(30), 1_060));
        assert!(!happened(&r, Some(3_600), 1_060), "a guest up for an hour did not reboot a minute ago");
        assert!(!happened(&r, None, 1_060), "an unknown uptime is not an observation");
    }
}
