//! **Which console password a machine holds (BUYER-18, 23 September 2026).**
//!
//! Core sends the password as a destination: a crypt(3) hash and its
//! generation, 0 for the one cloud-init set at first boot and one more for
//! each reset the buyer asked for. The agent sets a newer one on a running
//! machine through the guest agent, and writes down the generation it set so
//! the next pass does not ask the guest again.
//!
//! Unlike a reboot, setting a password twice is harmless: the same hash lands
//! on the same user. So this file saves calls and decides nothing. A lost
//! record is read as 0 — the first-boot password — and costs one repeated
//! `set-user-password`, never a wrong state.

use std::path::{Path, PathBuf};

pub fn dir(snippet_dir: &str) -> PathBuf {
    Path::new(snippet_dir).parent().unwrap_or(Path::new("/var/lib/onv")).join("console-passwords")
}

fn path(dir: &Path, id: &str) -> PathBuf {
    // An id is a uuid from Core; anything else is not a file name we write.
    let safe: String = id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
    dir.join(safe)
}

/// The generation last set on this machine; 0, the first-boot one, when
/// nothing was ever written down.
pub fn applied(dir: &Path, id: &str) -> u32 {
    std::fs::read_to_string(path(dir, id)).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

/// Through a temporary file and a rename, so a crash leaves one whole number.
pub fn record(dir: &Path, id: &str, generation: u32) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let target = path(dir, id);
    let tmp = target.with_extension("tmp");
    std::fs::write(&tmp, generation.to_string())?;
    std::fs::rename(&tmp, &target)?;
    Ok(())
}

pub fn remove(dir: &Path, id: &str) {
    let _ = std::fs::remove_file(path(dir, id));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_written_is_the_first_boot_password_and_an_id_stays_in_its_directory() {
        let dir = std::env::temp_dir().join(format!("onv-passwords-{}", std::process::id()));
        assert_eq!(applied(&dir, "m-1"), 0);
        record(&dir, "../../etc/shadow", 3).unwrap();
        assert!(dir.join("etcshadow").exists(), "the id was not confined to the journal");
        assert_eq!(applied(&dir, "../../etc/shadow"), 3);
        remove(&dir, "../../etc/shadow");
        assert_eq!(applied(&dir, "../../etc/shadow"), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
