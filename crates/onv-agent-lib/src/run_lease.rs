//! **The run lease's file and its lock** (lifecycle phase 12; moved here
//! from the agent's `lease.rs` by omnuv's modular design, A3): what the
//! agent's lease task writes and holds, and what the host timer
//! (`onv-lease-expire`, its own crate) reads and defers to. One copy, so the
//! two read one file by one rule and lock one lock.
//!
//! The agent writes `run-lease.json` (each leased machine's wall-clock
//! deadline) and holds `run-lease.lock` for as long as its lease task runs;
//! the timer acts only when it can take that lock itself.

use std::time::Duration;

/// One lease as the file holds it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Written {
    pub id: String,
    pub until_unix: u64,
}

/// **The file read strictly**, by the agent at start and by the host timer:
/// empty (nothing written, or only whitespace) is no lease; otherwise it is
/// `{"leases": [{"id", "until_unix"}, …]}` with every id non-empty, or it is
/// refused whole and nothing in it is acted on.
pub fn read_body(body: &str) -> Result<Vec<Written>, String> {
    #[derive(serde::Deserialize)]
    struct File {
        leases: Vec<Written>,
    }
    if body.trim().is_empty() {
        return Ok(Vec::new());
    }
    let f: File = serde_json::from_str(body).map_err(|e| format!("not a run-lease file: {e}"))?;
    if let Some(n) = f.leases.iter().position(|l| l.id.trim().is_empty()) {
        return Err(format!("lease {n} names no machine"));
    }
    Ok(f.leases)
}

/// How often the lease task looks, and so writes the file. The host timer's
/// staleness bound is derived from it (`onv_lease_expire::STALE_AFTER`).
pub const WRITE_EVERY: Duration = Duration::from_secs(30);

/// The lock that says the lease task is running, beside the file.
pub fn lock_file(file: &std::path::Path) -> std::path::PathBuf {
    file.with_extension("lock")
}

/// Opens the lock file, creating it when it is not there, never truncating
/// anything. **Read-only when it exists**: `flock` needs no write access, so a
/// lock file another user made (a person running the timer by hand as root)
/// still locks, rather than leaving the agent's task to run without it.
pub fn open_lock(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    match std::fs::File::open(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(path)
        }
        opened => opened,
    }
}

/// Where the file goes: beside the restore head.
pub fn file(snippet_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(snippet_dir).parent().unwrap_or(std::path::Path::new("/var/lib/onv")).join("run-lease.json")
}
