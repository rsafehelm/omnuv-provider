//! Collecting cloud-init snippets whose machine is gone — and refusing to when
//! we cannot tell.
//!
//! Phase 0b of `R1R2R3_planv2.md`. The delete path removes a machine's snippet
//! best-effort, because a stuck file must never stop a machine being deleted.
//! That trade is only safe if something looks again, and this is that something.
//!
//! **Why this is written defensively rather than tidily.** The directory holds
//! files that carry SSH keys, private addressing and hashed console passwords.
//! Deleting one belonging to a machine that is still being created destroys a
//! boot that has not happened yet. So every rule here is a refusal:
//!
//! ```text
//! a prefix is recognition, not authority   a complete grammar and a claim
//! absence is not disposability             a worker mid-creation has no VM yet
//! partial discovery collects nothing       a short listing is not a short world
//! uncertain origin is reported             never collected
//! ```
//!
//! The last three are the same rule the watchers in `CLAUDE.md` are held to: an
//! incomplete reading may not be acted on as if it were a complete one.

use std::collections::BTreeSet;

use crate::names::{snippet_owner, SnippetKind};

/// What the provider knows about its machines, as far as it managed to look.
///
/// `complete` is the whole point. A failed Proxmox listing, a truncated desired
/// state, or an error reading the directory all produce an incomplete view, and
/// an incomplete view collects nothing.
#[derive(Debug, Clone, Default)]
pub struct Known {
    /// Marketplace ids with a VM on this provider right now.
    pub live: BTreeSet<String>,
    /// Marketplace ids Core currently wants, whether or not they exist yet.
    /// A worker being created is in here and has no VM, which is exactly the
    /// case runtime absence gets wrong.
    pub desired: BTreeSet<String>,
    /// False if any of the above could not be fully determined.
    pub complete: bool,
}

/// What a sweep decided, and why. Returned rather than logged so a caller can
/// assert on it and a test can read it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Swept {
    /// Files removed, by name.
    pub collected: Vec<String>,
    /// Files kept because a live or desired machine needs them.
    pub kept: usize,
    /// Files whose grammar is ours but whose origin is uncertain — a legacy
    /// worker name for an id nothing claims. Reported, never removed.
    pub uncertain: Vec<String>,
    /// Files that are not ours at all. Untouched, and counted so a directory
    /// full of somebody else's things is visible rather than silent.
    pub foreign: usize,
    /// Removals that failed. The next sweep tries again, which is the point.
    pub failed: Vec<String>,
    /// Set when nothing was collected because the view was incomplete.
    pub refused: Option<String>,
}

/// Collect snippets whose machine neither exists nor is wanted.
///
/// `remove` is injected so the decision logic is testable over a temp directory
/// without a Proxmox host, and so a dry run is a one-line change at the call
/// site rather than a flag threaded through the rules.
pub fn sweep(
    dir: &std::path::Path,
    known: &Known,
    mut remove: impl FnMut(&std::path::Path) -> std::io::Result<()>,
) -> Swept {
    let mut out = Swept::default();

    // **An incomplete view collects nothing.** Not "collects less": a partial
    // listing of live machines makes every unlisted machine look disposable,
    // which is the one mistake in this function that cannot be undone.
    if !known.complete {
        out.refused =
            Some("provider view incomplete; collected nothing rather than guessing".into());
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            out.refused = Some(format!("cannot read {}: {e}", dir.display()));
            return out;
        }
    };

    for entry in entries {
        let Ok(entry) = entry else {
            // A directory entry that cannot be read makes this listing partial,
            // and a partial listing is not a short world.
            out.refused = Some("a directory entry could not be read; listing is partial".into());
            continue;
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some((kind, id)) = snippet_owner(&name) else {
            out.foreign += 1;
            continue;
        };
        if known.live.contains(id) || known.desired.contains(id) {
            out.kept += 1;
            continue;
        }
        // Ours by grammar, claimed by nothing. For a name that carries its kind
        // that is enough to collect; for the legacy name it is not, because the
        // grammar is only "the prefix and something uuid-shaped" and the cost of
        // being wrong is a machine's first boot.
        if kind == SnippetKind::WorkerLegacy {
            out.uncertain.push(name);
            continue;
        }
        if out.refused.is_some() {
            continue;
        }
        match remove(&entry.path()) {
            Ok(()) => out.collected.push(name),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => out.collected.push(name),
            Err(e) => out.failed.push(format!("{name}: {e}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn known(live: &[&str], desired: &[&str], complete: bool) -> Known {
        Known {
            live: live.iter().map(|s| s.to_string()).collect(),
            desired: desired.iter().map(|s| s.to_string()).collect(),
            complete,
        }
    }
    fn real(p: &std::path::Path) -> std::io::Result<()> {
        fs::remove_file(p)
    }
    const A: &str = "b3e77a10-5c44-4de9-8f02-91ab6e4c7d58";
    const B: &str = "7f1c0a94-3d2e-4b51-9a77-2c8e5d0b1f43";
    const C: &str = "c8a1f220-7e93-4b06-a5d1-3f70b9e2c614";

    fn dir_with(files: &[String]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for f in files {
            fs::write(d.path().join(f), "#cloud-config\n").unwrap();
        }
        d
    }

    /// Both filename generations, and the new one is collected while the legacy
    /// one is reported instead — its grammar is weaker, so the cost of being
    /// wrong is not worth paying automatically.
    #[test]
    fn both_generations_are_seen_and_treated_differently() {
        let d = dir_with(&[
            crate::names::snippet_worker(A),
            crate::names::snippet_worker_legacy(B),
        ]);
        let s = sweep(d.path(), &known(&[], &[], true), real);
        assert_eq!(s.collected, vec![crate::names::snippet_worker(A)]);
        assert_eq!(s.uncertain, vec![crate::names::snippet_worker_legacy(B)]);
        assert!(d.path().join(crate::names::snippet_worker_legacy(B)).exists());
    }

    /// A live machine keeps its file, and so does one that is merely *wanted* —
    /// a worker mid-creation has no VM, and runtime absence alone must not make
    /// its snippet disposable before the machine has booted from it.
    #[test]
    fn live_and_provisioning_machines_keep_their_snippets() {
        let d = dir_with(&[
            crate::names::snippet_worker(A),
            crate::names::snippet_worker(B),
            crate::names::snippet_worker(C),
        ]);
        let s = sweep(d.path(), &known(&[A], &[B], true), real);
        assert_eq!(s.kept, 2);
        assert_eq!(s.collected, vec![crate::names::snippet_worker(C)]);
        assert!(d.path().join(crate::names::snippet_worker(A)).exists());
        assert!(d.path().join(crate::names::snippet_worker(B)).exists());
    }

    /// Files that are not ours are counted and untouched. A prefix is
    /// recognition, not authority, and the directory is shared.
    #[test]
    fn foreign_files_are_left_alone() {
        let d = dir_with(&[
            "user-data.yaml".into(),
            "onv-notes.yaml".into(),
            crate::names::snippet_worker(A),
        ]);
        let s = sweep(d.path(), &known(&[], &[], true), real);
        assert_eq!(s.foreign, 2);
        assert_eq!(s.collected.len(), 1);
        assert!(d.path().join("user-data.yaml").exists());
        assert!(d.path().join("onv-notes.yaml").exists());
    }

    /// **Partial discovery collects nothing.** This is the test that matters
    /// most: with an incomplete view every unlisted machine looks disposable.
    #[test]
    fn an_incomplete_view_collects_nothing() {
        let files = vec![crate::names::snippet_worker(A), crate::names::snippet_worker(B)];
        let d = dir_with(&files);
        let s = sweep(d.path(), &known(&[], &[], false), real);
        assert!(s.collected.is_empty());
        assert!(s.refused.is_some());
        for f in &files {
            assert!(d.path().join(f).exists(), "{f} was collected on a partial view");
        }
    }

    /// An unreadable directory refuses, and says so. It does not report an empty
    /// directory, which is what a bare `read_dir().ok()` would have done.
    #[test]
    fn an_unreadable_directory_refuses_rather_than_reporting_empty() {
        let s = sweep(
            std::path::Path::new("/onv-no-such-directory-anywhere"),
            &known(&[], &[], true),
            real,
        );
        assert!(s.refused.is_some());
        assert!(s.collected.is_empty());
    }

    /// A permission error on one file is recorded, does not abort the sweep, and
    /// the next sweep retries it — which is what makes the best-effort delete
    /// path safe rather than permanent.
    #[test]
    fn a_failed_removal_is_recorded_and_retried_later() {
        let d = dir_with(&[crate::names::snippet_worker(A), crate::names::snippet_worker(B)]);
        let mut first = true;
        let s = sweep(d.path(), &known(&[], &[], true), |p| {
            if first {
                first = false;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "read-only file system",
                ));
            }
            fs::remove_file(p)
        });
        assert_eq!(s.failed.len(), 1, "{s:?}");
        assert_eq!(s.collected.len(), 1);

        // The retry: same directory, nothing else changed, and the file that
        // failed is collected this time.
        let again = sweep(d.path(), &known(&[], &[], true), real);
        assert_eq!(again.collected.len(), 1, "{again:?}");
        assert!(again.failed.is_empty());
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0);
    }

    /// Nothing to do is not an error, and does not refuse.
    #[test]
    fn an_empty_directory_is_quiet() {
        let d = dir_with(&[]);
        let s = sweep(d.path(), &known(&[], &[], true), real);
        assert_eq!(s, Swept::default());
    }
}
