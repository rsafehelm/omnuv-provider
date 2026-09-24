//! **A poisoned lock is recovered, not obeyed (24 September 2026).**
//!
//! A `std::sync::Mutex` is poisoned when a thread panics while holding it,
//! and from then on `lock()` returns an error. Every site in this agent read
//! that error with `.ok()` or `let Ok(..) else`, so one panic anywhere near a
//! lock switched something off for the life of the process, silently:
//! `reconcile_workers` returned before posting its status report, the audit
//! drain returned nothing for ever, and the tunnel could no longer resolve a
//! worker.
//!
//! What these locks guard is plain data: maps, queues, the last desired state.
//! A holder that panicked mid-update can leave a stale entry, never a broken
//! invariant, and every caller overwrites what it reads on its next pass. So
//! the guard is taken back, and the poisoning is said once per site.

use std::sync::{Mutex, MutexGuard};

pub fn lock<'a, T>(mutex: &'a Mutex<T>, what: &str) -> MutexGuard<'a, T> {
    mutex.lock().unwrap_or_else(|poisoned| {
        eprintln!("{what}: its lock was poisoned by a panic elsewhere; recovered, and the data is still used");
        poisoned.into_inner()
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    #[test]
    fn a_poisoned_lock_still_yields_its_data() {
        let m = Arc::new(Mutex::new(vec![1]));
        let held = m.clone();
        let _ = std::thread::spawn(move || {
            let _guard = held.lock().unwrap();
            panic!("poisoning on purpose");
        })
        .join();
        assert!(m.lock().is_err(), "the fixture did not poison the lock");
        super::lock(&m, "test").push(2);
        assert_eq!(*super::lock(&m, "test"), vec![1, 2]);
    }
}
