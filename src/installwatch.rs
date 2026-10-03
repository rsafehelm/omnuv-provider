//! **While a recipe installs, look again sooner than the poll** (3 October
//! 2026).
//!
//! A machine's install progress (`instance::recipe_progress`) is read on the
//! reconcile pass, and the pass runs every `providers.agent_poll` (120 s by
//! default) or when Core pushes a change, which nothing does while an install
//! runs. Measured on Pluto that day, from the hypervisor's own access log: the
//! agent read VM 101's status file twice in the whole install, at 23:03:58
//! (500, the script had not started) and 23:05:58 (200, already `done`). Every
//! step the guest wrote fell between two passes, so no install on production
//! had ever recorded one, and the buyer's card said "Installing" with no step
//! for two minutes.
//!
//! So while any machine here is installing, the loop runs a pass every
//! [`EVERY`] as well, the way it already follows up a teardown's proof. A
//! machine is installing when its last reading said `running`, or when it
//! runs a recipe, is up and has no reading yet (its script writes the file
//! only once cloud-init reaches it). The second is bounded by [`UNREAD_MAX`],
//! so a guest that never writes the file is not followed for ever.

use std::collections::HashMap;
use std::time::Duration;

use tokio::time::Instant;

/// How soon to look again while an install runs: Core's own fastest poll.
pub const EVERY: Duration = Duration::from_secs(10);

/// How long a machine with a recipe may say nothing before it stops being
/// followed closely. Twice the recipe test's install ceiling, measured
/// installs being two to four minutes.
pub const UNREAD_MAX: Duration = Duration::from_secs(30 * 60);

/// One machine, as a pass left it.
#[derive(Debug, Clone, Copy)]
pub struct Seen<'a> {
    pub id: &'a str,
    /// Up, as this pass observed it.
    pub running: bool,
    /// Its spec names a recipe.
    pub recipe: bool,
    /// Its install's status, when the guest's file said one.
    pub progress: Option<&'a str>,
}

/// Which machines are installing, and since when each has said nothing.
#[derive(Debug, Default)]
pub struct InstallWatch {
    unread_since: HashMap<String, Instant>,
    installing: bool,
}

impl InstallWatch {
    /// What a pass saw. Machines it did not see are forgotten.
    pub fn after_pass(&mut self, now: Instant, seen: &[Seen<'_>]) {
        let mut unread = HashMap::new();
        let mut installing = false;
        for s in seen {
            match s.progress {
                Some("running") => installing = true,
                Some(_) => {}
                None if s.running && s.recipe => {
                    let since = self.unread_since.get(s.id).copied().unwrap_or(now);
                    if now.saturating_duration_since(since) <= UNREAD_MAX {
                        installing = true;
                    }
                    unread.insert(s.id.to_string(), since);
                }
                None => {}
            }
        }
        self.unread_since = unread;
        self.installing = installing;
    }

    /// When the next pass is owed for an install, if one is.
    pub fn due(&self, now: Instant) -> Option<Instant> {
        self.installing.then(|| now + EVERY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen<'a>(id: &'a str, running: bool, recipe: bool, progress: Option<&'a str>) -> Seen<'a> {
        Seen { id, running, recipe, progress }
    }

    #[test]
    fn a_running_install_is_followed_and_a_finished_one_is_not() {
        let mut w = InstallWatch::default();
        let now = Instant::now();
        w.after_pass(now, &[seen("a", true, true, Some("running"))]);
        assert_eq!(w.due(now), Some(now + EVERY), "a running install waited for the poll");
        w.after_pass(now, &[seen("a", true, true, Some("done"))]);
        assert_eq!(w.due(now), None);
        w.after_pass(now, &[seen("a", true, true, Some("error"))]);
        assert_eq!(w.due(now), None);
    }

    #[test]
    fn a_recipe_machine_that_has_said_nothing_is_followed_for_a_while() {
        let mut w = InstallWatch::default();
        let start = Instant::now();
        // Up, a recipe, no file yet: cloud-init has not reached the script.
        w.after_pass(start, &[seen("a", true, true, None)]);
        assert!(w.due(start).is_some(), "the minutes before the script's first step went unwatched");
        let later = start + UNREAD_MAX;
        w.after_pass(later, &[seen("a", true, true, None)]);
        assert!(w.due(later).is_some(), "stopped before its time");
        let past = later + Duration::from_secs(1);
        w.after_pass(past, &[seen("a", true, true, None)]);
        assert_eq!(w.due(past), None, "a guest that never writes the file is followed for ever");
    }

    #[test]
    fn plain_stopped_and_gone_machines_are_not_followed() {
        let mut w = InstallWatch::default();
        let now = Instant::now();
        w.after_pass(now, &[seen("plain", true, false, None), seen("stopped", false, true, None)]);
        assert_eq!(w.due(now), None);
        // A machine that went unread is forgotten once a pass no longer sees it,
        // so its clock starts again if it comes back.
        w.after_pass(now, &[seen("a", true, true, None)]);
        w.after_pass(now + UNREAD_MAX * 2, &[]);
        let back = now + UNREAD_MAX * 3;
        w.after_pass(back, &[seen("a", true, true, None)]);
        assert!(w.due(back).is_some());
    }
}
