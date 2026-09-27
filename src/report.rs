//! **D35: this agent reports its inventory at Core's period, and only when
//! its survey completed** (the operator's decision of 27 September 2026 on
//! the lifecycle model's finding 5).
//!
//! Core judges a provider's silence by its reports: with its switch on, an
//! agent that advertises [`CAPABILITY`] is silent when no report arrived
//! within Core's `offline_after`, however steadily it heartbeats. So a
//! report must mean *this host was surveyed, and all of it answered*: a
//! survey that fails, or leaves a node's storage, devices or guests unread,
//! sends nothing, and a wedged host goes silent — which is the case the
//! decision wants caught and failed over without a person.
//!
//! ```text
//! the period      Core's `providers.report_interval` (D33): in the
//!                 handshake's answer (`report_interval_secs`) and in the
//!                 `onv-report-interval` header on every view, the latest
//!                 word kept. Obeyed exactly, held only to Core's own range
//! an old Core     says neither: `timings.inventoryEvery`, and never less
//!                 often than twice per Core poll, as before (the fallback)
//! the task        its own, beside the heartbeat's: a reconcile pass that
//!                 takes minutes never delays a report
//! ```
//!
//! Nothing here is Core's to rely on unless the agent advertised it, and a
//! Core from before D35 reads neither the capability nor anything else here.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::dur::Dur;

/// What this agent advertises: it reports at Core's period, and only a
/// completed survey. Core's `provider_api::REPORT_CAPABILITY`.
pub const CAPABILITY: &str = "report-interval";

/// The view answer's header carrying Core's period, in seconds. Core's own
/// header, never the protocol's view.
pub const HEADER: &str = "onv-report-interval";

/// The handshake answer's key carrying the same.
const ANSWER_KEY: &str = "report_interval_secs";

/// The range Core holds `providers.report_interval` to, and this agent holds
/// Core's number to: a local cap, not a second owner.
pub const FLOOR: Dur = Dur::secs(10);
pub const CEILING: Dur = Dur::mins(10);

/// What Core last said: its report period, and its poll (which the fallback
/// derives from). Zero is "not said". Shared by every clone of the client, so
/// the reconcile loop's views and the report task read one value.
#[derive(Clone, Debug, Default)]
pub struct Heard {
    period: Arc<AtomicU64>,
    poll: Arc<AtomicU64>,
}

impl Heard {
    /// From the handshake's answer. An answer without it (an old Core) leaves
    /// whatever a view said since.
    pub fn answer(&self, answer: &serde_json::Value) {
        if let Some(s) = answer.get(ANSWER_KEY).and_then(|v| v.as_u64()) {
            self.period.store(s, Ordering::Relaxed);
        }
    }

    /// From a view's header. A view without it is an old Core's: not said.
    pub fn header(&self, value: Option<&str>) {
        let s = value.and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(0);
        self.period.store(s, Ordering::Relaxed);
    }

    /// Core's poll, as the reconcile loop last kept it.
    pub fn poll(&self, said: Option<u64>) {
        self.poll.store(said.unwrap_or(0), Ordering::Relaxed);
    }

    /// The period to report at: Core's, exactly, held to its own range; the
    /// fallback when Core said none.
    pub fn period(&self, inventory_every: Duration) -> Duration {
        let said = self.period.load(Ordering::Relaxed);
        if said > 0 {
            return Dur::secs(said).max(FLOOR).min(CEILING).std();
        }
        let poll = self.poll.load(Ordering::Relaxed);
        fallback(inventory_every, crate::timings::poll((poll > 0).then_some(poll)))
    }

    /// Whether Core has said a period: with one, this agent reports at it.
    pub fn said(&self) -> bool {
        self.period.load(Ordering::Relaxed) > 0
    }
}

/// **The fallback, for a Core that says no period**: `timings.inventoryEvery`,
/// and never less often than twice per Core poll.
///
/// The inventory carries the node's disclosure, and a Core from before D35
/// stops selling a node whose disclosure is two of its polls old (D10). At
/// the 300 s default against Core's 120 s poll, every node was unsellable for
/// the last minute of every five. Twice per poll leaves one missed report
/// still fresh, which is the tolerance that window was built for.
pub fn fallback(configured: Duration, core_poll: Duration) -> Duration {
    configured.min(core_poll / 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// **Core's period is kept exactly**, from the handshake or a view, the
    /// latest word winning; the configured interval does not shorten it.
    #[test]
    fn core_s_period_is_kept_exactly() {
        let h = Heard::default();
        h.answer(&serde_json::json!({ "report_interval_secs": 30 }));
        assert_eq!(h.period(secs(300)), secs(30));
        assert_eq!(h.period(secs(5)), secs(30), "the agent's own interval shortened Core's period");
        h.header(Some("45"));
        assert_eq!(h.period(secs(300)), secs(45), "a view's word did not replace the handshake's");
        assert!(h.said());
    }

    /// Held to Core's own range, and zero or garbage is "not said".
    #[test]
    fn a_period_outside_core_s_range_is_held_to_it() {
        let h = Heard::default();
        h.header(Some("1"));
        assert_eq!(h.period(secs(300)), secs(10));
        h.header(Some("86400"));
        assert_eq!(h.period(secs(300)), secs(600));
        for nothing in [Some("0"), Some("soon"), Some(""), None] {
            h.header(nothing);
            assert!(!h.said(), "{nothing:?} was taken as a period");
        }
    }

    /// **An old Core says none, and the fallback is what it always was**:
    /// the configured interval, at least twice per Core poll. A handshake
    /// answer without the key leaves what a view said.
    #[test]
    fn an_old_core_gets_the_period_it_always_did() {
        let h = Heard::default();
        h.answer(&serde_json::json!({ "heartbeat_interval_secs": 30 }));
        assert!(!h.said());
        assert_eq!(h.period(secs(300)), secs(60), "300 s against the default 120 s poll");
        h.poll(Some(1800));
        assert_eq!(h.period(secs(300)), secs(300));
        h.poll(Some(1));
        assert!(h.period(secs(1)) > Duration::ZERO, "a zero period panics the interval");
        h.header(Some("30"));
        h.answer(&serde_json::json!({}));
        assert_eq!(h.period(secs(300)), secs(30), "an answer without the key erased a view's word");
    }

    /// The fallback, as the agent always computed it (D10).
    #[test]
    fn the_fallback_goes_at_least_twice_per_core_poll() {
        assert_eq!(fallback(secs(300), crate::timings::poll(None)), secs(60));
        assert!(2 * fallback(secs(300), secs(120)) < 2 * secs(120), "one missed report went stale");
        assert_eq!(fallback(secs(30), secs(120)), secs(30), "a shorter configured interval is kept");
        assert_eq!(fallback(secs(300), crate::timings::poll(Some(1800))), secs(300));
    }
}
