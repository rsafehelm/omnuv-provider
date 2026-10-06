//! **This agent's hold on its provider**: the session itself is
//! `onv_core_link::session` (omnuv's modular design, work package A1b). What
//! the handshake advertises stays here, since it names the capabilities of
//! modules that are still the agent's.

pub use onv_core_link::session::*;

/// What this agent advertises at its handshake: Core's
/// `provider_api::CAPABILITIES`, as far as this build has them.
///
/// ```text
/// session        this agent holds its provider under a session and stops
///                when superseded
/// proven-delete  "deleted" is said one complete listing after the destroy,
///                and a volume that stayed is reported as a residue
///                (`teardown`)
/// restore-mode   this agent keeps its head, tells Core when a view does not
///                extend it, and lists and acts on nothing while in a restore
///                (`restore`, lifecycle phase 8)
/// worker-lost    this agent reads a worker's `built`, never builds one sent
///                built, and says one it holds nothing of is lost (`worker`,
///                finding 6 for workers)
/// report-interval
///                this agent reports its inventory at Core's period, and
///                only when its survey completed, so Core may judge its
///                silence by its reports (`report`, D35)
/// group-prepare  this agent answers a held machine's readiness to start:
///                the start gate's reads on a machine built and stopped whose
///                spec names an attempt (`instance`, machine groups step 2)
/// ```
pub const CAPABILITIES: &[&str] = &[
    "session",
    "proven-delete",
    crate::restore::CAPABILITY,
    crate::lease::CAPABILITY,
    crate::worker::CAPABILITY,
    crate::scrub::CAPABILITY,
    crate::report::CAPABILITY,
    crate::instance::GROUP_PREPARE,
];
