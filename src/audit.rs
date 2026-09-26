//! Local audit log.
//!
//! This agent is open source and runs on hardware the provider owns. Core can
//! ask it to do things — create a VM, attach a GPU, forward a request — so the
//! provider must be able to see exactly what was asked and what happened,
//! without taking Omnuv's word for it and without asking Omnuv for the record.
//!
//! The log is therefore:
//!   - local, append-only JSON Lines the provider can read, grep and ship
//!   - written before an action is attempted and again with its outcome, so an
//!     action that crashed mid-way still leaves a trace
//!   - free of secrets and free of buyer payloads (see `redaction` below)

use std::io::Write;
use std::sync::Mutex;

use serde::Serialize;

/// Where the record is written. Also emitted to the journal via `tracing`, so
/// `journalctl -u onv-provider` shows the same events.
const DEFAULT_PATH: &str = "/var/log/onv/audit.log";

static SINK: Mutex<Option<std::fs::File>> = Mutex::new(None);

/// Records not yet sent to the marketplace.
///
/// The file on the provider's disk stays authoritative for the provider; this
/// is the subset that travels up so Core can show them what was asked of their
/// hardware in the same words, and so a buyer's timeline can say what actually
/// happened rather than only what state a thing reached.
///
/// Bounded, and dropped oldest-first when full: an agent that cannot reach
/// Core for a day must not grow a queue until it runs the host out of memory.
/// Losing the tail here costs the marketplace's *copy* of a record, never the
/// provider's, which is the right way round.
static PENDING: Mutex<std::collections::VecDeque<omnuv_protocol::AuditEntry>> =
    Mutex::new(std::collections::VecDeque::new());

/// How many unsent records the agent will hold: `timings.auditBacklog`, set
/// once at start. Its default until then, so a record made before the
/// configuration is read — a failed start — is held like any other.
static BACKLOG: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(crate::timings::defaults::AUDIT_BACKLOG as usize);

/// Puts `timings.auditBacklog` in force.
pub fn set_backlog(n: usize) {
    BACKLOG.store(n.max(1), std::sync::atomic::Ordering::Relaxed);
}

/// Appends to a bounded queue, dropping the oldest first.
fn push_bounded(
    q: &mut std::collections::VecDeque<omnuv_protocol::AuditEntry>,
    entry: omnuv_protocol::AuditEntry,
    max: usize,
) {
    while q.len() >= max.max(1) {
        q.pop_front();
    }
    q.push_back(entry);
}

#[derive(Serialize)]
struct Record<'a> {
    ts: String,
    /// What was done, e.g. "worker.create", "tunnel.request".
    action: &'a str,
    /// Who asked. "core" for anything arriving over the tunnel or desired
    /// state; "agent" for work the agent decided to do itself.
    actor: &'a str,
    /// What it acted on, in marketplace terms.
    subject: &'a str,
    outcome: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
}

pub fn init(path: Option<&str>) {
    let path = path.unwrap_or(DEFAULT_PATH);
    if let Some(dir) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    match std::fs::OpenOptions::new().create(true).append(true).open(path) {
        Ok(f) => {
            *crate::poison::lock(&SINK, "audit file") = Some(f);
            record("audit.start", "agent", path, "ok", None);
        }
        Err(e) => {
            // Not fatal: the journal still receives every event. But say so
            // loudly, because a provider who cannot read the file would
            // otherwise assume it exists.
            eprintln!("warning: cannot open audit log at {path}: {e}. Events go to the journal only.");
        }
    }
}

/// Appends one record. Never takes a body, a token or a prompt: see the module
/// note on redaction.
pub fn record(action: &str, actor: &str, subject: &str, outcome: &str, detail: Option<&str>) {
    let ts = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let rec = Record { ts: ts.clone(), action, actor, subject, outcome, detail };
    let line = serde_json::to_string(&rec).unwrap_or_default();

    // The journal copy means the record survives even if the file is missing.
    println!("audit {line}");

    if let Some(f) = crate::poison::lock(&SINK, "audit file").as_mut() {
        let _ = writeln!(f, "{line}");
        let _ = f.flush();
    }

    {
        let mut q = crate::poison::lock(&PENDING, "audit queue");
        let entry = omnuv_protocol::AuditEntry {
            at: ts,
            action: action.to_string(),
            actor: actor.to_string(),
            subject: subject.to_string(),
            outcome: outcome.to_string(),
            detail: detail.map(str::to_string),
        };
        push_bounded(&mut q, entry, BACKLOG.load(std::sync::atomic::Ordering::Relaxed));
    }
}

/// Takes the records waiting to go up, for one status report.
///
/// Destructive: a record that leaves here is not sent twice. If the report then
/// fails, the marketplace never sees those lines — which is the correct trade,
/// because the provider's own file has them and that is the copy that is
/// supposed to be authoritative for the provider.
pub fn drain(max: usize) -> Vec<omnuv_protocol::AuditEntry> {
    let mut q = crate::poison::lock(&PENDING, "audit queue");
    let take = max.min(q.len());
    q.drain(..take).collect()
}

/// Redaction policy, stated once so it is not re-decided per call site.
///
/// Recorded: what was asked, of which marketplace resource, by whom, when, the
/// outcome, and sizes and durations.
///
/// Never recorded: API tokens, the Proxmox credential, cloud-init contents, and
/// **buyer request or response bodies**. A prompt passing through a provider's
/// machine must not be persisted to that provider's disk by us — the provider is
/// semi-trusted, and writing tenant payloads to their filesystem by default
/// would be a privacy failure, not transparency.
pub const REDACTION_POLICY: &str = "metadata only; no secrets, no buyer payloads";

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering::Relaxed;

    /// **The backlog is `timings.auditBacklog`**, and past it the oldest record
    /// goes first. It was a constant, 500, until 26 September 2026.
    #[test]
    fn the_backlog_holds_what_it_was_set_to_and_drops_the_oldest() {
        let entry = |n: u32| omnuv_protocol::AuditEntry {
            at: String::new(),
            action: format!("a{n}"),
            actor: "agent".into(),
            subject: "s".into(),
            outcome: "ok".into(),
            detail: None,
        };
        let mut q = std::collections::VecDeque::new();
        for n in 0..5 {
            super::push_bounded(&mut q, entry(n), 3);
        }
        assert_eq!(q.iter().map(|e| e.action.as_str()).collect::<Vec<_>>(), ["a2", "a3", "a4"]);

        assert_eq!(super::BACKLOG.load(Relaxed), 500, "the default, before the configuration is read");
        // What start sets is what `record` keeps. The queue is the process's,
        // shared with every test that records, so the assertion is a bound:
        // whatever else was recorded or drained meanwhile, never more than 3.
        super::set_backlog(3);
        for n in 0..10 {
            super::record("test.backlog", "agent", &format!("s{n}"), "ok", None);
        }
        let held = super::drain(1000).len();
        super::set_backlog(crate::timings::defaults::AUDIT_BACKLOG as usize);
        assert!(held <= 3, "{held} records held with a backlog of 3");
    }
}
