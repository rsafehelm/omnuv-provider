//! Reading what a Workload Agent says about itself.
//!
//! ## The channel is the hypervisor, not the network
//!
//! The workload writes its report to a file; the Provider Agent reads that file
//! through the guest agent, on the reconcile tick it already runs. Nothing
//! listens on either side.
//!
//! That choice removes an entire security surface rather than defending one.
//! A listener on the provider bridge would have needed a secret in the guest —
//! and a guest's disk is readable by anyone who can read the storage — plus a
//! source-address check to stop one workload speaking for another. Reading
//! through Proxmox needs none of it: the hypervisor is already an authenticated
//! channel, and `file-read` names the VM, so a report *cannot* be attributed to
//! a machine other than the one it came from. It also works on a machine whose
//! own networking is broken, which is exactly when telemetry is worth having.
//!
//! It is the same mechanism the recipe install report uses, and it needs only
//! `VM.GuestAgent.FileRead` — not the unrestricted `exec` privilege.
//!
//! ## What a report is allowed to do
//!
//! Add detail. Never decide. The agent's own probe decides `WorkerState`; a
//! report that stops advancing is dropped rather than read as bad news, because
//! otherwise a dead reporter would be indistinguishable from a dead worker.

#![allow(dead_code)]

use omnuv_protocol::WorkloadReport;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Where the Workload Agent writes, and the Provider Agent reads. On `tmpfs`,
/// so a reboot cannot leave yesterday's report behind looking current.
pub const WORKLOAD_STATUS: &str = "/run/onv/workload.json";

/// Reads with no advance in `uptime_s` before the reporter is presumed dead.
///
/// Staleness is measured by the guest's own uptime rather than by a clock or a
/// timestamp in the file: a stopped reporter leaves a perfectly well-formed
/// file behind, and the only thing that distinguishes it from a live one is
/// that the number stops moving. Nothing here trusts the guest's wall clock.
// **Written, tested, and not yet wired**, which is why the compiler calls it
// dead. It is the staleness half of the workload-agent contract: a stopped
// reporter leaves a perfectly well-formed file behind, and the only thing
// separating it from a live one is that the uptime stops moving.
//
// `worker.rs` reads and parses reports today but does not yet hold this across
// passes, so nothing decides that a reporter has stopped being believable. Kept
// rather than deleted because the tests below are the decision — deleting it
// would throw away the reasoning and leave the gap unmarked.

const STUCK_AFTER_READS: u32 = 3;

#[derive(Clone, Default)]
pub struct Store {
    inner: Arc<Mutex<HashMap<String, Seen>>>,
}

#[derive(Clone)]
struct Seen {
    uptime_s: u64,
    unchanged_reads: u32,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a freshly read report and says whether to believe it.
    ///
    /// Returns `None` once the reporter has stopped advancing, so a worker
    /// whose Workload Agent died reports no telemetry rather than frozen
    /// telemetry. Frozen numbers are worse than absent ones: absent is
    /// obviously nothing, frozen looks like a healthy idle machine.
    pub fn observe(&self, report: WorkloadReport) -> Option<WorkloadReport> {
        let mut m = self.inner.lock().ok()?;

        let Some(seen) = m.get_mut(&report.workload_id) else {
            // First sight of this workload. There is nothing to compare it
            // against yet, so it cannot be stuck — counting this read as
            // "unchanged" would spend a third of the budget before the reporter
            // has had a chance to advance anything.
            m.insert(
                report.workload_id.clone(),
                Seen { uptime_s: report.uptime_s, unchanged_reads: 0 },
            );
            return Some(report);
        };

        // Backwards is a restart, and a restart is a live reporter — resetting
        // rather than accumulating is what keeps a crash-looping worker
        // visible, which is the thing uptime is here to expose.
        if report.uptime_s != seen.uptime_s {
            seen.uptime_s = report.uptime_s;
            seen.unchanged_reads = 0;
        } else {
            seen.unchanged_reads += 1;
        }

        (seen.unchanged_reads < STUCK_AFTER_READS).then_some(report)
    }

    /// Forgets a workload, so a deleted worker's last words do not sit in
    /// memory for the life of the agent.
    pub fn forget(&self, workload_id: &str) {
        if let Ok(mut m) = self.inner.lock() {
            m.remove(workload_id);
        }
    }
}

/// Parses the file the Workload Agent writes.
///
/// Every failure is `None`, and `None` means *not known* — never *unhealthy*.
/// A machine still booting, an image without the agent, a half-written file and
/// an older agent all land here, and none of them is news about the worker.
pub fn parse_report(content: &str) -> Option<WorkloadReport> {
    serde_json::from_str(content).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnuv_protocol::{GpuTelemetry, WorkloadHealth};

    fn report(id: &str, uptime_s: u64) -> WorkloadReport {
        WorkloadReport {
            workload_id: id.into(),
            uptime_s,
            health: WorkloadHealth::Serving,
            model: None,
            gpus: vec![],
            serving: None,
            observed: vec![],
        }
    }

    #[test]
    fn a_reporter_that_keeps_advancing_is_believed() {
        let s = Store::new();
        for t in [10, 25, 40, 55, 70, 85] {
            assert!(s.observe(report("w1", t)).is_some(), "uptime {t}");
        }
    }

    /// The failure this exists for: workloadd dies, its file stays on disk, and
    /// every read afterwards returns a well-formed report full of stale numbers
    /// that look like a healthy idle worker.
    #[test]
    fn a_reporter_that_stops_advancing_stops_being_believed() {
        let s = Store::new();
        assert!(s.observe(report("w1", 100)).is_some(), "first sight");
        assert!(s.observe(report("w1", 100)).is_some(), "one missed tick is not death");
        assert!(s.observe(report("w1", 100)).is_some(), "two is still not death");
        assert!(s.observe(report("w1", 100)).is_none(), "three unchanged: gone");
        assert!(s.observe(report("w1", 100)).is_none(), "and it stays gone");
    }

    /// A restarted machine reports a *smaller* uptime. That is a live reporter,
    /// not a stuck one, and treating it as stuck would blind us to a worker
    /// that is crash-looping — the very thing uptime is here to expose.
    #[test]
    fn a_restart_reads_as_alive_rather_than_stuck() {
        let s = Store::new();
        s.observe(report("w1", 5000));
        s.observe(report("w1", 5000));
        s.observe(report("w1", 5000));
        assert!(s.observe(report("w1", 5000)).is_none(), "stuck");
        // Rebooted: uptime restarts from near zero.
        assert!(s.observe(report("w1", 12)).is_some(), "a restart is life");
    }

    #[test]
    fn workloads_do_not_share_staleness() {
        let s = Store::new();
        for _ in 0..5 {
            s.observe(report("stuck", 42));
        }
        assert!(s.observe(report("stuck", 42)).is_none());
        assert!(s.observe(report("healthy", 42)).is_some());
    }

    #[test]
    fn forgetting_a_workload_clears_its_history() {
        let s = Store::new();
        for _ in 0..5 {
            s.observe(report("w1", 42));
        }
        assert!(s.observe(report("w1", 42)).is_none());
        s.forget("w1");
        assert!(s.observe(report("w1", 42)).is_some(), "a rebuilt worker starts clean");
    }

    #[test]
    fn a_real_report_parses() {
        let json = r#"{"workload_id":"w1","uptime_s":90,"health":"serving",
            "gpus":[{"index":0,"name":"NVIDIA GeForce RTX 3090","vram_total_mib":24576,
            "vram_used_mib":21000,"utilization_pct":87,"temperature_c":71,"power_mw":305500}]}"#;
        let r = parse_report(json).expect("parses");
        assert_eq!(r.health, WorkloadHealth::Serving);
        assert_eq!(r.gpus[0].vram_total_mib, 24576);
    }

    /// Everything that is not a report is "not known", never "unhealthy".
    #[test]
    fn anything_unreadable_is_not_known_rather_than_bad_news() {
        assert!(parse_report("").is_none());
        assert!(parse_report("{\"workload_id\":\"w1\"").is_none(), "half-written");
        assert!(parse_report("cloud-init still running").is_none());
    }

    /// An older Workload Agent that predates a field must still be readable —
    /// the same additive rule the protocol tests assert, exercised here because
    /// this is where a real one arrives.
    #[test]
    fn a_report_missing_optional_fields_still_parses() {
        let minimal = r#"{"workload_id":"w1","uptime_s":3,"health":"starting"}"#;
        let r = parse_report(minimal).expect("parses");
        assert!(r.gpus.is_empty());
        assert!(r.serving.is_none());
        assert!(r.model.is_none());
    }

    #[test]
    fn gpu_telemetry_survives_the_file() {
        let g = GpuTelemetry {
            index: 1,
            name: "NVIDIA GeForce RTX 3090".into(),
            vram_total_mib: 24576,
            vram_used_mib: 100,
            utilization_pct: 3,
            temperature_c: None,
            power_mw: None,
        };
        let mut r = report("w1", 1);
        r.gpus = vec![g.clone()];
        let round = parse_report(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(round.gpus[0], g);
    }
}
