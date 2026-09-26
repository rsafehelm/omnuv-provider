//! The agent's own timings: `timings` in `/etc/onv/agent.yaml`.
//!
//! **Why a file** (the operator, 26 September 2026; omnuv's
//! `docs/plans/runtime-configuration.md`, step 4). A timeout compiled into
//! the agent needs a package to change, and most of these are starting points
//! nobody has measured. `deploy-agent.yml` writes every key, taking the
//! defaults from `onv-provider print-config` so they live in one place, this
//! file; `onv-provider check-config` checks the result before anything
//! restarts; and the running agent reports [`Timings::hash`] with every
//! heartbeat, so a play can prove the agent took what it wrote.
//!
//! **What is not here**, and why. Values Core and the agent both build on are
//! Core's (D33): the heartbeat interval arrives with the handshake, each
//! machine's clone budget with its spec, and the poll with every view
//! (`DesiredState::poll_interval_secs`). What is here is the agent's own:
//! how it treats its host, its hypervisor and its workers, and the local caps
//! it holds Core's values to. And rules stay in code: a setting changes how
//! long, how often or how many, never whether a rule holds.
//!
//! **Bounds are safety, not style.** Each exists where a value outside it
//! breaks something this agent or Core relies on, and says what, in the
//! refusal an operator reads.

use crate::dur::Dur;
use crate::workload_config::{FASTEST_READ, WorkloadConfig};
use serde::{Deserialize, Serialize};

/// Every default, once: the values the code held before this file existed
/// (26 September 2026), each named after the constant it replaced.
pub mod defaults {
    use crate::dur::Dur;
    /// `inventoryEverySecs`' default, `config.rs`.
    pub const INVENTORY_EVERY: Dur = Dur::mins(5);
    /// `IDLE` in `Core::download_artefact`, `agent.rs`.
    pub const IMAGE_TRANSFER_IDLE: Dur = Dur::mins(2);
    /// `START_GATE_LOOKS` and `START_GATE_EVERY`, `proxmox.rs`.
    pub const START_GATE_LOOKS: u32 = 30;
    pub const START_GATE_EVERY: Dur = Dur::secs(2);
    /// The keepalive's interval and `SILENCE`, `tunnel.rs`.
    pub const TUNNEL_PING: Dur = Dur::secs(20);
    pub const TUNNEL_SILENCE: Dur = Dur::mins(1);
    /// `PENDING_MAX`, `audit.rs`.
    pub const AUDIT_BACKLOG: u32 = 500;
    /// `STUCK_AFTER_READS`, `workload.rs`.
    pub const WORKLOAD_STUCK_AFTER_READS: u32 = 3;
    /// The clamp in `Client::clone_polls`, `proxmox.rs`: 1800 one-second polls.
    pub const CLONE_BUDGET_MAX: Dur = Dur::mins(30);
}

/// The poll this agent keeps while Core says none: a Core that predates
/// `poll_interval_secs`, or one that sends zero. Core's own default for
/// `providers.agent_poll`, and the fixed 120 s this agent polled at before.
pub const POLL_WHEN_CORE_SAYS_NONE: Dur = Dur::secs(120);

/// The range this agent holds Core's poll to, which is Core's own range for
/// `providers.agent_poll`. A local cap, not a second owner: inside it Core's
/// number is obeyed exactly.
pub const POLL_FLOOR: Dur = FASTEST_READ;
pub const POLL_CEILING: Dur = Dur::mins(30);

/// The poll to keep, given what Core said. Absent and zero are both "not
/// said", like the heartbeat's interval, because an interval of nothing is
/// not a period anything can keep; anything else is Core's, held to the range
/// Core itself allows.
pub fn poll(said_secs: Option<u64>) -> std::time::Duration {
    match said_secs.filter(|s| *s > 0) {
        None => POLL_WHEN_CORE_SAYS_NONE.std(),
        Some(s) => Dur::secs(s.min(POLL_CEILING.as_secs())).max(POLL_FLOOR).std(),
    }
}

/// `timings` in `/etc/onv/agent.yaml`. A file names what it sets; the rest are
/// the defaults. Unknown keys are refused, so a misspelt key is an error
/// rather than a default nobody chose.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct Timings {
    /// How often the full inventory is re-reported. Heartbeats are far more
    /// frequent and are what decide online and offline.
    pub inventory_every: Dur,
    /// A download of an image that sends no bytes for this long is dead, and
    /// is dropped so the next pass can resume it.
    pub image_transfer_idle: Dur,
    /// How many times, and how far apart, a machine's inputs are looked at
    /// before it is started (`Client::start_when_ready`).
    pub start_gate_looks: u32,
    pub start_gate_every: Dur,
    /// The tunnel's keepalive to Core, and how long Core may say nothing
    /// before the tunnel is taken as gone and dialled again.
    pub tunnel_ping: Dur,
    pub tunnel_silence: Dur,
    /// Audit records held for Core while it cannot be reached, oldest dropped
    /// first. The provider's own file keeps every one.
    pub audit_backlog: u32,
    /// Reads of a worker's report with no progress before its Workload Agent
    /// is taken as dead and its numbers are no longer shown.
    pub workload_stuck_after_reads: u32,
    /// The longest one pass waits on a clone, whatever budget Core sent. A
    /// clone that outlasts it stays journalled and the next pass settles it.
    pub clone_budget_max: Dur,
    /// What this agent writes into every worker's `/etc/onv/workload.yaml`.
    pub workload: WorkloadConfig,
}

impl Default for Timings {
    fn default() -> Self {
        use defaults::*;
        Self {
            inventory_every: INVENTORY_EVERY,
            image_transfer_idle: IMAGE_TRANSFER_IDLE,
            start_gate_looks: START_GATE_LOOKS,
            start_gate_every: START_GATE_EVERY,
            tunnel_ping: TUNNEL_PING,
            tunnel_silence: TUNNEL_SILENCE,
            audit_backlog: AUDIT_BACKLOG,
            workload_stuck_after_reads: WORKLOAD_STUCK_AFTER_READS,
            clone_budget_max: CLONE_BUDGET_MAX,
            workload: WorkloadConfig::default(),
        }
    }
}

impl Timings {
    /// Every value against its bounds, and the rules that tie values together.
    /// Every problem is named, with the key as the file spells it, not just
    /// the first.
    pub fn check(&self) -> Result<(), Vec<String>> {
        let mut bad = Vec::new();
        fn within(bad: &mut Vec<String>, key: &str, v: Dur, lo: Dur, hi: Dur, why: &str) {
            if v < lo || v > hi {
                bad.push(format!("timings.{key} is {v}; it must be between {lo} and {hi}: {why}"));
            }
        }
        fn count(bad: &mut Vec<String>, key: &str, v: u32, lo: u32, hi: u32, why: &str) {
            if !(lo..=hi).contains(&v) {
                bad.push(format!("timings.{key} is {v}; it must be between {lo} and {hi}: {why}"));
            }
        }
        within(&mut bad, "inventoryEvery", self.inventory_every, Dur::secs(1), Dur::hours(24),
            "an interval needs a period, and an inventory a day old hides a day of capacity changes");
        within(&mut bad, "imageTransferIdle", self.image_transfer_idle, Dur::secs(10), Dur::hours(1),
            "shorter kills a slow uplink's healthy pauses; longer lets a dead transfer hold the image mirror");
        count(&mut bad, "startGateLooks", self.start_gate_looks, 1, 600,
            "a machine is looked at at least once before it starts");
        within(&mut bad, "startGateEvery", self.start_gate_every, Dur::secs(1), Dur::mins(1),
            "each look asks the hypervisor several questions");
        if u64::from(self.start_gate_looks) * self.start_gate_every.as_millis() > Dur::mins(10).as_millis() {
            bad.push(format!(
                "timings.startGateLooks ({}) times timings.startGateEvery ({}) is more than 10m: the gate \
                 holds the whole pass, and every other machine on this provider waits behind it",
                self.start_gate_looks, self.start_gate_every
            ));
        }
        within(&mut bad, "tunnelPing", self.tunnel_ping, Dur::secs(1), Dur::secs(20),
            "Core leaves a tunnel it has heard nothing on for its tunnel.silence, at least 60s, \
             and needs three pings inside it");
        within(&mut bad, "tunnelSilence", self.tunnel_silence, Dur::secs(3), Dur::mins(10),
            "a dead tunnel is left within ten minutes, as Core leaves one");
        if self.tunnel_silence.as_millis() < 3 * self.tunnel_ping.as_millis() {
            bad.push(format!(
                "timings.tunnelSilence ({}) must be at least three timings.tunnelPing ({}): Core answers \
                 each ping, so a shorter silence cuts a tunnel that is only one answer late",
                self.tunnel_silence, self.tunnel_ping
            ));
        }
        count(&mut bad, "auditBacklog", self.audit_backlog, 100, 50_000,
            "one report takes up to 100 records, and an outage must not grow the queue without limit");
        count(&mut bad, "workloadStuckAfterReads", self.workload_stuck_after_reads, 1, 20,
            "at least one read, and frozen numbers are not shown for more than twenty passes");
        within(&mut bad, "cloneBudgetMax", self.clone_budget_max, Dur::mins(1), Dur::hours(2),
            "a clone holds every other placement on this provider for as long as a pass waits on it");
        bad.extend(self.workload.check("timings.workload."));
        // A worker's report must move between the reads that could call it
        // stuck: a reporter slower than that reads as a dead one. Reads come
        // at least a poll apart, and Core's poll is never under ten seconds.
        let window = u64::from(self.workload_stuck_after_reads) * FASTEST_READ.as_millis();
        if self.workload.report_every.as_millis() > window {
            bad.push(format!(
                "timings.workload.reportEvery ({}) must be at most timings.workloadStuckAfterReads ({}) \
                 times {FASTEST_READ}, the fastest poll Core may ask for: a report slower than that can \
                 read as a dead reporter",
                self.workload.report_every, self.workload_stuck_after_reads
            ));
        }
        if bad.is_empty() { Ok(()) } else { Err(bad) }
    }

    /// Twelve hex digits of a SHA-256 over the canonical form: what every
    /// heartbeat carries and `check-config` prints. Over the timings alone,
    /// never a credential and never where this agent is, so two agents that
    /// run the same timings, or the mirror and production, report the same
    /// hash. A value written two ways (`300s`, `5m`) hashes as one.
    pub fn hash(&self) -> String {
        use sha2::Digest as _;
        let canonical = serde_json::to_vec(self).expect("timings serialise");
        sha2::Sha256::digest(&canonical).iter().take(6).map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The first release changes nothing**: every default is the value the
    /// code held before this file existed, written out here once, so a default
    /// that drifts fails by name.
    #[test]
    fn the_defaults_are_the_values_the_code_held() {
        let t = Timings::default();
        let secs = |d: Dur| d.std().as_secs_f64();
        assert_eq!(secs(t.inventory_every), 300.0, "inventoryEverySecs defaulted to 300");
        assert_eq!(secs(t.image_transfer_idle), 120.0, "agent.rs IDLE");
        assert_eq!((t.start_gate_looks, secs(t.start_gate_every)), (30, 2.0), "proxmox.rs START_GATE_*");
        assert_eq!((secs(t.tunnel_ping), secs(t.tunnel_silence)), (20.0, 60.0), "tunnel.rs");
        assert_eq!(t.audit_backlog, 500, "audit.rs PENDING_MAX");
        assert_eq!(t.workload_stuck_after_reads, 3, "workload.rs STUCK_AFTER_READS");
        assert_eq!(secs(t.clone_budget_max), 1800.0, "proxmox.rs clone_polls' clamp");
        assert_eq!(t.workload, WorkloadConfig::default());
        assert!(t.check().is_ok(), "{:?}", t.check());
        assert_eq!(poll(None).as_secs(), 120, "the reconcile interval in agent.rs");
        // And their hash, pinned: every agent running the defaults reports
        // this. A change to a default or to the canonical form moves it on
        // every provider at once, so it moves here, on purpose, in that change.
        assert_eq!(t.hash(), "a57be9feb152");
    }

    /// Core's poll is obeyed inside Core's own range, and zero or absent is
    /// "not said".
    #[test]
    fn core_s_poll_is_kept_inside_core_s_own_range() {
        assert_eq!(poll(Some(60)).as_secs(), 60);
        assert_eq!(poll(Some(0)).as_secs(), 120);
        assert_eq!(poll(None).as_secs(), 120);
        assert_eq!(poll(Some(1)).as_secs(), 10, "below Core's floor");
        assert_eq!(poll(Some(86_400)).as_secs(), 1800, "above Core's ceiling");
        assert_eq!(poll(Some(u64::MAX)).as_secs(), 1800, "no overflow on the way");
    }

    fn refused(yaml: &str) -> Vec<String> {
        let t: Timings = serde_yaml_ng::from_str(yaml).expect("parses");
        t.check().expect_err("was accepted")
    }

    /// Each bound and each rule refuses, naming the key as the file spells it.
    #[test]
    fn every_bound_and_rule_refuses_by_name() {
        for (yaml, key) in [
            ("inventoryEvery: 0s", "timings.inventoryEvery"),
            ("imageTransferIdle: 5s", "timings.imageTransferIdle"),
            ("startGateLooks: 0", "timings.startGateLooks"),
            ("startGateEvery: 500ms", "timings.startGateEvery"),
            ("startGateLooks: 600\nstartGateEvery: 2s", "timings.startGateLooks (600) times"),
            ("tunnelPing: 30s\ntunnelSilence: 2m", "timings.tunnelPing"),
            ("tunnelSilence: 50s", "timings.tunnelSilence (50s) must be at least three"),
            ("tunnelSilence: 11m", "timings.tunnelSilence is 11m"),
            ("auditBacklog: 99", "timings.auditBacklog"),
            ("workloadStuckAfterReads: 0", "timings.workloadStuckAfterReads"),
            ("cloneBudgetMax: 3h", "timings.cloneBudgetMax"),
            ("workload:\n  degradedAbove: 10s", "timings.workload.degradedAbove"),
            ("workloadStuckAfterReads: 1", "timings.workload.reportEvery (15s) must be at most"),
        ] {
            let e = refused(yaml);
            assert!(e.iter().any(|m| m.starts_with(key)), "{yaml:?} was not refused as {key}: {e:?}");
        }
    }

    /// A value inside its bounds is the operator's, and the edges are inside.
    #[test]
    fn the_edges_of_every_bound_are_accepted() {
        let t: Timings = serde_yaml_ng::from_str(
            "inventoryEvery: 1s\nimageTransferIdle: 1h\nstartGateLooks: 300\nstartGateEvery: 2s\n\
             tunnelPing: 20s\ntunnelSilence: 1m\nauditBacklog: 50000\nworkloadStuckAfterReads: 20\n\
             cloneBudgetMax: 2h\nworkload:\n  reportEvery: 2m\n  degradedAbove: 100ms\n",
        )
        .expect("parses");
        assert_eq!(t.check(), Ok(()));
    }

    /// An unknown key is refused, not defaulted: a misspelling is a value
    /// nobody chose.
    #[test]
    fn an_unknown_key_is_refused_by_name() {
        let e = serde_yaml_ng::from_str::<Timings>("tunelPing: 10s\n").expect_err("a misspelt key was taken");
        assert!(e.to_string().contains("tunelPing"), "{e}");
    }

    /// The hash moves with a value and only with a value.
    #[test]
    fn the_hash_names_the_values() {
        let a = Timings::default();
        let written: Timings = serde_yaml_ng::from_str("inventoryEvery: 300s\n").unwrap();
        let moved: Timings = serde_yaml_ng::from_str("tunnelPing: 15s\n").unwrap();
        assert_eq!(a.hash(), written.hash(), "writing a default out another way changed the hash");
        assert_ne!(a.hash(), moved.hash());
        assert_eq!(a.hash().len(), 12);
        assert!(a.hash().chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    /// What `print-config` writes reads back as the same timings: the play
    /// writes the defaults out, and the agent must read them unchanged.
    #[test]
    fn what_is_printed_reads_back_the_same() {
        let yaml = serde_yaml_ng::to_string(&Timings::default()).unwrap();
        let back: Timings = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(back, Timings::default());
        assert!(yaml.contains("tunnelPing: 20s"), "{yaml}");
    }
}
