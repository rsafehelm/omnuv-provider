//! What the Workload Agent is told: `/etc/onv/workload.yaml`.
//!
//! **Written by cloud-init, from the Provider Agent's own `timings.workload`.**
//! The Provider Agent generates every worker's first-boot configuration, so it
//! is the generator this file belongs to: a value changed in `agent.yaml`
//! changes the worker's snippet, and the agent reboots a worker whose snippet
//! changed (PROVIDER-31), which a marketplace-owned machine allows. So a new
//! value reaches a worker when it is rebuilt or rebooted, and never before.
//!
//! **Only for machines the marketplace owns.** The Workload Agent runs in
//! inference workers and never in a buyer's machine, so nothing writes this
//! file anywhere else.
//!
//! Shared by both programs through `#[path]`: the crate has no library, and
//! the writer's defaults and bounds must be the reader's. The Workload Agent
//! includes it with `dead_code` allowed, because it uses the reading half and
//! the Provider Agent the writing half; here, only what the Provider Agent
//! does not use says so.

use crate::dur::Dur;
use serde::{Deserialize, Serialize};

/// Where cloud-init writes it and the Workload Agent reads it.
pub const PATH: &str = "/etc/onv/workload.yaml";

/// How long the Workload Agent waits for its own probe of the model server.
/// A bound on `degradedAbove`, which must be shorter: an answer slower than
/// this is an error, read as down, and can never be read as slow.
pub const PROBE_TIMEOUT: Dur = Dur::secs(10);

/// The fastest poll Core may ask of an agent (`providers.agent_poll` is at
/// least ten seconds in Core's own bounds, and the agent holds it there too).
/// A Provider Agent reading its workers on that poll reads a report no more
/// often than this.
pub const FASTEST_READ: Dur = Dur::secs(10);

/// `/etc/onv/workload.yaml`. Every key has its default, which is the value the
/// code held before the file existed (26 September 2026).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct WorkloadConfig {
    /// How often the report is written. Faster than the Provider Agent reads,
    /// so a read never finds nothing new: a report that does not move reads as
    /// a reporter that died.
    pub report_every: Dur,
    /// Beyond this, a worker that answers is still not somewhere to send
    /// traffic. Generous on purpose: `/v1/models` is a trivial handler, so two
    /// seconds means the event loop is starved, not that the model is large.
    pub degraded_above: Dur,
}

impl Default for WorkloadConfig {
    fn default() -> Self {
        Self { report_every: Dur::secs(15), degraded_above: Dur::secs(2) }
    }
}

impl WorkloadConfig {
    /// Each value against its bounds, named under `prefix` (`timings.workload.`
    /// in the agent's file, nothing in the worker's own).
    pub fn check(&self, prefix: &str) -> Vec<String> {
        let mut bad = Vec::new();
        let within = |bad: &mut Vec<String>, key: &str, v: Dur, lo: Dur, hi: Dur, why: &str| {
            if v < lo || v > hi {
                bad.push(format!("{prefix}{key} is {v}; it must be between {lo} and {hi}: {why}"));
            }
        };
        within(
            &mut bad,
            "reportEvery",
            self.report_every,
            Dur::secs(1),
            Dur::mins(2),
            "each report runs the GPU query and two probes, and a report older than two minutes is not about now",
        );
        within(
            &mut bad,
            "degradedAbove",
            self.degraded_above,
            Dur::millis(100),
            Dur::millis(PROBE_TIMEOUT.as_millis() - 1000),
            "the probe gives up at ten seconds, so a threshold at or past it could never read as slow",
        );
        bad
    }

    /// Parse and check the worker's own file. Unknown keys are refused, and
    /// every problem is named, not just the first. An empty file is the
    /// defaults, like an absent one.
    #[allow(dead_code)] // The Workload Agent's; the Provider Agent only writes the file.
    pub fn parse(yaml: &str) -> Result<Self, Vec<String>> {
        if yaml.trim().is_empty() {
            return Ok(Self::default());
        }
        let c: Self = serde_yaml_ng::from_str(yaml).map_err(|e| vec![e.to_string()])?;
        let bad = c.check("");
        if bad.is_empty() { Ok(c) } else { Err(bad) }
    }

    /// The file's text, as cloud-init writes it.
    pub fn to_yaml(self) -> String {
        format!(
            "# Written by cloud-init from the Provider Agent's timings.workload.\n\
             # A changed value reaches this machine when it is rebuilt or rebooted.\n\
             reportEvery: {}\ndegradedAbove: {}\n",
            self.report_every, self.degraded_above
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The defaults are the values the code held**: the Workload Agent's
    /// `INTERVAL` (15 s) and `DEGRADED_ABOVE` (2000 ms) before 26 September.
    #[test]
    fn the_defaults_are_the_values_the_workload_agent_held() {
        let d = WorkloadConfig::default();
        assert_eq!(d.report_every.std(), std::time::Duration::from_secs(15));
        assert_eq!(d.degraded_above.std(), std::time::Duration::from_millis(2000));
        assert!(d.check("").is_empty(), "{:?}", d.check(""));
    }

    /// What the agent writes is what the worker reads back, unchanged.
    #[test]
    fn what_is_written_reads_back_the_same() {
        let c = WorkloadConfig { report_every: Dur::secs(5), degraded_above: Dur::millis(750) };
        assert_eq!(WorkloadConfig::parse(&c.to_yaml()), Ok(c));
        assert_eq!(WorkloadConfig::parse(""), Ok(WorkloadConfig::default()));
    }

    /// Each bound refuses, by name; so does an unknown key and a bare number.
    #[test]
    fn a_file_is_refused_key_by_key() {
        let e = WorkloadConfig::parse("reportEvery: 0s\ndegradedAbove: 10s\n").unwrap_err();
        assert!(e.iter().any(|m| m.starts_with("reportEvery is 0s")), "{e:?}");
        assert!(e.iter().any(|m| m.starts_with("degradedAbove is 10s")), "{e:?}");
        let e = WorkloadConfig::parse("reportEvry: 15s\n").unwrap_err();
        assert!(e[0].contains("reportEvry"), "{e:?}");
        let e = WorkloadConfig::parse("reportEvery: 15\n").unwrap_err();
        assert!(e[0].contains("15s"), "{e:?}");
        assert!(WorkloadConfig::parse("degradedAbove: 9s\n").is_ok(), "the last value under the probe's timeout");
    }
}
