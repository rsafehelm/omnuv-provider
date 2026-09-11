//! Everything the hypervisor will say about a machine the marketplace owns.
//!
//! **The rule is the tag, and it cuts both ways.** A machine carrying a
//! marketplace tag is one Core created and is answerable for, so there is no
//! reason to be shy: the more that comes back, the fewer root-cause analyses
//! end with somebody logging into a hypervisor to read a field. A machine
//! without a marketplace tag is the provider's own business and nothing about
//! it is collected at all — the one exception is `HostCommitment`, which is
//! aggregate, opt-in and audited.
//!
//! Nothing here needs a privilege the agent did not already hold: `VM.Audit`
//! reads status and config, `Sys.Audit` reads the task log. Nothing enters the
//! guest.

use omnuv_protocol::Diagnostics;

/// What `status/current` offers, verified against a live PVE 9.2 rather than
/// recalled. Everything optional: a field that is absent on one Proxmox version
/// must not take the rest of the reading down with it.
#[derive(serde::Deserialize, Default)]
pub(crate) struct Current {
    #[serde(default)]
    pub qmpstatus: Option<String>,
    #[serde(default)]
    pub lock: Option<String>,
    #[serde(default)]
    pub uptime: Option<u64>,
    #[serde(default)]
    pub cpus: Option<u32>,
    #[serde(default)]
    pub maxmem: Option<u64>,
    #[serde(default)]
    pub mem: Option<u64>,
    #[serde(default)]
    pub maxdisk: Option<u64>,
    // Kernel pressure stall: the share of time something was made to wait.
    // Utilisation says a resource is busy; this says somebody is suffering for
    // it, which is what the buyer actually feels.
    #[serde(default)]
    pub pressurecpusome: Option<f32>,
    #[serde(default)]
    pub pressureiosome: Option<f32>,
    #[serde(default)]
    pub pressurememorysome: Option<f32>,
}

/// Fold a status reading, the VM config and an optional task error into one
/// diagnostic.
pub(crate) fn build(
    node: &str,
    current: Option<Current>,
    config: Option<&serde_json::Value>,
    guest_agent_answered: Option<bool>,
    last_task_error: Option<String>,
) -> Diagnostics {
    let c = current.unwrap_or_default();
    Diagnostics {
        run_state: c.qmpstatus,
        lock: c.lock,
        uptime_s: c.uptime,
        vcpus: c.cpus,
        memory_mib: c.maxmem.map(|b| b / (1024 * 1024)),
        memory_used_mib: c.mem.map(|b| b / (1024 * 1024)),
        disk_gib: c.maxdisk.map(|b| b / (1024 * 1024 * 1024)),
        pressure_cpu: c.pressurecpusome,
        pressure_io: c.pressureiosome,
        pressure_memory: c.pressurememorysome,
        // The agent being enabled in the config proves nothing; whether it
        // answered this pass is the fact that separates "the machine is down"
        // from "the machine is up and we cannot see inside it".
        guest_agent: guest_agent_answered,
        pci: config.map(pci_of).unwrap_or_default(),
        node: Some(node.to_string()),
        last_task_error,
    }
}

/// PCI addresses actually attached, so a GPU that was sold and did not attach
/// is visible without reading the VM config on the host by hand.
fn pci_of(config: &serde_json::Value) -> Vec<String> {
    let Some(map) = config.as_object() else { return Vec::new() };
    let mut out: Vec<String> = map
        .iter()
        .filter(|(k, _)| k.starts_with("hostpci"))
        .filter_map(|(_, v)| Some(crate::proxmox::pci_slot(v.as_str()?)))
        .collect();
    out.sort();
    out
}

/// One line of the hypervisor's own task log, which usually already contains
/// the answer to "what went wrong" and which nothing was carrying upward.
#[derive(serde::Deserialize)]
pub(crate) struct Task {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub starttime: Option<i64>,
}

/// The most recent task for this machine that did not end `OK`.
pub(crate) fn failure_in(tasks: &[Task]) -> Option<String> {
    tasks
        .iter()
        .filter(|t| t.status.as_deref().is_some_and(|s| s != "OK" && !s.is_empty()))
        .max_by_key(|t| t.starttime.unwrap_or(0))
        .map(|t| format!("{}: {}", t.kind, t.status.clone().unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reading_that_could_not_be_taken_is_absent_rather_than_zero() {
        let d = build("pve", None, None, None, None);
        assert_eq!(d.run_state, None);
        assert_eq!(d.uptime_s, None);
        assert_eq!(d.memory_mib, None, "a machine with no reading is not a machine with no memory");
        assert!(d.pci.is_empty());
        assert_eq!(d.node.as_deref(), Some("pve"));
    }

    #[test]
    fn bytes_become_the_units_the_marketplace_speaks() {
        let c = Current {
            maxmem: Some(34_359_738_368),
            mem: Some(32_028_667_904),
            maxdisk: Some(128_849_018_880),
            ..Default::default()
        };
        let d = build("pve", Some(c), None, None, None);
        assert_eq!(d.memory_mib, Some(32_768));
        assert_eq!(d.memory_used_mib, Some(30_544));
        assert_eq!(d.disk_gib, Some(120));
    }

    /// The field that explains a reconcile which looks stuck while every call
    /// returns success.
    #[test]
    fn a_lock_is_carried_up_rather_than_left_on_the_host() {
        let c = Current { lock: Some("backup".into()), ..Default::default() };
        assert_eq!(build("pve", Some(c), None, None, None).lock.as_deref(), Some("backup"));
    }

    #[test]
    fn attached_cards_are_listed_and_nothing_else_is() {
        let cfg = serde_json::json!({
            "hostpci0": "0000:21:00,pcie=1,rombar=0",
            "scsi0": "local-lvm:vm-105-disk-0,size=120G",
            "name": "omnuv-worker-x",
        });
        let d = build("pve", None, Some(&cfg), None, None);
        assert_eq!(d.pci, vec!["0000:21:00".to_string()]);
    }

    /// Proxmox also reports `agent: 1`, meaning the option is enabled in the
    /// config. That is deliberately not read: whether the agent *replied* is a
    /// different fact, and it is the one that separates "the machine is down"
    /// from "the machine is up and we cannot see inside it".
    #[test]
    fn an_enabled_guest_agent_is_not_an_answering_one() {
        let c = Current { uptime: Some(60), ..Default::default() };
        assert_eq!(build("pve", Some(c), None, Some(false), None).guest_agent, Some(false));
    }

    #[test]
    fn the_newest_failure_wins_and_successes_are_not_failures() {
        let tasks = vec![
            Task { kind: "qmstart".into(), status: Some("OK".into()), starttime: Some(300) },
            Task {
                kind: "qmclone".into(),
                status: Some("unable to create image: got lock timeout".into()),
                starttime: Some(100),
            },
            Task {
                kind: "qmstart".into(),
                status: Some("start failed: QEMU exited with code 1".into()),
                starttime: Some(200),
            },
        ];
        assert_eq!(
            failure_in(&tasks).as_deref(),
            Some("qmstart: start failed: QEMU exited with code 1")
        );
    }

    #[test]
    fn a_clean_task_log_reports_no_failure() {
        let tasks = vec![Task {
            kind: "qmstart".into(),
            status: Some("OK".into()),
            starttime: Some(1),
        }];
        assert_eq!(failure_in(&tasks), None);
    }
}
