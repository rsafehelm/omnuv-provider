//! **The host timer** (lifecycle phase 12, TD14; omnuv's
//! `docs/plans/lifecycle-phase-12.md`, "the host timer").
//!
//! The agent's lease task (`lease.rs`) stops a machine whose run lease ran
//! out, and an agent that is dead stops nothing, so a restart elsewhere could
//! leave two copies running. This is the other half: `onv-lease-expire.timer`
//! runs `onv-provider run-lease-expire` every minute, and it stops each
//! machine in `run-lease.json` past its time **when the lease task is not
//! running**. It is a separate, minimal entry point: it reads the file and
//! the configuration's hypervisor credentials, never talks to Core, and
//! never does anything but stop.
//!
//! ```text
//! no file, or empty    nothing is leased here: no lock taken, nothing asked
//! lock held            the agent's lease task holds run-lease.lock for as long
//!                      as it runs (the kernel frees it when the process or the
//!                      task is gone): it is running, so this does nothing. If
//!                      the file is also older than STALE_AFTER the task is
//!                      alive and not writing, which is said as a refusal
//! written recently     the lock was free, but the file is younger than
//!                      STALE_AFTER: an agent that does not take the lock (one
//!                      older than it, or one that could not open it) may be
//!                      running, so this does nothing
//! unreadable           refused whole: nothing in it is acted on
//! otherwise            each lease past its time: the machine's guests with its
//!                      claim tag and whole stamp, stopped when their node's
//!                      live status says they are not (lease.rs stop_leased,
//!                      the agent's own call), a decoy left and said
//! ```
//!
//! **The two never act at once.** This holds the lock for its whole pass, so
//! an agent starting meanwhile waits for it before its lease task runs; and
//! it acts only once it holds that lock, so it never acts beside a running
//! lease task. `STALE_AFTER` is the second test, for an agent that holds no
//! lock.
//!
//! **What it writes**: each stop, each refusal and each failure, to its own
//! file (`/var/log/onv/run-lease-expire.log`) and to the audit log, as the
//! `host-timer` actor; one line per run to the journal, the verdict. Ids,
//! VMIDs, nodes and the hypervisor's own error text; never a credential. It
//! never writes `run-lease.json`, whose one writer is the agent.

use crate::lease;
use crate::proxmox::Client;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// **How recently a lock-free agent must have written the file for this to
/// leave it alone.** Derived, not measured:
///
/// ```text
/// at least  lease::WRITE_EVERY (30 s), the lease task's period, plus 15 s
///           for a pass that stops nothing (a write): a live agent's file
///           is never older than that between two passes
/// at most   60 s: a machine whose agent died at its deadline D is stopped
///           by D + 30 (the agent's last pass) + STALE_AFTER + EVERY (60 s),
///           and Core budgets lifecycle.run_lease_pass + run_lease_skew =
///           150 s past D for it (run_lease_pass says "the host timer every
///           60 s")
/// ```
///
/// 45 s leaves 15 s of the skew for the stop itself. It matters only when no
/// agent holds the lock; one that does is never raced, whatever the file's
/// age.
pub const STALE_AFTER: Duration = Duration::from_secs(45);

/// The timer's period, as `onv-lease-expire.timer` says it (`OnCalendar=
/// minutely`, `AccuracySec=1s`). Written here so the bound above can name it.
pub const EVERY: Duration = Duration::from_secs(60);

// The derivation above, held at compile time: longer than the agent's period,
// and short enough that a dead agent's machine stops within Core's 150 s.
const _: () = assert!(
    STALE_AFTER.as_secs() > lease::WRITE_EVERY.as_secs()
        && lease::WRITE_EVERY.as_secs() + STALE_AFTER.as_secs() + EVERY.as_secs() <= 150
);

/// This entry point's own log, beside the audit log.
pub const DEFAULT_LOG: &str = "/var/log/onv/run-lease-expire.log";

/// What one run found, and did.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// No `run-lease.json`: nothing has been leased on this host.
    NoFile,
    /// The agent's lease task holds the lock. `stale` is the file's age when
    /// it is past [`STALE_AFTER`] too: alive and not writing.
    AgentHolds { stale: Option<u64> },
    /// The lock was free and the file younger than [`STALE_AFTER`].
    WrittenRecently { age: u64 },
    /// Empty, or no lease in it.
    NothingLeased,
    /// Leases, none past its time.
    NoneDue { leases: usize },
    /// Could not be read, parsed or locked: nothing was stopped.
    Refused(String),
    /// `--dry-run`: the machines a run would try to stop.
    WouldStop(Vec<String>),
    /// Leases past their time, acted on.
    Acted { due: usize, stopped: usize, refused: usize, failed: usize },
}

impl Verdict {
    /// The journal's one line for the run.
    pub fn describe(&self) -> String {
        match self {
            Verdict::NoFile => "no run-lease.json: nothing is leased on this host".into(),
            Verdict::AgentHolds { stale: None } => "the agent's lease task holds the lease lock; nothing to do".into(),
            Verdict::AgentHolds { stale: Some(age) } => format!(
                "the agent's lease task holds the lease lock and has not written run-lease.json for {age} s; \
                 nothing stopped, since the timer never acts beside a running lease task"
            ),
            Verdict::WrittenRecently { age } => format!(
                "the lease lock is free but run-lease.json was written {age} s ago (under {} s): an agent may be \
                 running without the lock; nothing to do",
                STALE_AFTER.as_secs()
            ),
            Verdict::NothingLeased => "run-lease.json names no lease; nothing to do".into(),
            Verdict::NoneDue { leases } => format!("{leases} lease(s), none past its time; nothing to do"),
            Verdict::Refused(why) => format!("refused, nothing stopped: {why}"),
            Verdict::WouldStop(ids) => format!("dry run: would stop {} machine(s): {}", ids.len(), ids.join(" ")),
            Verdict::Acted { due, stopped, refused, failed } => format!(
                "{due} lease(s) past their time without the agent: {stopped} guest(s) stopped, {refused} refused, \
                 {failed} machine(s) not stopped"
            ),
        }
    }

    /// The process's exit status: 0 when nothing is wrong, 1 when something
    /// was not done that should have been, 2 when the file was refused.
    pub fn exit_code(&self) -> i32 {
        match self {
            Verdict::Refused(_) => 2,
            Verdict::AgentHolds { stale: Some(_) } => 1,
            Verdict::Acted { failed, .. } if *failed > 0 => 1,
            _ => 0,
        }
    }
}

/// Where the timer says what it did: its own file, and the audit log.
pub struct Log {
    own: PathBuf,
    /// The audit log, opened on the first record: a run with nothing to say
    /// writes nothing there. `None` in tests, where the journal copy (stdout)
    /// and the process's queue are all `audit::record` touches.
    audit: Option<String>,
    opened: std::sync::OnceLock<()>,
}

impl Log {
    pub fn new(own: PathBuf, audit: Option<String>) -> Self {
        Self { own, audit, opened: std::sync::OnceLock::new() }
    }

    /// One record: a line in the timer's own file (one write, appended) and
    /// one in the audit log, as `host-timer`, and on stderr for the journal.
    pub fn say(&self, subject: &str, outcome: &str, detail: &str) {
        if let Some(path) = &self.audit {
            self.opened.get_or_init(|| {
                crate::audit::open(Some(path));
            });
        }
        crate::audit::record("instance.lease", "host-timer", subject, outcome, Some(detail));
        let ts = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let line = format!("{ts} {subject} {outcome}: {detail}\n");
        eprintln!("run-lease-expire: {subject} {outcome}: {detail}");
        let written = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.own)
            .and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()));
        if let Err(e) = written {
            eprintln!("run-lease-expire: {} not written: {e}", self.own.display());
        }
    }
}

/// The file's age by its modification time, against `now`. A time in the
/// future (the clock stepped back) is age zero: written just now, as far as
/// can be said.
fn age_of(file: &Path, now: SystemTime) -> std::io::Result<Duration> {
    let written = std::fs::metadata(file)?.modified()?;
    Ok(now.duration_since(written).unwrap_or(Duration::ZERO))
}

fn refuse(log: &Log, file: &Path, why: String) -> Verdict {
    log.say(&file.display().to_string(), "refused", &format!("{why}; nothing stopped"));
    Verdict::Refused(why)
}

/// **One run.** Stops, when `act`, each machine in `file` past its time, if
/// and only if the agent's lease task is not running; see the module note for
/// the order of the tests. The lock is held from the first test to the last
/// stop, and released when this returns.
pub async fn pass(driver: &Client, file: &Path, log: &Log, now: SystemTime, act: bool) -> Verdict {
    match std::fs::metadata(file) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Verdict::NoFile,
        Err(e) => return refuse(log, file, format!("it could not be read: {e}")),
    }

    let lock_path = lease::lock_file(file);
    let lock = match lease::open_lock(&lock_path) {
        Ok(f) => f,
        Err(e) => return refuse(log, file, format!("the lease lock {} could not be opened: {e}", lock_path.display())),
    };
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            let stale = age_of(file, now).ok().filter(|a| *a > STALE_AFTER).map(|a| a.as_secs());
            let v = Verdict::AgentHolds { stale };
            if stale.is_some() {
                log.say(&file.display().to_string(), "refused", &v.describe());
            }
            return v;
        }
        Err(std::fs::TryLockError::Error(e)) => {
            return refuse(log, file, format!("the lease lock {} could not be taken: {e}", lock_path.display()));
        }
    }

    // Under the lock from here: the age read again, since the agent may have
    // written the file just before it let the lock go.
    let age = match age_of(file, now) {
        Ok(a) => a,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Verdict::NoFile,
        Err(e) => return refuse(log, file, format!("its age could not be read: {e}")),
    };
    if age < STALE_AFTER {
        return Verdict::WrittenRecently { age: age.as_secs() };
    }
    let body = match std::fs::read_to_string(file) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Verdict::NoFile,
        Err(e) => return refuse(log, file, format!("it could not be read: {e}")),
    };
    let leases = match lease::read_body(&body) {
        Ok(l) => l,
        Err(e) => return refuse(log, file, e),
    };
    if leases.is_empty() {
        return Verdict::NothingLeased;
    }
    let now_unix = now.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut due: Vec<lease::Written> = leases.iter().filter(|l| l.until_unix <= now_unix).cloned().collect();
    due.sort_by(|a, b| a.id.cmp(&b.id));
    due.dedup_by(|a, b| a.id == b.id);
    if due.is_empty() {
        return Verdict::NoneDue { leases: leases.len() };
    }
    if !act {
        return Verdict::WouldStop(due.into_iter().map(|l| l.id).collect());
    }

    let (mut stopped, mut refused, mut failed) = (0, 0, 0);
    for l in &due {
        // Said before it is tried, so a run that dies mid-stop leaves a trace.
        log.say(
            &l.id,
            "attempt",
            &format!(
                "its lease ran out {} s ago and the agent's lease task is not running (file {} s old); stopping it",
                now_unix.saturating_sub(l.until_unix),
                age.as_secs()
            ),
        );
        let mut out = lease::Stops::default();
        let result = driver.stop_leased(&l.id, &mut out).await;
        for g in &out.stopped {
            log.say(&l.id, "stopped", g);
        }
        for r in &out.refused {
            log.say(&l.id, "refused", r);
        }
        stopped += out.stopped.len();
        refused += out.refused.len();
        if let Err(e) = result {
            failed += 1;
            log.say(&l.id, "failed", &format!("not stopped; the next run tries again: {e:#}"));
        }
    }
    Verdict::Acted { due: due.len(), stopped, refused, failed }
}

/// `onv-provider run-lease-expire`: one run, from the agent's own files. The
/// exit status is [`Verdict::exit_code`]; a configuration that cannot be
/// loaded is 1, said without the loader's words (they can quote a value).
pub async fn main(config: &str, secrets: &str, dry_run: bool) -> i32 {
    let audit = std::env::var("OMNUV_AUDIT_LOG").unwrap_or_else(|_| "/var/log/onv/audit.log".into());
    let own = std::env::var("OMNUV_LEASE_TIMER_LOG").unwrap_or_else(|_| DEFAULT_LOG.into());
    let log = Log::new(PathBuf::from(own), Some(audit));
    let cfg = match crate::config::load_agent_with(config, secrets) {
        Ok(c) => c,
        Err(_) => {
            log.say(
                config,
                "refused",
                "the configuration could not be loaded, so no machine can be asked about; \
                 `onv-provider check-config` names the key; nothing stopped",
            );
            return 1;
        }
    };
    let driver = match crate::agent::driver_of(&cfg) {
        Ok(d) => d,
        Err(e) => {
            log.say(config, "refused", &format!("the hypervisor client could not be built: {e:#}; nothing stopped"));
            return 1;
        }
    };
    let file = lease::file(&cfg.proxmox.snippet_dir);
    let v = pass(&driver, &file, &log, SystemTime::now(), !dry_run).await;
    println!("run-lease-expire: {}", v.describe());
    v.exit_code()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pvemock::{task_ok, Mock};

    const ID: &str = "0b1f7a2e-1111-4222-8333-944455556666";

    /// Two guests carry the machine's tag: 701 with its whole stamp, 702 (the
    /// decoy) with another. `status` is what 701's node says of it now.
    async fn proxmox(status: (u16, serde_json::Value)) -> Mock {
        let tags = format!("onv-instance;{}", crate::names::short_tag(ID));
        let stamp = crate::names::description(crate::names::TAG_INSTANCE, ID);
        Mock::start(move |method, path, _| {
            if let Some(r) = task_ok(path) {
                return r;
            }
            match (method, path) {
                ("GET", "/cluster/resources?type=vm") => (
                    200,
                    serde_json::json!([
                        {"node": "n1", "vmid": 701, "tags": tags, "status": "running"},
                        {"node": "n1", "vmid": 702, "tags": tags, "status": "running"},
                    ]),
                ),
                ("GET", "/nodes/n1/qemu/701/config") => (200, serde_json::json!({"description": stamp})),
                ("GET", "/nodes/n1/qemu/702/config") => {
                    (200, serde_json::json!({"description": "Omnuv instance 0b1f7a2e-1111-4222-8333-000000000000"}))
                }
                ("GET", "/nodes/n1/qemu/701/status/current") => status.clone(),
                ("GET", p) if p.ends_with("/status/current") => (200, serde_json::json!({"status": "running"})),
                ("POST", p) if p.ends_with("/status/stop") => (200, serde_json::json!("UPID:n1:stop")),
                _ => (404, serde_json::Value::Null),
            }
        })
        .await
    }

    fn running() -> (u16, serde_json::Value) {
        (200, serde_json::json!({"status": "running"}))
    }

    fn stops(mock: &Mock) -> Vec<String> {
        mock.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.method == "POST" && c.path.ends_with("/status/stop"))
            .map(|c| c.path.clone())
            .collect()
    }

    fn asked_anything(mock: &Mock) -> bool {
        !mock.calls.lock().unwrap().is_empty()
    }

    struct Host {
        _dir: tempfile::TempDir,
        file: PathBuf,
        log: Log,
        own: PathBuf,
    }

    /// A state directory holding `body` as run-lease.json, last written
    /// `age` ago.
    fn host(body: Option<&str>, age: Duration) -> Host {
        let dir = tempfile::tempdir().expect("a directory");
        let file = dir.path().join("run-lease.json");
        if let Some(body) = body {
            std::fs::write(&file, body).unwrap();
            let f = std::fs::File::options().write(true).open(&file).unwrap();
            f.set_modified(SystemTime::now() - age).unwrap();
        }
        let own = dir.path().join("run-lease-expire.log");
        Host { log: Log::new(own.clone(), None), file, own, _dir: dir }
    }

    /// One lease, `ID`, that ran out `ago` seconds before now.
    fn expired_body(ago: u64) -> String {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        serde_json::json!({"leases": [{"id": ID, "until_unix": now - ago}]}).to_string()
    }

    fn own_log(h: &Host) -> String {
        std::fs::read_to_string(&h.own).unwrap_or_default()
    }

    /// **An expired machine is stopped when the agent is dead**: no lock
    /// held, the file two minutes old, the lease a minute past. The guest
    /// with the whole stamp is stopped, and said in the timer's own file.
    #[tokio::test]
    async fn an_expired_machine_is_stopped_when_the_agent_is_dead() {
        let mock = proxmox(running()).await;
        let h = host(Some(&expired_body(60)), Duration::from_secs(120));
        let v = pass(&mock.client(), &h.file, &h.log, SystemTime::now(), true).await;
        assert_eq!(v, Verdict::Acted { due: 1, stopped: 1, refused: 1, failed: 0 }, "{}", v.describe());
        assert_eq!(stops(&mock), ["/nodes/n1/qemu/701/status/stop"], "the wrong guests were stopped");
        let said = own_log(&h);
        assert!(said.contains(&format!("{ID} attempt:")), "the attempt was not said first: {said}");
        assert!(said.contains(&format!("{ID} stopped: vm 701 on n1")), "the stop was not said: {said}");
        assert!(!mock.called("DELETE", "/nodes/n1/qemu/701"), "a stop destroyed");
        assert!(v.exit_code() == 0);
    }

    /// **A decoy with the tag and another stamp is left**, and the refusal is
    /// said, naming the stamp it carries.
    #[tokio::test]
    async fn a_decoy_with_the_tag_but_another_stamp_is_left() {
        let mock = proxmox(running()).await;
        let h = host(Some(&expired_body(60)), Duration::from_secs(120));
        pass(&mock.client(), &h.file, &h.log, SystemTime::now(), true).await;
        assert!(!stops(&mock).iter().any(|p| p.contains("/702/")), "the decoy was stopped");
        let said = own_log(&h);
        assert!(
            said.contains(&format!("{ID} refused: vm 702 on n1 carries {ID}'s tag but not its stamp")),
            "the decoy's refusal was not said: {said}"
        );
    }

    /// **Nothing is stopped while the agent is alive**: its lease task holds
    /// the lock. The file is stale too, so the refusal is said; nothing is
    /// asked of Proxmox at all.
    #[tokio::test]
    async fn nothing_is_stopped_while_the_agent_holds_the_lease_lock() {
        let mock = proxmox(running()).await;
        let h = host(Some(&expired_body(60)), Duration::from_secs(120));
        let held = lease::take_lock(&h.file).await.expect("the agent's lock");
        let v = pass(&mock.client(), &h.file, &h.log, SystemTime::now(), true).await;
        assert_eq!(v, Verdict::AgentHolds { stale: Some(120) }, "{}", v.describe());
        assert!(!asked_anything(&mock), "Proxmox was asked while the agent ran");
        assert!(own_log(&h).contains("refused"), "a live agent that stopped writing was not said");
        // A fresh file under a held lock is the normal case: nothing said.
        let fresh = host(Some(&expired_body(60)), Duration::from_secs(5));
        let _also = lease::take_lock(&fresh.file).await.expect("the agent's lock");
        let v = pass(&mock.client(), &fresh.file, &fresh.log, SystemTime::now(), true).await;
        assert_eq!(v, Verdict::AgentHolds { stale: None });
        assert_eq!(own_log(&fresh), "", "the normal case was logged");
        drop(held);
        assert!(stops(&mock).is_empty());
    }

    /// **Nothing is stopped while an agent without the lock is writing**: an
    /// older agent, or one that could not open the lock, is alive as long as
    /// its file is younger than `STALE_AFTER`.
    #[tokio::test]
    async fn nothing_is_stopped_while_the_file_is_younger_than_the_bound() {
        let mock = proxmox(running()).await;
        let h = host(Some(&expired_body(60)), STALE_AFTER - Duration::from_secs(5));
        let v = pass(&mock.client(), &h.file, &h.log, SystemTime::now(), true).await;
        assert!(matches!(v, Verdict::WrittenRecently { .. }), "{}", v.describe());
        assert!(!asked_anything(&mock), "Proxmox was asked while an agent wrote");
    }

    /// **An agent that starts during a pass waits for it**, and one that holds
    /// the lock keeps the timer out: the exclusion, from both sides.
    #[tokio::test]
    async fn an_agent_starting_during_a_pass_waits_for_it() {
        let h = host(Some("{\"leases\": []}"), Duration::from_secs(120));
        let timer = lease::open_lock(&lease::lock_file(&h.file)).unwrap();
        timer.try_lock().expect("the timer's lock");
        let file = h.file.clone();
        let agent = tokio::spawn(async move { lease::take_lock(&file).await });
        tokio::time::sleep(Duration::from_millis(200)).await; // wait: nothing to poll; a lock not yet granted
        assert!(!agent.is_finished(), "the agent's lease task ran beside the timer's pass");
        drop(timer);
        let held = tokio::time::timeout(Duration::from_secs(5), agent).await.expect("the agent waited for ever");
        assert!(held.unwrap().is_some(), "the agent did not take the lock once the pass ended");
    }

    /// **An unreadable status stops nothing**: the node cannot say whether
    /// 701 runs, so it is not stopped, the failure is said with the node's
    /// own words, and the run exits non-zero.
    #[tokio::test]
    async fn an_unreadable_status_stops_nothing() {
        let mock = proxmox((500, serde_json::Value::Null)).await;
        let h = host(Some(&expired_body(60)), Duration::from_secs(120));
        let v = pass(&mock.client(), &h.file, &h.log, SystemTime::now(), true).await;
        assert!(stops(&mock).is_empty(), "a machine whose status could not be read was stopped");
        assert!(matches!(v, Verdict::Acted { stopped: 0, failed: 1, .. }), "{}", v.describe());
        assert_eq!(v.exit_code(), 1);
        assert!(own_log(&h).contains(&format!("{ID} failed: not stopped")), "{}", own_log(&h));
    }

    /// **No file, or an empty one, is a no-op**: nothing asked, nothing said.
    #[tokio::test]
    async fn an_absent_or_empty_file_is_a_no_op() {
        let mock = proxmox(running()).await;
        let absent = host(None, Duration::ZERO);
        assert_eq!(pass(&mock.client(), &absent.file, &absent.log, SystemTime::now(), true).await, Verdict::NoFile);
        assert!(!lease::lock_file(&absent.file).exists(), "a lock was made where nothing is leased");
        for body in ["", "  \n", "{\"leases\": []}"] {
            let h = host(Some(body), Duration::from_secs(120));
            let v = pass(&mock.client(), &h.file, &h.log, SystemTime::now(), true).await;
            assert_eq!(v, Verdict::NothingLeased, "{body:?}");
            assert_eq!(own_log(&h), "");
        }
        assert!(!asked_anything(&mock));
    }

    /// **A file it cannot parse is refused whole**, said, and nothing stopped:
    /// not even the lease that reads well beside a broken one.
    #[tokio::test]
    async fn a_file_it_cannot_parse_stops_nothing() {
        let mock = proxmox(running()).await;
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        for body in [
            "{\"leases\": [".to_string(),
            "not json".to_string(),
            serde_json::json!({"leases": [{"id": ID, "until_unix": now - 60}, {"id": "", "until_unix": 1}]}).to_string(),
            serde_json::json!({"leases": [{"id": ID, "until_unix": "yesterday"}]}).to_string(),
            serde_json::json!({"leases": {"id": ID}}).to_string(),
        ] {
            let h = host(Some(&body), Duration::from_secs(120));
            let v = pass(&mock.client(), &h.file, &h.log, SystemTime::now(), true).await;
            assert!(matches!(v, Verdict::Refused(_)), "{body:?} read as {}", v.describe());
            assert_eq!(v.exit_code(), 2);
            assert!(own_log(&h).contains("refused"), "{body:?}: the refusal was not said");
        }
        assert!(!asked_anything(&mock), "Proxmox was asked about a file that was refused");
    }

    /// **A lease not yet past its time is left**, and a dry run names what a
    /// run would stop without stopping it.
    #[tokio::test]
    async fn a_lease_not_yet_due_is_left_and_a_dry_run_stops_nothing() {
        let mock = proxmox(running()).await;
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let body = serde_json::json!({"leases": [{"id": ID, "until_unix": now + 600}]}).to_string();
        let h = host(Some(&body), Duration::from_secs(120));
        assert_eq!(pass(&mock.client(), &h.file, &h.log, SystemTime::now(), true).await, Verdict::NoneDue { leases: 1 });
        let h = host(Some(&expired_body(60)), Duration::from_secs(120));
        let v = pass(&mock.client(), &h.file, &h.log, SystemTime::now(), false).await;
        assert_eq!(v, Verdict::WouldStop(vec![ID.to_string()]));
        assert!(!asked_anything(&mock));
    }

    /// **The period the bound is derived from is the unit's**, and the unit
    /// runs this entry point.
    #[test]
    fn the_timer_unit_runs_this_entry_point_every_minute_to_the_second() {
        let timer = include_str!("../packaging/deb/lib/systemd/system/onv-lease-expire.timer");
        let lines: Vec<&str> = timer.lines().map(str::trim).collect();
        assert!(lines.contains(&"OnCalendar=minutely"), "the timer's period is not the one STALE_AFTER assumes");
        assert!(lines.contains(&"AccuracySec=1s"), "systemd's default accuracy (1 min) would double the period");
        assert_eq!(EVERY, Duration::from_secs(60));
        let service = include_str!("../packaging/deb/lib/systemd/system/onv-lease-expire.service");
        assert!(
            service.lines().any(|l| l == "ExecStart=/usr/bin/onv-provider run-lease-expire --config /etc/onv/agent.yaml"),
            "the service does not run the host timer's entry point"
        );
    }

    /// **The bound fits Core's margin**: a machine whose agent died at its
    /// deadline is stopped within run_lease_pass + run_lease_skew (150 s,
    /// omnuv's lifecycle.*) of it, and a live agent's file is never older
    /// than the bound between passes.
    #[test]
    fn the_staleness_bound_sits_between_the_agents_period_and_cores_margin() {
        assert!(STALE_AFTER > lease::WRITE_EVERY, "a live agent between two passes would be taken for dead");
        let worst = lease::WRITE_EVERY + STALE_AFTER + EVERY;
        assert!(worst <= Duration::from_secs(150), "a dead agent's machine stops {worst:?} after its deadline");
    }
}
