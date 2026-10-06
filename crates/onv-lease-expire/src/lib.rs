//! **The host timer** (lifecycle phase 12, TD14; omnuv's
//! `docs/plans/lifecycle-phase-12.md`, "the host timer").
//!
//! The agent's lease task (`lease.rs`) stops a machine whose run lease ran
//! out, and an agent that is dead stops nothing, so a restart elsewhere could
//! leave two copies running. This is the other half: `onv-lease-expire.timer`
//! runs `onv-lease-expire` every minute, and it stops each machine in
//! `run-lease.json` past its time **when the lease task is not running**.
//!
//! **A binary of its own, with a credential of its own** (omnuv's modular
//! design, A3). It was `onv-provider run-lease-expire`, which loaded the
//! agent's whole configuration and both its credentials, so a configuration
//! the agent refused disarmed it too, and it held Core's token for no
//! reason. Now it reads four keys of agent.yaml (`ForTimer`) and one token,
//! `onv@pve!lease` (VM.Audit and VM.PowerMgmt on the buyers' pool), handed
//! to it by its unit's `LoadCredential=`; it refuses to start without it. It
//! links no Core client, never talks to Core, and never does anything but
//! stop.
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
//!                      live status says they are not
//!                      (`onv_driver_proxmox::leased::stop_leased`, the
//!                      agent's own rule), a decoy left and said
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

mod pve;
#[cfg(test)]
mod mock;

pub use onv_agent_lib::lease_token::{read_token, CREDENTIAL, CREDENTIAL_SOURCE, PRIVILEGES};
use onv_agent_lib::audit;
use onv_agent_lib::run_lease as lease;
use onv_driver_proxmox::leased::{self, Api};
pub use pve::Client;
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
                audit::open(Some(path));
            });
        }
        audit::record("instance.lease", "host-timer", subject, outcome, Some(detail));
        let ts = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        // One record, one line: a hypervisor's hint can carry newlines.
        let line = format!("{ts} {subject} {outcome}: {}\n", detail.replace(['\n', '\r'], " "));
        eprintln!("run-lease-expire: {subject} {outcome}: {detail}");
        let written = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.own)
            .and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()));
        if let Err(e) = written {
            eprintln!("run-lease-expire: {} not written: {e:#}", self.own.display());
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
/// stop, and released when this returns. `driver` is asked for only when
/// there is something to stop, so a hypervisor client that cannot be built
/// is said only then, not every minute on a host with nothing leased.
pub async fn pass(driver: &anyhow::Result<Client>, file: &Path, log: &Log, now: SystemTime, act: bool) -> Verdict {
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
    let driver = match driver {
        Ok(d) => d,
        Err(e) => return refuse(log, file, format!("the hypervisor client could not be built: {e:#}")),
    };

    // Every due lease is asked about on every run (this keeps no state of its
    // own), but only what is done is said: a machine already stopped makes
    // no line, and a stop is said just before it is sent.
    let (mut stopped, mut refused, mut failed) = (0, 0, 0);
    for l in &due {
        let announce = |guest: &str| {
            log.say(
                &l.id,
                "attempt",
                &format!(
                    "{guest}: its lease ran out {} s ago and the agent's lease task is not running \
                     (run-lease.json {} s old); stopping it",
                    now_unix.saturating_sub(l.until_unix),
                    age.as_secs()
                ),
            )
        };
        let mut out = leased::Stops { announce: Some(&announce), ..Default::default() };
        let result = leased::stop_leased(driver, &l.id, &mut out).await;
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

/// What the timer reads of `agent.yaml`: the hypervisor's address, its
/// certificate and where the lease file is. **Nothing else**, so a
/// key the agent refuses, or a credential the file still holds from an older
/// `join`, is never parsed here, and a configuration the agent refuses does
/// not disarm the timer.
#[derive(serde::Deserialize)]
struct ForTimer {
    proxmox: TimerProxmox,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TimerProxmox {
    api_url: String,
    #[serde(default)]
    tls_fingerprint_sha256: Option<String>,
    #[serde(default = "default_snippet_dir")]
    snippet_dir: String,
}

/// The agent's own default for `proxmox.snippetDir` (its config.rs).
fn default_snippet_dir() -> String {
    "/var/lib/onv/snippets".to_string()
}

/// **The token holds what it should, and nothing more**, asked of Proxmox with
/// the token itself (`/access/permissions`, which answers any caller its own):
/// [`PRIVILEGES`] on the buyers' pool, and no privilege outside them anywhere.
/// What deploy-agent.yml spends the token on before it trusts it.
pub async fn probe(driver: &Client) -> Result<String, String> {
    let held: std::collections::BTreeMap<String, std::collections::BTreeMap<String, serde_json::Value>> =
        driver.get_json("/access/permissions").await.map_err(|e| format!("the token was refused: {e:#}"))?;
    let pool = format!("/pool/{}", onv_agent_lib::names::POOL_BUYERS);
    let beyond: Vec<String> = held
        .iter()
        .flat_map(|(path, privs)| privs.keys().filter(|p| !PRIVILEGES.contains(&p.as_str())).map(move |p| format!("{p} on {path}")))
        .collect();
    if !beyond.is_empty() {
        return Err(format!("the token holds more than {}: {}", PRIVILEGES.join(" and "), beyond.join(", ")));
    }
    let on_pool = held.get(&pool);
    let lacking: Vec<&str> =
        PRIVILEGES.iter().copied().filter(|p| !on_pool.is_some_and(|privs| privs.contains_key(*p))).collect();
    if !lacking.is_empty() {
        return Err(format!("the token lacks {} on {pool}", lacking.join(" and ")));
    }
    Ok(format!("the token authenticates and holds {} on {pool}, and nothing else", PRIVILEGES.join(" and ")))
}

/// One invocation, as `cli` reads it from the process: separate so a test
/// can run it whole against a stand-in hypervisor.
pub struct Invocation {
    pub config: String,
    pub dry_run: bool,
    pub probe: bool,
    pub credentials: Option<PathBuf>,
    pub log: Log,
}

const USAGE: &str = "\
onv-lease-expire - the Omnuv host timer

USAGE:
    onv-lease-expire [--config /etc/onv/agent.yaml] [--dry-run]
    onv-lease-expire [--config /etc/onv/agent.yaml] --probe

Run by onv-lease-expire.timer every minute, as onv: when the agent's lease
task is not running, it stops each machine in run-lease.json past its run
lease, and only stops. `--dry-run` says what it would stop. It exits 0 when
nothing is wrong, 1 when something was not done (a missing token among
them), and 2 when the lease file was refused.

It holds one credential, its own Proxmox token (onv@pve!lease: VM.Audit and
VM.PowerMgmt on the buyers' pool), given by its unit's LoadCredential=; it
refuses to start without it. It reads agent.yaml's proxmox address,
certificate and snippetDir, and never Core's token. `--probe` asks
Proxmox, with the token, what the token holds, and fails on anything more.
";

/// `onv-lease-expire`: one run. The exit status is [`Verdict::exit_code`]; a
/// missing or wrong token, or a configuration that cannot be read, is 1, said
/// without the loader's words (they can quote a value).
pub async fn cli() -> i32 {
    // reqwest needs a process-wide default when built with
    // `rustls-no-provider`; ring, the agent's.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return 0;
    }
    let known = |a: &String| matches!(a.as_str(), "--config" | "--dry-run" | "--probe");
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if !known(a) {
            eprint!("onv-lease-expire: unknown argument {a:?}\n\n{USAGE}");
            return 2;
        }
        if a == "--config" && it.next().is_none() {
            eprintln!("onv-lease-expire: --config needs a path");
            return 2;
        }
    }
    let config = args
        .iter()
        .position(|a| a == "--config")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "/etc/onv/agent.yaml".into());
    // As the agent's user, as the unit runs it: a log this made as root is one
    // the unit can no longer append to, and nobody would notice.
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!(
            "onv-lease-expire: not as root; as the agent's user, as onv-lease-expire.service runs it: \
             systemd-run -p User=onv -p LoadCredential={CREDENTIAL}:{CREDENTIAL_SOURCE} --pipe --wait \
             /usr/bin/onv-lease-expire --dry-run. Nothing done"
        );
        return 1;
    }
    let audit = std::env::var("OMNUV_AUDIT_LOG").unwrap_or_else(|_| "/var/log/onv/audit.log".into());
    let own = std::env::var("OMNUV_LEASE_TIMER_LOG").unwrap_or_else(|_| DEFAULT_LOG.into());
    let inv = Invocation {
        config,
        dry_run: args.iter().any(|a| a == "--dry-run"),
        probe: args.iter().any(|a| a == "--probe"),
        credentials: std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from),
        log: Log::new(PathBuf::from(own), Some(audit)),
    };
    run(&inv).await
}

/// **One run, in order: the token, then the configuration, then the pass.**
/// No token is a refusal before anything else is read or asked: the timer
/// does not start without the one credential it is given.
pub async fn run(inv: &Invocation) -> i32 {
    let token = match read_token(inv.credentials.as_deref()) {
        Ok(t) => t,
        Err(why) => {
            inv.log.say(CREDENTIAL, "refused", &format!("{why}; nothing stopped"));
            return 1;
        }
    };
    let cfg = match std::fs::read_to_string(&inv.config)
        .ok()
        .and_then(|raw| serde_yaml_ng::from_str::<ForTimer>(&raw).ok())
    {
        Some(c) => c.proxmox,
        None => {
            inv.log.say(
                &inv.config,
                "refused",
                "the configuration could not be read (proxmox.apiUrl, and tlsFingerprintSha256 and \
                 snippetDir where set), so no machine can be asked about; nothing stopped",
            );
            return 1;
        }
    };
    let driver = Client::new(&cfg.api_url, cfg.tls_fingerprint_sha256.as_deref(), &token.id, token.secret.expose());
    if inv.probe {
        let said = match &driver {
            Ok(d) => probe(d).await,
            Err(e) => Err(format!("the hypervisor client could not be built: {e:#}")),
        };
        return match said {
            Ok(fine) => {
                println!("onv-lease-expire: {} ({})", fine, token.id);
                0
            }
            Err(why) => {
                inv.log.say(CREDENTIAL, "refused", &format!("{} ({})", why, token.id));
                1
            }
        };
    }
    let file = lease::file(&cfg.snippet_dir);
    let v = pass(&driver, &file, &inv.log, SystemTime::now(), !inv.dry_run).await;
    println!("run-lease-expire: {}", v.describe());
    v.exit_code()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{task_ok, Mock};
    use onv_agent_lib::names;

    const ID: &str = "0b1f7a2e-1111-4222-8333-944455556666";

    /// Two guests carry the machine's tag: 701 with its whole stamp, 702 (the
    /// decoy) with another. `status` is what 701's node says of it now.
    async fn proxmox(status: (u16, serde_json::Value)) -> Mock {
        let tags = format!("onv-instance;{}", names::short_tag(ID));
        let stamp = names::description(names::TAG_INSTANCE, ID);
        Mock::start(move |method, path| {
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

    /// **The agent's lease task, as far as the timer can tell**: the lock it
    /// holds for as long as it runs (the agent's `lease::take_lock`, the same
    /// `flock` on the same file, `run_lease::lock_file`).
    fn agents_lock(file: &Path) -> std::fs::File {
        let f = lease::open_lock(&lease::lock_file(file)).expect("the lock file");
        f.try_lock().expect("the agent's lock");
        f
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
        let v = pass(&Ok(mock.client()), &h.file, &h.log, SystemTime::now(), true).await;
        assert_eq!(v, Verdict::Acted { due: 1, stopped: 1, refused: 1, failed: 0 }, "{}", v.describe());
        assert_eq!(stops(&mock), ["/nodes/n1/qemu/701/status/stop"], "the wrong guests were stopped");
        let said = own_log(&h);
        let attempt = said.find(&format!("{ID} attempt: vm 701 on n1:")).expect("the attempt was not said");
        let stop = said.find(&format!("{ID} stopped: vm 701 on n1")).expect("the stop was not said");
        assert!(attempt < stop, "the stop was said before it was tried: {said}");
        assert!(!mock.called("DELETE", "/nodes/n1/qemu/701"), "a stop destroyed");
        assert!(v.exit_code() == 0);
    }

    /// **A decoy with the tag and another stamp is left**, and the refusal is
    /// said, naming the stamp it carries.
    #[tokio::test]
    async fn a_decoy_with_the_tag_but_another_stamp_is_left() {
        let mock = proxmox(running()).await;
        let h = host(Some(&expired_body(60)), Duration::from_secs(120));
        pass(&Ok(mock.client()), &h.file, &h.log, SystemTime::now(), true).await;
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
        let held = agents_lock(&h.file);
        let v = pass(&Ok(mock.client()), &h.file, &h.log, SystemTime::now(), true).await;
        assert_eq!(v, Verdict::AgentHolds { stale: Some(120) }, "{}", v.describe());
        assert!(!asked_anything(&mock), "Proxmox was asked while the agent ran");
        assert!(own_log(&h).contains("refused"), "a live agent that stopped writing was not said");
        // A fresh file under a held lock is the normal case: nothing said.
        let fresh = host(Some(&expired_body(60)), Duration::from_secs(5));
        let _also = agents_lock(&fresh.file);
        let v = pass(&Ok(mock.client()), &fresh.file, &fresh.log, SystemTime::now(), true).await;
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
        let v = pass(&Ok(mock.client()), &h.file, &h.log, SystemTime::now(), true).await;
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
        // The agent's take_lock: a blocking flock, off the runtime's threads.
        let agent = tokio::task::spawn_blocking(move || {
            let f = lease::open_lock(&lease::lock_file(&file)).ok()?;
            f.lock().ok().map(|()| f)
        });
        tokio::time::sleep(Duration::from_millis(200)).await; // wait: nothing to poll; a lock not yet granted
        assert!(!agent.is_finished(), "the agent's lease task ran beside the timer's pass");
        drop(timer);
        let held = tokio::time::timeout(Duration::from_secs(5), agent).await.expect("the agent waited for ever");
        assert!(held.unwrap().is_some(), "the agent did not take the lock once the pass ended");
    }

    /// **A machine already stopped is not stopped again, and says nothing**:
    /// the timer keeps no state, so a dead agent's expired lease is asked
    /// about every minute, and only what is done may be written.
    #[tokio::test]
    async fn a_machine_already_stopped_is_left_and_says_nothing() {
        let mock = proxmox((200, serde_json::json!({"status": "stopped"}))).await;
        let h = host(Some(&expired_body(3600)), Duration::from_secs(3000));
        let v = pass(&Ok(mock.client()), &h.file, &h.log, SystemTime::now(), true).await;
        assert_eq!(v, Verdict::Acted { due: 1, stopped: 0, refused: 1, failed: 0 }, "{}", v.describe());
        assert!(stops(&mock).is_empty(), "a stopped machine was stopped again");
        let said = own_log(&h);
        assert!(!said.contains("attempt") && !said.contains("stopped:"), "a stop was said that was not tried: {said}");
    }

    /// **An unreadable status stops nothing**: the node cannot say whether
    /// 701 runs, so it is not stopped, the failure is said with the node's
    /// own words, and the run exits non-zero.
    #[tokio::test]
    async fn an_unreadable_status_stops_nothing() {
        let mock = proxmox((500, serde_json::Value::Null)).await;
        let h = host(Some(&expired_body(60)), Duration::from_secs(120));
        let v = pass(&Ok(mock.client()), &h.file, &h.log, SystemTime::now(), true).await;
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
        assert_eq!(pass(&Ok(mock.client()), &absent.file, &absent.log, SystemTime::now(), true).await, Verdict::NoFile);
        assert!(!lease::lock_file(&absent.file).exists(), "a lock was made where nothing is leased");
        for body in ["", "  \n", "{\"leases\": []}"] {
            let h = host(Some(body), Duration::from_secs(120));
            let v = pass(&Ok(mock.client()), &h.file, &h.log, SystemTime::now(), true).await;
            assert_eq!(v, Verdict::NothingLeased, "{body:?}");
            assert_eq!(own_log(&h), "");
        }
        assert!(!asked_anything(&mock));
    }

    /// **A hypervisor client that cannot be built is said only when there
    /// is something to stop**, not every minute on a host with no lease.
    #[tokio::test]
    async fn a_client_that_cannot_be_built_is_said_only_when_a_stop_is_due() {
        let broken: anyhow::Result<Client> = Err(anyhow::anyhow!("no tlsFingerprintSha256 configured"));
        let idle = host(Some("{\"leases\": []}"), Duration::from_secs(120));
        assert_eq!(pass(&broken, &idle.file, &idle.log, SystemTime::now(), true).await, Verdict::NothingLeased);
        assert_eq!(own_log(&idle), "", "a client nothing needed was complained of");
        let due = host(Some(&expired_body(60)), Duration::from_secs(120));
        let v = pass(&broken, &due.file, &due.log, SystemTime::now(), true).await;
        assert!(matches!(v, Verdict::Refused(_)), "{}", v.describe());
        assert!(own_log(&due).contains("no tlsFingerprintSha256 configured; nothing stopped"), "{}", own_log(&due));
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
            let v = pass(&Ok(mock.client()), &h.file, &h.log, SystemTime::now(), true).await;
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
        assert_eq!(pass(&Ok(mock.client()), &h.file, &h.log, SystemTime::now(), true).await, Verdict::NoneDue { leases: 1 });
        let h = host(Some(&expired_body(60)), Duration::from_secs(120));
        let v = pass(&Ok(mock.client()), &h.file, &h.log, SystemTime::now(), false).await;
        assert_eq!(v, Verdict::WouldStop(vec![ID.to_string()]));
        assert!(!asked_anything(&mock));
    }

    /// **The period the bound is derived from is the unit's**, and the unit
    /// runs this binary, with its token and nothing else (A3).
    #[test]
    fn the_timer_unit_runs_this_binary_every_minute_to_the_second() {
        let timer = include_str!("../../../packaging/deb/lib/systemd/system/onv-lease-expire.timer");
        let lines: Vec<&str> = timer.lines().map(str::trim).collect();
        assert!(lines.contains(&"OnCalendar=minutely"), "the timer's period is not the one STALE_AFTER assumes");
        assert!(lines.contains(&"AccuracySec=1s"), "systemd's default accuracy (1 min) would double the period");
        assert_eq!(EVERY, Duration::from_secs(60));
        let service = include_str!("../../../packaging/deb/lib/systemd/system/onv-lease-expire.service");
        assert!(
            service.lines().any(|l| l == "ExecStart=/usr/bin/onv-lease-expire --config /etc/onv/agent.yaml"),
            "the service does not run the host timer's binary"
        );
        let load = format!("LoadCredential={CREDENTIAL}:{CREDENTIAL_SOURCE}");
        assert!(service.lines().any(|l| l == load), "the service does not load the timer's token as {CREDENTIAL}");
    }

    /// A credentials directory as systemd makes one, holding `body` as the
    /// timer's credential (or nothing).
    fn credentials(body: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        if let Some(body) = body {
            std::fs::write(dir.path().join(CREDENTIAL), body).unwrap();
        }
        dir
    }

    const LEASE_TOKEN: &str = "proxmoxTokenId: onv@pve!lease\nproxmoxTokenSecret: SEKRET-LEASE\n";

    /// agent.yaml as the timer reads it, beside `h`'s lease file: the
    /// stand-in's address and nothing of Core. The agent itself refuses this
    /// file (no core section, no token id, a timing it does not know), which
    /// is the point: the timer reads only its own keys.
    fn config_for(h: &Host, mock: &Mock) -> PathBuf {
        let snippets = h.file.parent().unwrap().join("snippets");
        let path = h.file.parent().unwrap().join("agent.yaml");
        let body = format!(
            "proxmox:\n  apiUrl: {}\n  tlsFingerprintSha256: \"{}\"\n  snippetDir: {}\ntimings:\n  noSuchTiming: 1\n",
            mock.base,
            "AB".repeat(32),
            snippets.display()
        );
        std::fs::write(&path, body).unwrap();
        path
    }

    fn invocation(config: &Path, creds: Option<&Path>, h: &Host, probe: bool) -> Invocation {
        Invocation {
            config: config.display().to_string(),
            dry_run: false,
            probe,
            credentials: creds.map(Path::to_path_buf),
            log: Log::new(h.own.clone(), None),
        }
    }

    /// **The timer refuses to start without its token** (A3's acceptance): a
    /// machine past its lease, a dead agent, and no credential, or a
    /// credentials directory without the timer's. Nothing is asked of
    /// Proxmox, nothing is stopped, the refusal is said in the timer's own
    /// file naming where the token comes from, and the run exits 1.
    #[tokio::test]
    async fn the_timer_refuses_to_start_without_its_token() {
        let mock = proxmox(running()).await;
        let h = host(Some(&expired_body(60)), Duration::from_secs(120));
        let config = config_for(&h, &mock);
        let empty = credentials(None);
        for creds in [None, Some(empty.path())] {
            let code = run(&invocation(&config, creds, &h, false)).await;
            assert_eq!(code, 1, "{creds:?}: a run without its token did not refuse");
        }
        assert!(!asked_anything(&mock), "Proxmox was asked without the timer's token");
        let said = own_log(&h);
        assert_eq!(said.matches("lease refused: no credential").count(), 2, "{said}");
        assert!(said.contains(&format!("LoadCredential={CREDENTIAL}:{CREDENTIAL_SOURCE}")), "{said}");
        // The same files, with the token: the machine is stopped. So the
        // refusal above was the token's absence and nothing else.
        let token = credentials(Some(LEASE_TOKEN));
        assert_eq!(run(&invocation(&config, Some(token.path()), &h, false)).await, 0, "{}", own_log(&h));
        assert_eq!(stops(&mock), ["/nodes/n1/qemu/701/status/stop"]);
    }

    /// **It stops with its own token, and asks with nothing else**: every
    /// call carries `onv@pve!lease`, never the agent's token, and the
    /// configuration it read is one the agent itself refuses.
    #[tokio::test]
    async fn with_its_token_it_stops_with_that_token_alone() {
        let mock = proxmox(running()).await;
        let h = host(Some(&expired_body(60)), Duration::from_secs(120));
        let config = config_for(&h, &mock);
        let token = credentials(Some(LEASE_TOKEN));
        assert_eq!(run(&invocation(&config, Some(token.path()), &h, false)).await, 0, "{}", own_log(&h));
        assert_eq!(stops(&mock), ["/nodes/n1/qemu/701/status/stop"]);
        let auths: std::collections::BTreeSet<String> = mock.calls.lock().unwrap().iter().map(|c| c.auth.clone()).collect();
        assert_eq!(auths.into_iter().collect::<Vec<_>>(), ["PVEAPIToken=onv@pve!lease=SEKRET-LEASE"]);
    }

    /// **A credential that is not the timer's own is refused**, before
    /// anything is asked: one naming Core's token, one naming the agent's
    /// Proxmox token, one with a part missing or empty or not a string. No
    /// refusal quotes a secret.
    #[tokio::test]
    async fn a_credential_that_is_not_the_timers_own_is_refused() {
        let mock = proxmox(running()).await;
        let h = host(Some(&expired_body(60)), Duration::from_secs(120));
        let config = config_for(&h, &mock);
        for (body, why) in [
            ("proxmoxTokenId: onv@pve!lease\nproxmoxTokenSecret: SEKRET-A\ncoreToken: SEKRET-B\n", "`coreToken` is not a credential"),
            ("proxmoxTokenId: onv@pve!agent\nproxmoxTokenSecret: SEKRET-A\n", "never with the agent's"),
            ("proxmoxTokenId: lease\nproxmoxTokenSecret: SEKRET-A\n", "not a `<user>@<realm>!lease` token"),
            ("proxmoxTokenSecret: SEKRET-A\n", "proxmoxTokenId missing"),
            ("proxmoxTokenId: onv@pve!lease\n", "proxmoxTokenSecret missing"),
            ("proxmoxTokenId: onv@pve!lease\nproxmoxTokenSecret: ''\n", "proxmoxTokenSecret is empty"),
            ("proxmoxTokenId: onv@pve!lease\nproxmoxTokenSecret: [SEKRET-A]\n", "proxmoxTokenSecret must be a string"),
            ("proxmoxTokenSecret: \"SEKRET-A\n", "not a map of names to values"),
        ] {
            let creds = credentials(Some(body));
            let why_said = read_token(Some(creds.path())).err().unwrap_or_default();
            assert!(why_said.contains(why), "{body:?}: said {why_said:?}");
            assert!(!why_said.contains("SEKRET"), "{body:?}: a secret was quoted: {why_said}");
            assert_eq!(run(&invocation(&config, Some(creds.path()), &h, false)).await, 1, "{body:?}");
        }
        assert!(!asked_anything(&mock), "Proxmox was asked with a credential that is not the timer's");
        assert!(!own_log(&h).contains("SEKRET"), "a secret reached the log");
    }

    /// The token's own permissions, as `/access/permissions` answers them.
    async fn permissions(held: serde_json::Value) -> Mock {
        Mock::start(move |method, path| match (method, path) {
            ("GET", "/access/permissions") => (200, held.clone()),
            _ => (404, serde_json::Value::Null),
        })
        .await
    }

    /// **`--probe` passes the token that holds what it should, and fails one
    /// that holds more or less**: the play's proof that the token it minted
    /// works and is the narrow one.
    #[tokio::test]
    async fn the_probe_passes_only_the_narrow_token() {
        let h = host(None, Duration::ZERO);
        let token = credentials(Some(LEASE_TOKEN));
        let right = serde_json::json!({
            "/pool/onv-buyers": {"VM.Audit": 1, "VM.PowerMgmt": 1},
            "/vms/701": {"VM.Audit": 1, "VM.PowerMgmt": 1},
        });
        let mock = permissions(right).await;
        let config = config_for(&h, &mock);
        assert_eq!(run(&invocation(&config, Some(token.path()), &h, true)).await, 0, "{}", own_log(&h));
        assert!(mock.calls.lock().unwrap().iter().all(|c| c.auth == "PVEAPIToken=onv@pve!lease=SEKRET-LEASE"));
        for (held, why) in [
            (
                serde_json::json!({"/pool/onv-buyers": {"VM.Audit": 1, "VM.PowerMgmt": 1}, "/": {"Sys.Audit": 1}}),
                "Sys.Audit on /",
            ),
            (
                serde_json::json!({"/pool/onv-buyers": {"VM.Audit": 1, "VM.PowerMgmt": 1, "VM.Allocate": 1}}),
                "VM.Allocate on /pool/onv-buyers",
            ),
            (serde_json::json!({"/pool/onv-buyers": {"VM.Audit": 1}}), "lacks VM.PowerMgmt on /pool/onv-buyers"),
            (serde_json::json!({"/pool/onv": {"VM.Audit": 1, "VM.PowerMgmt": 1}}), "lacks VM.Audit and VM.PowerMgmt"),
        ] {
            let mock = permissions(held.clone()).await;
            let config = config_for(&h, &mock);
            assert_eq!(run(&invocation(&config, Some(token.path()), &h, true)).await, 1, "{held} passed");
            assert!(own_log(&h).contains(why), "{held}: {}", own_log(&h));
        }
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
