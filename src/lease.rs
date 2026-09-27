//! **The run lease** (lifecycle phase 12, A9, TD14; omnuv's
//! `docs/plans/lifecycle-phase-12.md`).
//!
//! A buyer who chose "one copy on an honest provider" (D21) has their machine
//! restarted on another provider when this one falls silent. That is safe
//! only if this host stops its copy first, on its own clock, without Core:
//! a partition is exactly when Core cannot tell it to.
//!
//! ```text
//! told      each view answer to an agent that advertised run-lease carries
//!           onv-run-lease: "<T> <id> <id> …", the machines under lease
//! renewed   a good view names a listed machine Running: its deadline is
//!           asked_at + T, counted from when the view was *asked for*, so a
//!           slow answer shortens the lease and never lengthens it
//! kept      a view naming it Absent, or not naming it, leaves its deadline
//!           where it was: Core superseded it, and counts on it stopping
//! released  a view naming it Running and not listing it: Core no longer
//!           relies on the lease (the buyer's choice, or the switch, is off)
//! expired   past its deadline the machine is stopped (its claim tag and its
//!           whole stamp, its live status, status/stop), and maintenance
//!           never restarts it
//! ```
//!
//! **Core waits 2T + one pass + skew** after the supersede before it sends
//! the new copy anywhere: 2T covers this host's clock running at half speed,
//! the pass covers this task's period and the stop's own time.
//!
//! An agent that is dead stops nothing, so the file this task writes
//! (`run-lease.json`, each leased machine's wall-clock deadline) is read by
//! the **host timer** (`hosttimer.rs`, `onv-lease-expire.timer`), which stops
//! them when this task is not running. The two never act at once: this task
//! holds `run-lease.lock` for as long as it runs, and the timer acts only
//! when it can take that lock itself (the kernel frees it the moment this
//! process, or this task, is gone).
//!
//! **The file outlives the process.** A restarted agent resumes the leases
//! its predecessor wrote before it hears Core again, and this task starts
//! before the handshake, not after it: a restart during a partition is
//! exactly when Core cannot renew or release anything.

use crate::proxmox::Client;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

/// The capability this agent advertises in its handshake.
pub const CAPABILITY: &str = "run-lease";

/// The header Core names the lease in, on each view answer.
pub const HEADER: &str = "onv-run-lease";

/// When a view was asked for, on both clocks: the monotonic one the lease is
/// counted on, and the wall clock the host timer's file is written in.
#[derive(Debug, Clone, Copy)]
pub struct Asked {
    pub at: Instant,
    pub wall: SystemTime,
}

impl Asked {
    pub fn now() -> Self {
        Self { at: Instant::now(), wall: SystemTime::now() }
    }
}

#[derive(Debug, Clone)]
struct Reading {
    asked: Asked,
    header: Option<String>,
}

#[derive(Debug, Clone)]
struct Lease {
    deadline: Instant,
    wall: SystemTime,
    stopped: bool,
}

/// The leases this agent holds, and the last reading not yet applied.
#[derive(Debug, Default)]
pub struct Book {
    pending: Option<Reading>,
    leases: HashMap<String, Lease>,
}

pub type Shared = Arc<Mutex<Book>>;

/// `<T> <id> …` read strictly: T a positive number of seconds, then ids.
/// Anything else is no lease at all.
pub fn parse(header: &str) -> Option<(Duration, Vec<String>)> {
    let mut words = header.split(' ').filter(|w| !w.is_empty());
    let t: u64 = words.next()?.parse().ok()?;
    if t == 0 {
        return None;
    }
    Some((Duration::from_secs(t), words.map(str::to_string).collect()))
}

/// A view was answered: its header, and when it was asked for. Applied by
/// [`renew`] against the view the pass resolves (the answer may be
/// `unchanged`, and then the view is the copy in hand).
pub fn heard(book: &Shared, asked: Asked, header: Option<String>) {
    crate::poison::lock(book, "run lease").pending = Some(Reading { asked, header });
}

/// Applies the last reading to the view it answered.
pub fn renew(book: &Shared, view: &omnuv_protocol::DesiredState) {
    let mut b = crate::poison::lock(book, "run lease");
    if let Some(r) = b.pending.take() {
        apply(&mut b, &r, view);
    }
}

fn apply(b: &mut Book, r: &Reading, view: &omnuv_protocol::DesiredState) {
    let told = r.header.as_deref().and_then(parse);
    for spec in &view.instances {
        if spec.intent != omnuv_protocol::Lifecycle::Running {
            // Absent or Stopped: the deadline stays where it was.
            continue;
        }
        match &told {
            Some((t, ids)) if ids.contains(&spec.id) => {
                let deadline = r.asked.at + *t;
                // Never moved back by an older reading.
                let keep = b.leases.get(&spec.id).is_some_and(|l| l.deadline > deadline);
                if !keep {
                    b.leases.insert(spec.id.clone(), Lease { deadline, wall: r.asked.wall + *t, stopped: false });
                }
            }
            // Running and not leased: Core no longer relies on a lease here.
            _ => {
                b.leases.remove(&spec.id);
            }
        }
    }
}

/// The leased machines past their deadline and not yet stopped.
pub fn expired(book: &Shared, now: Instant) -> Vec<String> {
    let b = crate::poison::lock(book, "run lease");
    let mut out: Vec<String> =
        b.leases.iter().filter(|(_, l)| !l.stopped && l.deadline <= now).map(|(id, _)| id.clone()).collect();
    out.sort();
    out
}

/// Whether maintenance may start this machine again: never once its lease
/// ran out (A6: "never a restart-elsewhere attempt").
pub fn may_restart(book: &Shared, id: &str, now: Instant) -> bool {
    crate::poison::lock(book, "run lease").leases.get(id).is_none_or(|l| l.deadline > now)
}

fn stopped(book: &Shared, id: &str) {
    if let Some(l) = crate::poison::lock(book, "run lease").leases.get_mut(id) {
        l.stopped = true;
    }
}

/// What the host timer reads: each leased machine's wall-clock deadline, in
/// seconds since the epoch.
pub fn file_body(book: &Shared) -> serde_json::Value {
    let b = crate::poison::lock(book, "run lease");
    let mut leases: Vec<(&String, u64)> = b
        .leases
        .iter()
        .map(|(id, l)| (id, l.wall.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)))
        .collect();
    leases.sort();
    serde_json::json!({
        "leases": leases.into_iter().map(|(id, until)| serde_json::json!({ "id": id, "until_unix": until })).collect::<Vec<_>>()
    })
}

/// One lease as the file holds it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Written {
    pub id: String,
    pub until_unix: u64,
}

/// **The file read strictly**, by the agent at start and by the host timer:
/// empty (nothing written, or only whitespace) is no lease; otherwise it is
/// `{"leases": [{"id", "until_unix"}, …]}` with every id non-empty, or it is
/// refused whole and nothing in it is acted on.
pub fn read_body(body: &str) -> Result<Vec<Written>, String> {
    #[derive(serde::Deserialize)]
    struct File {
        leases: Vec<Written>,
    }
    if body.trim().is_empty() {
        return Ok(Vec::new());
    }
    let f: File = serde_json::from_str(body).map_err(|e| format!("not a run-lease file: {e}"))?;
    if let Some(n) = f.leases.iter().position(|l| l.id.trim().is_empty()) {
        return Err(format!("lease {n} names no machine"));
    }
    Ok(f.leases)
}

/// **A restarted agent resumes its predecessor's leases**: each deadline in
/// the file, mapped from the wall clock onto this process's monotonic one (one
/// already past is past now), unless the book already holds a later one. An
/// expired lease resumed here is never restarted by maintenance and is stopped
/// by the first pass, as it would have been. Returns how many were resumed.
pub fn resume(book: &Shared, file: &std::path::Path) -> usize {
    let body = match std::fs::read_to_string(file) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(e) => {
            eprintln!("run lease: {} could not be read, so no lease is resumed: {e:#}", file.display());
            return 0;
        }
    };
    let leases = match read_body(&body) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("run lease: {} refused, so no lease is resumed: {e:#}", file.display());
            return 0;
        }
    };
    let (now, wall) = (Instant::now(), SystemTime::now());
    let mut b = crate::poison::lock(book, "run lease");
    let mut n = 0;
    for l in leases {
        let until = SystemTime::UNIX_EPOCH + Duration::from_secs(l.until_unix);
        let deadline = now + until.duration_since(wall).unwrap_or(Duration::ZERO);
        if b.leases.get(&l.id).is_some_and(|held| held.deadline >= deadline) {
            continue;
        }
        b.leases.insert(l.id, Lease { deadline, wall: until, stopped: false });
        n += 1;
    }
    n
}

/// What one stop of a leased machine did, guest by guest, for whoever logs it.
#[derive(Default)]
pub(crate) struct Stops<'a> {
    /// `vm <vmid> on <node>`, stopped by this call.
    pub stopped: Vec<String>,
    /// Guests carrying the claim that were left, and why: another stamp.
    pub refused: Vec<String>,
    /// Told `vm <vmid> on <node>` just before its stop is sent, so a run
    /// that dies mid-stop has said what it was doing, and a machine already
    /// stopped says nothing at all.
    pub announce: Option<&'a (dyn Fn(&str) + Sync)>,
}

impl Client {
    /// **A leased machine stopped**: every guest carrying its claim tag and
    /// its whole stamp, stopped when its node says it is not. A guest with
    /// the tag and another stamp is left alone and said. What was done is in
    /// `out` even when a later guest fails; an error ends the call there, and
    /// the caller tries the whole machine again on its next pass.
    ///
    /// The power state is the node's live one (`status/current`), never the
    /// cluster listing's, which lags. Stop only: nothing here destroys.
    pub(crate) async fn stop_leased(&self, id: &str, out: &mut Stops<'_>) -> anyhow::Result<()> {
        let tag = crate::names::TAG_INSTANCE;
        for g in self.claimed_guests(tag, id).await? {
            let config: serde_json::Value =
                self.get_json(&format!("/nodes/{}/qemu/{}/config", g.node, g.vm.vmid)).await?;
            let first = config.get("description").and_then(|d| d.as_str()).and_then(|d| d.lines().next());
            if first != Some(crate::names::stamped(tag, id).as_str()) {
                out.refused.push(format!(
                    "vm {} on {} carries {id}'s tag but not its stamp (its first line reads {:?}); not stopped",
                    g.vm.vmid,
                    g.node,
                    first.unwrap_or("")
                ));
                continue;
            }
            if self.live_status(&g.node, g.vm.vmid).await? == "stopped" {
                continue;
            }
            if let Some(say) = out.announce {
                say(&format!("vm {} on {}", g.vm.vmid, g.node));
            }
            let upid: String = self
                .post_form(&format!("/nodes/{}/qemu/{}/status/stop", g.node, g.vm.vmid), &[] as &[(String, String)])
                .await?;
            self.wait_task(&g.node, &upid).await?;
            out.stopped.push(format!("vm {} on {}", g.vm.vmid, g.node));
        }
        Ok(())
    }
}

/// One look: every expired lease's machine stopped, and the file written.
pub async fn check(book: &Shared, driver: &Client, file: &std::path::Path) {
    for id in expired(book, Instant::now()) {
        let mut out = Stops::default();
        let result = driver.stop_leased(&id, &mut out).await;
        for r in &out.refused {
            crate::audit::record("instance.lease", "agent", &id, "refused", Some(r));
            eprintln!("run lease: {r}");
        }
        match result {
            Ok(()) => {
                stopped(book, &id);
                let n = out.stopped.len().to_string();
                crate::audit::record("instance.lease", "agent", &id, "stopped", Some(&n));
                println!("run lease: {id} ran past its lease without a view from Core; stopped ({n})");
            }
            Err(e) => eprintln!("run lease: {id} past its lease was not stopped: {e:#}"),
        }
    }
    let body = file_body(book).to_string();
    let tmp = file.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp, body).and_then(|_| std::fs::rename(&tmp, file)) {
        eprintln!("run lease: {} not written: {e:#}", file.display());
    }
}

/// How often the lease task looks, and so writes the file. The host timer's
/// staleness bound is derived from it (`hosttimer::STALE_AFTER`).
pub const WRITE_EVERY: Duration = Duration::from_secs(30);

/// The lock that says the lease task is running, beside the file.
pub fn lock_file(file: &std::path::Path) -> std::path::PathBuf {
    file.with_extension("lock")
}

/// Opens the lock file, creating it when it is not there, never truncating
/// anything. **Read-only when it exists**: `flock` needs no write access, so a
/// lock file another user made (a person running the timer by hand as root)
/// still locks, rather than leaving the agent's task to run without it.
pub fn open_lock(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    match std::fs::File::open(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(path)
        }
        opened => opened,
    }
}

/// **The lease lock, held for as long as the task runs.** Waited for while
/// the host timer holds it (it is stopping machines; this task goes on after
/// it), and owned by the task, so a panic here frees it as surely as the
/// process ending does. `None` when it cannot be opened or locked: the task
/// runs anyway, and the timer's second test, a file written within
/// `hosttimer::STALE_AFTER`, is what keeps it from acting meanwhile.
pub(crate) async fn take_lock(file: &std::path::Path) -> Option<std::fs::File> {
    let path = lock_file(file);
    let f = match open_lock(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("run lease: {} could not be opened ({e:#}); the lease task runs without it", path.display());
            return None;
        }
    };
    match f.try_lock() {
        Ok(()) => return Some(f),
        Err(std::fs::TryLockError::WouldBlock) => {
            println!("run lease: the host timer holds {}; waiting for its pass to end", path.display());
        }
        Err(std::fs::TryLockError::Error(e)) => {
            eprintln!("run lease: {} could not be locked ({e:#}); the lease task runs without it", path.display());
            return None;
        }
    }
    match tokio::task::spawn_blocking(move || f.lock().map(|()| f)).await {
        Ok(Ok(f)) => Some(f),
        Ok(Err(e)) => {
            eprintln!("run lease: {} could not be locked ({e:#}); the lease task runs without it", path.display());
            None
        }
        Err(e) => {
            eprintln!("run lease: waiting for {} failed ({e:#}); the lease task runs without it", path.display());
            None
        }
    }
}

/// The lease task: beside the reconcile loop, never inside it, because it
/// must run exactly when Core cannot be reached. Every [`WRITE_EVERY`]. The
/// file's leases are resumed before this returns, so the first view renews
/// or releases them rather than racing their resumption.
pub fn spawn(book: Shared, driver: Arc<Client>, file: std::path::PathBuf) {
    let n = resume(&book, &file);
    if n > 0 {
        println!("run lease: {n} lease(s) resumed from {}", file.display());
    }
    let task = tokio::spawn(async move {
        let _held = take_lock(&file).await;
        let mut every = tokio::time::interval(WRITE_EVERY);
        loop {
            every.tick().await;
            check(&book, &driver, &file).await;
        }
    });
    // **The agent never runs without its lease task.** A panic there frees
    // the lock, and the host timer would then act beside a reconcile loop
    // still maintaining the same machines; so the process ends, and systemd
    // starts it again with the file's leases resumed.
    tokio::spawn(async move {
        if let Err(e) = task.await
            && e.is_panic()
        {
            eprintln!("run lease: the lease task panicked; the agent exits rather than run without it");
            std::process::exit(70);
        }
    });
}

/// Where the file goes: beside the restore head.
pub fn file(snippet_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(snippet_dir).parent().unwrap_or(std::path::Path::new("/var/lib/onv")).join("run-lease.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnuv_protocol::{DesiredState, InstanceSpec, Lifecycle};

    fn view(specs: &[(&str, Lifecycle)]) -> DesiredState {
        DesiredState {
            protocol_version: omnuv_protocol::PROTOCOL_VERSION,
            version: 1,
            unchanged: false,
            inference_workers: vec![],
            instances: specs
                .iter()
                .map(|(id, intent)| InstanceSpec { id: id.to_string(), intent: *intent, ..Default::default() })
                .collect(),
            images: vec![],
            poll_interval_secs: None,
        }
    }

    fn book() -> Shared {
        Arc::new(Mutex::new(Book::default()))
    }

    /// **The lease counts from the ask, not the answer.** A view asked for
    /// at t0 and answered late leases to t0 + T, so Core's 2T bound, counted
    /// from its supersede, holds whatever the answer's delay.
    #[test]
    fn the_lease_counts_from_the_ask_not_the_answer() {
        let b = book();
        let asked = Asked::now();
        heard(&b, asked, Some("900 m1".into()));
        renew(&b, &view(&[("m1", Lifecycle::Running)]));
        assert!(expired(&b, asked.at + Duration::from_secs(899)).is_empty());
        assert_eq!(expired(&b, asked.at + Duration::from_secs(900)), ["m1"]);
    }

    /// **An Absent does not renew a lease.** Core superseded the machine and
    /// counts on its deadline; a view naming it Absent leaves it there.
    #[test]
    fn an_absent_does_not_renew_a_lease() {
        let b = book();
        let t0 = Asked::now();
        heard(&b, t0, Some("900 m1".into()));
        renew(&b, &view(&[("m1", Lifecycle::Running)]));
        let later = Asked { at: t0.at + Duration::from_secs(600), wall: t0.wall + Duration::from_secs(600) };
        heard(&b, later, Some("900".into()));
        renew(&b, &view(&[("m1", Lifecycle::Absent)]));
        assert_eq!(expired(&b, t0.at + Duration::from_secs(900)), ["m1"], "the Absent renewed the lease");
        // Nor a view that no longer names it.
        heard(&b, later, Some("900".into()));
        renew(&b, &view(&[]));
        assert_eq!(expired(&b, t0.at + Duration::from_secs(900)), ["m1"]);
    }

    /// **A machine not leased is never stopped** (D15: restarts only), and
    /// one Core stops leasing while it runs is released.
    #[test]
    fn a_machine_not_leased_is_never_stopped() {
        let b = book();
        let t0 = Asked::now();
        heard(&b, t0, Some("900 m1".into()));
        renew(&b, &view(&[("m1", Lifecycle::Running), ("m2", Lifecycle::Running)]));
        let far = t0.at + Duration::from_secs(100_000);
        assert_eq!(expired(&b, far), ["m1"], "m2 was leased without being told");
        heard(&b, t0, Some("900".into()));
        renew(&b, &view(&[("m1", Lifecycle::Running)]));
        assert!(expired(&b, far).is_empty(), "a lease Core no longer names was kept");
        assert!(may_restart(&b, "m2", far));
    }

    /// **Against a Core that sends no lease, nothing is leased**: an old
    /// Core, or the switch off. The agent restarts only, as before.
    #[test]
    fn against_a_core_that_sends_no_lease_nothing_is_leased() {
        let b = book();
        heard(&b, Asked::now(), None);
        renew(&b, &view(&[("m1", Lifecycle::Running)]));
        assert!(expired(&b, Instant::now() + Duration::from_secs(100_000)).is_empty());
        assert_eq!(file_body(&b), serde_json::json!({ "leases": [] }));
        for bad in ["", "0 m1", "soon m1", "-5 m1"] {
            assert_eq!(parse(bad), None, "{bad:?} read as a lease");
        }
        assert_eq!(parse("900 a b"), Some((Duration::from_secs(900), vec!["a".into(), "b".into()])));
    }

    /// **An expired lease is never restarted** by maintenance (A6).
    #[test]
    fn an_expired_lease_is_never_restarted() {
        let b = book();
        let t0 = Asked::now();
        heard(&b, t0, Some("60 m1".into()));
        renew(&b, &view(&[("m1", Lifecycle::Running)]));
        assert!(may_restart(&b, "m1", t0.at + Duration::from_secs(59)));
        assert!(!may_restart(&b, "m1", t0.at + Duration::from_secs(61)));
    }

    /// **A restarted agent resumes the leases its predecessor wrote**, before
    /// it hears Core: one already past is past now and never restarted, one
    /// still running keeps its deadline, and the file is written back as it
    /// was read rather than emptied. It started with an empty book until 27
    /// September 2026, and its first pass wrote `{"leases": []}` over the
    /// only record of what had to stop.
    #[test]
    fn a_restarted_agent_resumes_the_leases_in_its_file() {
        let dir = tempfile::tempdir().expect("a directory");
        let file = dir.path().join("run-lease.json");
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let body = serde_json::json!({"leases": [
            {"id": "gone", "until_unix": now - 60},
            {"id": "later", "until_unix": now + 600},
        ]});
        std::fs::write(&file, body.to_string()).unwrap();
        let b = book();
        assert_eq!(resume(&b, &file), 2);
        let t = Instant::now();
        assert_eq!(expired(&b, t), ["gone"], "the expired lease was not resumed as expired");
        assert!(!may_restart(&b, "gone", t), "maintenance may restart a machine past its lease");
        assert!(may_restart(&b, "later", t));
        assert_eq!(expired(&b, t + Duration::from_secs(601)), ["gone", "later"]);
        assert_eq!(file_body(&b), body, "the file was not written back as it was read");
        // A file that does not read resumes nothing, and neither does none.
        std::fs::write(&file, "{\"leases\": [").unwrap();
        assert_eq!(resume(&book(), &file), 0);
        assert_eq!(resume(&book(), &dir.path().join("absent.json")), 0);
    }

    /// **A lock file the agent cannot write to still locks**: one a person
    /// made by running the timer as root, say. It was opened read-write, so
    /// the task would have run without the lock and the timer beside it.
    #[tokio::test]
    async fn a_lock_file_the_agent_cannot_write_to_still_locks() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("a directory");
        let file = dir.path().join("run-lease.json");
        let lock = lock_file(&file);
        std::fs::write(&lock, "").unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o444)).unwrap();
        let held = take_lock(&file).await;
        assert!(held.is_some(), "a read-only lock file left the lease task without its lock");
        let probe = open_lock(&lock).unwrap();
        assert!(matches!(probe.try_lock(), Err(std::fs::TryLockError::WouldBlock)), "the lock was not held");
    }

    /// **The lease task holds the lock the host timer defers to**, from its
    /// start, and writes the file on its first pass.
    #[tokio::test]
    async fn the_lease_task_holds_the_lock_the_host_timer_defers_to() {
        let mock = crate::pvemock::Mock::start(|_, _, _| (404, serde_json::Value::Null)).await;
        let dir = tempfile::tempdir().expect("a directory");
        let file = dir.path().join("run-lease.json");
        spawn(book(), Arc::new(mock.client()), file.clone());
        let probe = open_lock(&lock_file(&file)).unwrap();
        let mut held = false;
        for _ in 0..250 {
            match probe.try_lock() {
                Err(std::fs::TryLockError::WouldBlock) => {
                    held = true;
                    break;
                }
                Ok(()) => probe.unlock().unwrap(),
                Err(std::fs::TryLockError::Error(e)) => panic!("the lock could not be tried: {e}"),
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(held, "the lease task did not take the lock within 5 s");
        for _ in 0..250 {
            if file.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(read_body(&std::fs::read_to_string(&file).unwrap()), Ok(vec![]));
    }

    /// **A leased machine is stopped once its view is older than T** — the
    /// one carrying its tag and whole stamp; a decoy with the tag and another
    /// stamp is not touched. Against the fake Proxmox.
    #[tokio::test]
    async fn a_leased_machine_is_stopped_once_its_view_is_older_than_t() {
        use crate::pvemock::{task_ok, Mock};
        let id = "0b1f7a2e-1111-4222-8333-944455556666";
        let tags = format!("onv-instance;{}", crate::names::short_tag(id));
        let stamp = crate::names::description(crate::names::TAG_INSTANCE, id);
        let mock = Mock::start(move |method, path, _| {
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
                ("GET", "/nodes/n1/qemu/702/config") => (200, serde_json::json!({"description": "somebody else's"})),
                ("GET", p) if p.ends_with("/status/current") => (200, serde_json::json!({"status": "running"})),
                ("POST", p) if p.ends_with("/status/stop") => (200, serde_json::json!("UPID:n1:stop")),
                _ => (404, serde_json::Value::Null),
            }
        })
        .await;
        let b = book();
        let past = Asked { at: Instant::now() - Duration::from_secs(1), wall: SystemTime::now() };
        heard(&b, past, Some(format!("1 {id}")));
        renew(&b, &view(&[(id, Lifecycle::Running)]));
        let dir = std::env::temp_dir().join(format!("onv-lease-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("run-lease.json");
        check(&b, &mock.client(), &file).await;
        let stops: Vec<String> = mock
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.method == "POST" && c.path.ends_with("/status/stop"))
            .map(|c| c.path.clone())
            .collect();
        assert_eq!(stops, ["/nodes/n1/qemu/701/status/stop"], "the wrong guests were stopped");
        assert!(expired(&b, Instant::now()).is_empty(), "a stopped lease is stopped again");
        assert!(!may_restart(&b, id, Instant::now()));
        let written: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(written["leases"][0]["id"], serde_json::json!(id));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
