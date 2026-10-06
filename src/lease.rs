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
//! ended     the machine proven gone here (its delete's proof: nothing
//!           carries its claim or its stamp), or stopped past its deadline
//!           and no longer named by Core's view: nothing is left to stop
//! ```
//!
//! **A lease ends with its machine** (27 September 2026). Until then nothing
//! ended one but a view naming the machine Running without listing it, which
//! a deleted machine never gets: on the mirror a machine deleted at 23:12 was
//! "stopped" by its lease at 23:27, fifteen minutes after its proof, "without
//! a view from Core" that no longer named it, and `run-lease.json` kept it for
//! good — so the host-timer proof's stop play, which asserts the file names
//! exactly the machine under test, refused the next run.
//!
//! **Core waits 2T + one pass + skew** after the supersede before it sends
//! the new copy anywhere: 2T covers this host's clock running at half speed,
//! the pass covers this task's period and the stop's own time.
//!
//! An agent that is dead stops nothing, so the file this task writes
//! (`run-lease.json`, each leased machine's wall-clock deadline) is read by
//! the **host timer** (`onv-lease-expire`, its own crate), which stops
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
// The file and its lock, shared with the host timer (A3).
pub use onv_agent_lib::run_lease::{file, lock_file, open_lock, read_body, WRITE_EVERY};
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
    // **Stopped past its deadline, and no longer named: done.** Core names a
    // superseded attempt Absent until its provider proves it gone, so a view
    // that does not name it at all has nothing more to ask of this host; and
    // the stop, the one thing the lease was for, has been made. A lease not
    // yet past its deadline, or whose stop failed, is kept whatever the view
    // says: that is the partition the lease exists for.
    b.leases.retain(|id, l| !(l.stopped && l.deadline <= r.asked.at && !view.instances.iter().any(|s| s.id == *id)));
}

/// **A machine proven gone here holds no lease**: its delete's proof found
/// nothing carrying its claim or its stamp, so there is nothing left to stop,
/// and a stop "without a view from Core" later would say something false.
pub fn forget(book: &Shared, id: &str) {
    crate::poison::lock(book, "run lease").leases.remove(id);
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

/// Why the file's leases were not resumed ([`resumed`]): what the boot-time
/// maintain path (omnuv's modular design, A6) is gated on. Read before the
/// lease task writes the file again, since that write keeps only what was
/// resumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unread {
    /// No file: an agent that never ran here, or one somebody removed.
    Missing,
    /// There, and not readable.
    Unreadable(String),
    /// Read, and refused whole (`read_body`).
    Refused(String),
}

impl std::fmt::Display for Unread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unread::Missing => write!(f, "no run-lease file"),
            Unread::Unreadable(e) => write!(f, "the run-lease file could not be read ({e})"),
            Unread::Refused(e) => write!(f, "the run-lease file was refused ({e})"),
        }
    }
}

/// **A restarted agent resumes its predecessor's leases**: each deadline in
/// the file, mapped from the wall clock onto this process's monotonic one (one
/// already past is past now), unless the book already holds a later one. An
/// expired lease resumed here is never restarted by maintenance and is stopped
/// by the first pass, as it would have been. Returns how many were resumed,
/// or why none were ([`Unread`]).
pub fn resumed(book: &Shared, file: &std::path::Path) -> Result<usize, Unread> {
    let body = match std::fs::read_to_string(file) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Unread::Missing),
        Err(e) => return Err(Unread::Unreadable(format!("{}: {e:#}", file.display()))),
    };
    let leases = read_body(&body).map_err(|e| Unread::Refused(format!("{}: {e}", file.display())))?;
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
    Ok(n)
}

/// What one stop of a leased machine did: the driver crate's since A3,
/// shared with the host timer.
pub(crate) use onv_driver_proxmox::leased::Stops;

impl Client {
    /// **A leased machine stopped**: `onv_driver_proxmox::leased::stop_leased`,
    /// the rule the host timer stops by too, over this client.
    pub(crate) async fn stop_leased(&self, id: &str, out: &mut Stops<'_>) -> anyhow::Result<()> {
        onv_driver_proxmox::leased::stop_leased(self, id, out).await
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

/// **The lease lock, held for as long as the task runs.** Waited for while
/// the host timer holds it (it is stopping machines; this task goes on after
/// it), and owned by the task, so a panic here frees it as surely as the
/// process ending does. `None` when it cannot be opened or locked: the task
/// runs anyway, and the timer's second test, a file written within
/// `onv_lease_expire::STALE_AFTER`, is what keeps it from acting meanwhile.
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
/// or releases them rather than racing their resumption. Returns what the
/// resumption found, which gates the boot-time maintain path (A6).
///
/// `on_unread` is told why nothing was resumed **before the task can write
/// the file**: that write keeps only what was resumed, so from it on the next
/// start reads an empty book as a whole one. What depends on the file having
/// been read (the held view, `heldview::retire`) is taken out of use there,
/// in this start, or never.
pub fn spawn(book: Shared, driver: Arc<Client>, file: std::path::PathBuf, on_unread: impl FnOnce(&Unread)) -> Result<usize, Unread> {
    let found = resumed(&book, &file);
    match &found {
        Ok(0) | Err(Unread::Missing) => {}
        Ok(n) => println!("run lease: {n} lease(s) resumed from {}", file.display()),
        Err(e) => eprintln!("run lease: {e:#}, so no lease is resumed"),
    }
    if let Err(why) = &found {
        on_unread(why);
    }
    // **The agent never runs without its lease task.** A panic there frees
    // the lock, and the host timer would then act beside a reconcile loop
    // still maintaining the same machines; so the process ends (70, as every
    // supervised task's panic does since A4), and systemd starts it again
    // with the file's leases resumed.
    onv_core_link::supervise::spawn("run lease", async move {
        let _held = take_lock(&file).await;
        let mut every = tokio::time::interval(WRITE_EVERY);
        loop {
            every.tick().await;
            check(&book, &driver, &file).await;
        }
    });
    found
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
            agent_settings: None,
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

    /// **A lease ends with its machine** (27 September 2026). Proven gone,
    /// it is forgotten at once. Stopped past its deadline and no longer named
    /// by the view, it ends too: the stale lease a restarted agent resumes
    /// for a machine the ledger has let go is dropped on its first view. And
    /// what it must not end: a lease still running, or whose stop failed,
    /// whatever the view says (the partition the lease is for), and one the
    /// view still names Absent (Core still asks for it).
    #[test]
    fn a_lease_ends_with_its_machine() {
        let b = book();
        let t0 = Asked::now();
        heard(&b, t0, Some("60 gone proven kept named".into()));
        renew(&b, &view(&[("gone", Lifecycle::Running), ("proven", Lifecycle::Running), ("kept", Lifecycle::Running), ("named", Lifecycle::Running)]));
        forget(&b, "proven");
        let past = t0.at + Duration::from_secs(61);
        assert_eq!(expired(&b, past), ["gone", "kept", "named"], "a machine proven gone kept its lease");
        // "gone" and "named" were stopped by the lease task; "kept"'s stop failed.
        stopped(&b, "gone");
        stopped(&b, "named");
        let later = Asked { at: past, wall: t0.wall + Duration::from_secs(61) };
        heard(&b, later, Some("60".into()));
        renew(&b, &view(&[("named", Lifecycle::Absent)]));
        let left: Vec<String> = read_body(&file_body(&b).to_string()).unwrap().into_iter().map(|l| l.id).collect();
        assert_eq!(left, ["kept", "named"], "a lease ended while it had work left, or outlived it");
        // Not yet past its deadline, and not named: kept (Core counts on it).
        let c = book();
        heard(&c, t0, Some("900 running".into()));
        renew(&c, &view(&[("running", Lifecycle::Running)]));
        heard(&c, Asked { at: t0.at + Duration::from_secs(10), wall: t0.wall }, Some("900".into()));
        renew(&c, &view(&[]));
        assert_eq!(expired(&c, t0.at + Duration::from_secs(900)), ["running"], "a lease still running was ended by a view");
    }

    /// **A stale lease resumed from the file ends on the first view**: the
    /// mirror's machine of 27 September, deleted and proven while the lease
    /// was held, resumed expired by a restarted agent, stopped (nothing
    /// carries its claim), and named by no view: dropped, and the file
    /// written without it.
    #[tokio::test]
    async fn a_stale_lease_resumed_from_the_file_ends_on_the_first_view() {
        let mock = crate::pvemock::Mock::start(|method, path, _| match (method, path) {
            ("GET", "/cluster/resources?type=vm") => (200, serde_json::json!([])),
            ("GET", "/nodes") => (200, serde_json::json!([{"node": "n1", "status": "online"}])),
            ("GET", "/nodes/n1/qemu") => (200, serde_json::json!([])),
            _ => (404, serde_json::Value::Null),
        })
        .await;
        let dir = tempfile::tempdir().expect("a directory");
        let file = dir.path().join("run-lease.json");
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        std::fs::write(&file, serde_json::json!({"leases": [{"id": "f35783b3", "until_unix": now - 600}]}).to_string()).unwrap();
        let b = book();
        assert_eq!(resumed(&b, &file), Ok(1));
        check(&b, &mock.client(), &file).await;
        assert_eq!(read_body(&std::fs::read_to_string(&file).unwrap()).unwrap().len(), 1, "stopped, and not yet told");
        heard(&b, Asked::now(), Some("900".into()));
        renew(&b, &view(&[]));
        check(&b, &mock.client(), &file).await;
        assert_eq!(read_body(&std::fs::read_to_string(&file).unwrap()), Ok(vec![]), "the stale lease outlived its machine");
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
        assert_eq!(resumed(&b, &file), Ok(2));
        let t = Instant::now();
        assert_eq!(expired(&b, t), ["gone"], "the expired lease was not resumed as expired");
        assert!(!may_restart(&b, "gone", t), "maintenance may restart a machine past its lease");
        assert!(may_restart(&b, "later", t));
        assert_eq!(expired(&b, t + Duration::from_secs(601)), ["gone", "later"]);
        assert_eq!(file_body(&b), body, "the file was not written back as it was read");
        // A file that does not read resumes nothing, and neither does none.
        std::fs::write(&file, "{\"leases\": [").unwrap();
        assert!(matches!(resumed(&book(), &file), Err(Unread::Refused(_))), "a torn file was resumed");
        assert_eq!(resumed(&book(), &dir.path().join("absent.json")), Err(Unread::Missing));
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
        let _ = spawn(book(), Arc::new(mock.client()), file.clone(), |_| {});
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
