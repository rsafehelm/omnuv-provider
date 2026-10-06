//! **The held view, persisted** (omnuv's modular design, A6).
//!
//! The view this agent maintains from while Core is unreachable was held in
//! memory only, so a restart during an outage (a host reboot is one) left
//! every buyer machine stopped until Core answered the handshake and a view
//! again. It is rebuildable state, like `run-lease.json` and
//! `restore-head.json`: Core's answer, kept so it can be asked again, never
//! a second orchestration store.
//!
//! ```text
//! written   every pass that resolved a view this agent may act on (a full
//!           answer, or `unchanged` against the copy in hand): its machines'
//!           ids and intents, the Core it came from, and when it was asked for
//! read      only at start, before any Core has answered, and only after a
//!           handshake found Core unreachable (no answer, 5xx or 429)
//! acts      starts only, through `Client::maintain`: a machine whose intent
//!           is Running, which exists, and which its node calls stopped.
//!           Nothing is created, stopped or destroyed
//! gated     the run-lease file read whole (missing or refused: nothing,
//!           and the view is retired in that start, `retire`, so a later
//!           start cannot read the lease task's rewrite as a whole book),
//!           no expired lease (`lease::may_restart`), the restore bit kept
//!           in the head (`restore::held_at_boot`), the same Core url, and a
//!           view no older than `timings.heldViewMaxAge` (15 min)
//! ends      the moment the handshake succeeds: a pass in flight finishes,
//!           and from then the reconcile loop decides, as before
//! ```
//!
//! Ids and intents only: what `maintain` needs, and nothing a buyer would not
//! want kept on the host's disk (no keys, no user data).

use omnuv_protocol::{DesiredState, InstanceSpec, Lifecycle};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// How far ahead of this host's clock a view may say it was asked for and
/// still be read: a clock stepped back by NTP at boot by up to this much. A
/// view further in the future has no age this agent can know.
pub const FUTURE_SKEW: Duration = Duration::from_secs(60);

/// What the file holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Persisted {
    /// The Core the view came from: a view from another Core is not this one's.
    pub core_url: String,
    /// The view's revision, for whoever reads the file.
    pub version: u64,
    /// When the view was asked for, seconds since the epoch: a view Core
    /// answered `unchanged` is as fresh as that answer.
    pub asked_unix: u64,
    pub instances: Vec<Held>,
}

/// One machine of the view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Held {
    pub id: String,
    pub intent: Lifecycle,
}

/// Where the file goes: beside the run lease and the restore head.
pub fn file(snippet_dir: &str) -> PathBuf {
    Path::new(snippet_dir).parent().unwrap_or(Path::new("/var/lib/onv")).join("held-view.json")
}

fn unix(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The view as the file keeps it.
pub fn of(core_url: &str, view: &DesiredState, asked: SystemTime) -> Persisted {
    Persisted {
        core_url: core_url.to_string(),
        version: view.version,
        asked_unix: unix(asked),
        instances: view.instances.iter().map(|s| Held { id: s.id.clone(), intent: s.intent }).collect(),
    }
}

/// Written whole or not at all (tmp and rename), readable by this agent's
/// user alone. A failure is said; the pass goes on, and the next one writes.
pub fn write(file: &Path, held: &Persisted) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let tmp = file.with_extension("json.tmp");
    let written = serde_json::to_vec(held).map_err(std::io::Error::other).and_then(|body| {
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
        std::fs::rename(&tmp, file)
    });
    if let Err(e) = written {
        eprintln!("held view: {} not written: {e:#}", file.display());
    }
}

/// Where a retired view goes: kept for whoever reads the host, never read.
pub fn retired(file: &Path) -> PathBuf {
    file.with_extension("json.refused")
}

/// **A start whose run-lease file was not resumed takes the held view out of
/// use** (`lease::spawn`'s `on_unread`). That start's own passes refuse on the
/// lease result; this is for the next start in the same outage, which would
/// read the file the lease task wrote from an empty book, find nothing run
/// out, and start machines whose leases in the lost file had. The view comes
/// back when Core answers and a pass writes a fresh one.
///
/// Renamed aside, or removed when it cannot be; when neither works it is said,
/// and a later start may still read it.
pub fn retire(file: &Path, why: &crate::lease::Unread) {
    match std::fs::rename(file, retired(file)) {
        Ok(()) => eprintln!("held view: {why}, so {} is retired until Core answers", file.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => match std::fs::remove_file(file) {
            Ok(()) => eprintln!("held view: {why}, so {} is removed (not renamed: {e:#})", file.display()),
            Err(e2) if e2.kind() == std::io::ErrorKind::NotFound => {}
            Err(e2) => eprintln!(
                "held view: {why}, and {} could be neither renamed ({e:#}) nor removed ({e2:#}); a later start may maintain from it",
                file.display()
            ),
        },
    }
}

/// **The lease task, as `agent::run` starts it**: [`lease::spawn`] with the
/// held view retired when the run-lease file is not resumed, before the
/// task's first write.
///
/// [`lease::spawn`]: crate::lease::spawn
pub fn spawn_leases(
    book: crate::lease::Shared,
    driver: Arc<crate::proxmox::Client>,
    lease_file: PathBuf,
    held_view: &Path,
) -> Result<usize, crate::lease::Unread> {
    crate::lease::spawn(book, driver, lease_file, |why| retire(held_view, why))
}

/// **The file, if it may be maintained from now**: there, read whole, from
/// this Core, and asked for no more than `max_age` ago. Every refusal says why.
pub fn read(file: &Path, core_url: &str, max_age: Duration, now: SystemTime) -> Result<Persisted, String> {
    let body = std::fs::read(file).map_err(|e| format!("{} not read: {e}", file.display()))?;
    let held: Persisted = serde_json::from_slice(&body).map_err(|e| format!("{} refused: {e}", file.display()))?;
    if held.core_url != core_url {
        return Err(format!("the held view is {}'s, and this agent's Core is {core_url}", held.core_url));
    }
    let asked = SystemTime::UNIX_EPOCH + Duration::from_secs(held.asked_unix);
    match now.duration_since(asked) {
        Ok(age) if age > max_age => Err(format!(
            "the held view was asked for {}s ago, past heldViewMaxAge ({}s)",
            age.as_secs(),
            max_age.as_secs()
        )),
        Ok(_) => Ok(held),
        Err(ahead) if ahead.duration() <= FUTURE_SKEW => Ok(held),
        Err(ahead) => Err(format!(
            "the held view says it was asked for {}s from now; its age cannot be known",
            ahead.duration().as_secs()
        )),
    }
}

/// The machines a boot pass may start: intent Running, and no lease of its
/// run out.
pub fn to_start(held: &Persisted, lease: &crate::lease::Shared, now: Instant) -> Vec<InstanceSpec> {
    held.instances
        .iter()
        .filter(|h| h.intent == Lifecycle::Running)
        .filter(|h| crate::lease::may_restart(lease, &h.id, now))
        .map(|h| InstanceSpec { id: h.id.clone(), intent: Lifecycle::Running, ..Default::default() })
        .collect()
}

/// What decides a boot pass, apart from the file itself.
pub struct Gates {
    pub file: PathBuf,
    pub core_url: String,
    pub max_age: Duration,
    /// What the lease task found when it resumed the file
    /// (`lease::spawn`): read before its first write, which keeps only what
    /// was resumed.
    pub leases: Result<usize, crate::lease::Unread>,
    pub lease: crate::lease::Shared,
    pub restore: crate::restore::Shared,
}

/// What one boot pass did.
#[derive(Debug, PartialEq, Eq)]
pub enum Pass {
    /// Nothing was looked at, and why.
    Refused(String),
    /// This many machines were started.
    Started(usize),
}

/// **One boot pass**: every gate, then starts only.
pub async fn pass(gates: &Gates, driver: &crate::proxmox::Client) -> Pass {
    if gates.max_age.is_zero() {
        return Pass::Refused("heldViewMaxAge is 0s: the boot-time maintain path is off".into());
    }
    if let Err(e) = &gates.leases {
        return Pass::Refused(format!("{e}: which machines ran under a lease cannot be known"));
    }
    if let Some(evidence) = crate::restore::held_at_boot(&gates.restore) {
        return Pass::Refused(format!("this agent is in a restore ({evidence})"));
    }
    let held = match read(&gates.file, &gates.core_url, gates.max_age, SystemTime::now()) {
        Ok(h) => h,
        Err(e) => return Pass::Refused(e),
    };
    let specs = to_start(&held, &gates.lease, Instant::now());
    if specs.is_empty() {
        return Pass::Started(0);
    }
    match driver.maintain(&specs).await {
        Ok(n) => Pass::Started(n),
        Err(e) => Pass::Refused(format!("maintenance failed: {e:#}")),
    }
}

/// The boot task: a pass each time a handshake finds Core unreachable,
/// until it is told the handshake succeeded.
pub struct Boot {
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

/// Starts the boot task. `unreachable` moves each time a handshake finds
/// Core unreachable; passes coalesce, so a pass that outlasts several
/// attempts is followed by one more, never by a queue.
pub fn spawn(gates: Gates, driver: Arc<crate::proxmox::Client>, mut unreachable: tokio::sync::watch::Receiver<u64>) -> Boot {
    let (stop, mut stopped) = tokio::sync::watch::channel(false);
    let task = onv_core_link::supervise::spawn("held view at boot", async move {
        loop {
            tokio::select! {
                _ = stopped.changed() => return,
                moved = unreachable.changed() => if moved.is_err() { return },
            }
            if *stopped.borrow() {
                return;
            }
            match pass(&gates, &driver).await {
                Pass::Started(0) => {}
                Pass::Started(n) => println!(
                    "core unreachable at start; maintained {n} machine(s) from the held view, decided nothing"
                ),
                Pass::Refused(why) => eprintln!("core unreachable at start; nothing maintained from the held view: {why}"),
            }
        }
    });
    Boot { stop, task }
}

impl Boot {
    /// The handshake succeeded: the reconcile loop decides from here. A pass
    /// in flight finishes first, so no start of it races the first pass.
    pub async fn finish(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const CORE: &str = "https://api.test.omnuv.com";

    fn persisted(asked: SystemTime, instances: &[(&str, Lifecycle)]) -> Persisted {
        Persisted {
            core_url: CORE.into(),
            version: 7,
            asked_unix: unix(asked),
            instances: instances.iter().map(|(id, intent)| Held { id: id.to_string(), intent: *intent }).collect(),
        }
    }

    /// **The file reads back what was written, and is the agent's alone.**
    #[test]
    fn the_file_reads_back_what_was_written() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("held-view.json");
        let p = persisted(SystemTime::now(), &[("m1", Lifecycle::Running), ("m2", Lifecycle::Absent)]);
        write(&f, &p);
        assert_eq!(read(&f, CORE, Duration::from_secs(900), SystemTime::now()), Ok(p));
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!f.with_extension("json.tmp").exists(), "the temporary file was left");
    }

    /// **The age, both ways**: within the bound it is read, one second past
    /// it nothing is; a view from the future beyond the skew has no age.
    #[test]
    fn a_view_past_its_age_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("held-view.json");
        // A whole second: the file keeps seconds.
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(unix(SystemTime::now()));
        let max = Duration::from_secs(900);
        write(&f, &persisted(now - max, &[("m1", Lifecycle::Running)]));
        assert!(read(&f, CORE, max, now).is_ok(), "a view exactly at its age was refused");
        write(&f, &persisted(now - max - Duration::from_secs(1), &[("m1", Lifecycle::Running)]));
        let e = read(&f, CORE, max, now).expect_err("a view past its age was read");
        assert!(e.contains("past heldViewMaxAge"), "{e}");
        write(&f, &persisted(now + FUTURE_SKEW, &[]));
        assert!(read(&f, CORE, max, now).is_ok(), "a clock stepped back within the skew refused the view");
        write(&f, &persisted(now + FUTURE_SKEW + Duration::from_secs(5), &[]));
        assert!(read(&f, CORE, max, now).is_err(), "a view from the future was read");
    }

    /// **Another Core's view, an unreadable file, none at all: nothing.**
    #[test]
    fn a_view_not_this_core_s_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("held-view.json");
        let max = Duration::from_secs(900);
        assert!(read(&f, CORE, max, SystemTime::now()).is_err(), "no file was read as a view");
        write(&f, &persisted(SystemTime::now(), &[("m1", Lifecycle::Running)]));
        assert!(read(&f, "https://api.omnuv.com", max, SystemTime::now()).is_err(), "another Core's view was read");
        std::fs::write(&f, b"{\"core_url\":").unwrap();
        assert!(read(&f, CORE, max, SystemTime::now()).is_err(), "a torn file was read");
    }

    /// A hypervisor holding one stopped guest per id, each carrying its claim
    /// and its stamp, that starts anything it is asked to.
    async fn hypervisor(ids: &[&str]) -> crate::pvemock::Mock {
        use crate::names::{TAG_INSTANCE as TAG, description, short_tag};
        let guests: Vec<(u32, String, String)> = ids
            .iter()
            .enumerate()
            .map(|(n, id)| (900 + n as u32, short_tag(id), description(TAG, id)))
            .collect();
        crate::pvemock::Mock::start(move |method, path, _| {
            if let Some(r) = crate::pvemock::task_ok(path) {
                return r;
            }
            if (method, path) == ("GET", "/cluster/resources?type=vm") {
                let list: Vec<_> = guests
                    .iter()
                    .map(|(vmid, tag, _)| serde_json::json!({"node": "n1", "vmid": vmid, "status": "stopped", "tags": format!("{TAG};{tag}")}))
                    .collect();
                return (200, serde_json::Value::Array(list));
            }
            for (vmid, _, stamp) in &guests {
                if path == format!("/nodes/n1/qemu/{vmid}/status/current") {
                    return (200, serde_json::json!({"status": "stopped"}));
                }
                if method == "GET" && path == format!("/nodes/n1/qemu/{vmid}/config") {
                    return (200, serde_json::json!({"description": stamp}));
                }
                if method == "POST" && path == format!("/nodes/n1/qemu/{vmid}/status/start") {
                    return (200, serde_json::json!(format!("UPID:n1:start:{vmid}")));
                }
            }
            crate::pvemock::gate_clear(method, path).unwrap_or((404, serde_json::Value::Null))
        })
        .await
    }

    /// Every call that changed something on the hypervisor.
    fn acts(mock: &crate::pvemock::Mock) -> Vec<String> {
        mock.calls.lock().unwrap().iter().filter(|c| c.method != "GET").map(|c| format!("{} {}", c.method, c.path)).collect()
    }

    const LEASED: &str = "11111111-1111-4111-8111-111111111111";
    const EXPIRED: &str = "22222222-2222-4222-8222-222222222222";
    const FREE: &str = "33333333-3333-4333-8333-333333333333";
    const OFF: &str = "44444444-4444-4444-8444-444444444444";
    const GONE: &str = "55555555-5555-4555-8555-555555555555";

    /// A host as a restarted agent finds it: a run-lease file (one lease
    /// running, one run out), a restore head, and a held view `age` old
    /// naming five machines, every one of them stopped on the hypervisor.
    struct Host {
        dir: tempfile::TempDir,
        mock: crate::pvemock::Mock,
    }

    impl Host {
        async fn new(age: Duration) -> Host {
            let dir = tempfile::tempdir().unwrap();
            let now = unix(SystemTime::now());
            std::fs::write(
                dir.path().join("run-lease.json"),
                serde_json::json!({"leases": [{"id": LEASED, "until_unix": now + 600}, {"id": EXPIRED, "until_unix": now - 10}]})
                    .to_string(),
            )
            .unwrap();
            write(
                &dir.path().join("held-view.json"),
                &persisted(
                    SystemTime::now() - age,
                    &[
                        (EXPIRED, Lifecycle::Running),
                        (OFF, Lifecycle::Stopped),
                        (GONE, Lifecycle::Absent),
                        (LEASED, Lifecycle::Running),
                        (FREE, Lifecycle::Running),
                    ],
                ),
            );
            let mock = hypervisor(&[EXPIRED, OFF, GONE, LEASED, FREE]).await;
            Host { dir, mock }
        }

        /// The gates as `agent::run` builds them, from the files as they are now.
        fn gates(&self) -> Gates {
            let lease: crate::lease::Shared = Default::default();
            let leases = crate::lease::resumed(&lease, &self.dir.path().join("run-lease.json"));
            Gates {
                file: self.dir.path().join("held-view.json"),
                core_url: CORE.into(),
                max_age: Duration::from_secs(900),
                leases,
                lease,
                restore: crate::restore::load(self.dir.path().join("restore-head.json")),
            }
        }

        fn vmid(id: &str) -> u32 {
            900 + [EXPIRED, OFF, GONE, LEASED, FREE].iter().position(|i| *i == id).unwrap() as u32
        }
    }

    /// **The acceptance, at the pass**: held guests within their lease are
    /// started, and nothing else is done: no stop, no delete, no create, and
    /// no start of a machine Stopped, Absent or past its lease.
    #[tokio::test]
    async fn held_guests_within_their_lease_are_started_and_nothing_else_is_done() {
        let host = Host::new(Duration::from_secs(60)).await;
        assert_eq!(pass(&host.gates(), &host.mock.client()).await, Pass::Started(2));
        let mut acts = acts(&host.mock);
        acts.sort();
        let mut want =
            vec![format!("POST /nodes/n1/qemu/{}/status/start", Host::vmid(LEASED)), format!("POST /nodes/n1/qemu/{}/status/start", Host::vmid(FREE))];
        want.sort();
        assert_eq!(acts, want, "the boot pass did something other than start the two held machines");
    }

    /// **A view older than its age starts nothing.**
    #[tokio::test]
    async fn a_view_older_than_its_age_starts_nothing() {
        let host = Host::new(Duration::from_secs(16 * 60)).await;
        let p = pass(&host.gates(), &host.mock.client()).await;
        assert!(matches!(&p, Pass::Refused(why) if why.contains("past heldViewMaxAge")), "{p:?}");
        assert_eq!(acts(&host.mock), Vec::<String>::new(), "a stale view started something");
    }

    /// **A set restore bit starts nothing**: the head this agent kept says it
    /// is in a restore, and no Core has answered since.
    #[tokio::test]
    async fn a_set_restore_bit_starts_nothing() {
        let host = Host::new(Duration::from_secs(60)).await;
        let head = crate::restore::Head {
            provider: "p-1".into(),
            revision: 9,
            mode: Some(crate::restore::Mode { evidence: "Core sent view revision 4, below revision 9".into(), core: None }),
            armed: Some(true),
        };
        std::fs::write(host.dir.path().join("restore-head.json"), serde_json::to_vec(&head).unwrap()).unwrap();
        let p = pass(&host.gates(), &host.mock.client()).await;
        assert!(matches!(&p, Pass::Refused(why) if why.contains("in a restore")), "{p:?}");
        assert_eq!(acts(&host.mock), Vec::<String>::new(), "an agent in a restore started something");
    }

    /// **No lease file, or one refused, starts nothing**: which machines ran
    /// under a lease is then unknown, and one of them may run elsewhere.
    #[tokio::test]
    async fn a_lease_file_missing_or_refused_starts_nothing() {
        for (body, why) in [(None, "no run-lease file"), (Some("{\"leases\": ["), "was refused")] {
            let host = Host::new(Duration::from_secs(60)).await;
            let lf = host.dir.path().join("run-lease.json");
            match body {
                None => std::fs::remove_file(&lf).unwrap(),
                Some(b) => std::fs::write(&lf, b).unwrap(),
            }
            let p = pass(&host.gates(), &host.mock.client()).await;
            assert!(matches!(&p, Pass::Refused(w) if w.contains(why)), "{why}: {p:?}");
            assert_eq!(acts(&host.mock), Vec::<String>::new(), "{why}: something was started");
        }
    }

    /// **A torn lease file holds for every start of the outage, not only the
    /// first.** Start one refuses on the lease result; its lease task then
    /// writes the file from an empty book, so start two resumes it whole
    /// (`Ok(0)`) and finds no lease run out. Start two must still start
    /// nothing: the view was retired in start one, before that write.
    #[tokio::test]
    async fn a_torn_lease_file_starts_nothing_on_the_next_start_either() {
        let host = Host::new(Duration::from_secs(60)).await;
        let lf = host.dir.path().join("run-lease.json");
        let hv = host.dir.path().join("held-view.json");
        std::fs::write(&lf, b"{\"leases\": [").unwrap();

        // Start one, as `agent::run` makes it (`spawn_leases`).
        let lease: crate::lease::Shared = Default::default();
        let leases = spawn_leases(lease.clone(), Arc::new(host.mock.client()), lf.clone(), &hv);
        assert!(matches!(leases, Err(crate::lease::Unread::Refused(_))), "{leases:?}");
        let first = Gates { leases, lease, ..host.gates() };
        let p = pass(&first, &host.mock.client()).await;
        assert!(matches!(&p, Pass::Refused(w) if w.contains("was refused")), "{p:?}");
        assert!(retired(&hv).exists(), "the view was not set aside");

        // The lease task's first write, polled for: bounded, it is immediate.
        let mut rewritten = false;
        for _ in 0..250 {
            if std::fs::read_to_string(&lf).is_ok_and(|b| crate::lease::read_body(&b).is_ok()) {
                rewritten = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(rewritten, "the lease task never rewrote the torn file");

        // Start two: the file now reads whole, and empty.
        let second = host.gates();
        assert_eq!(second.leases, Ok(0), "the premise: the rewrite reads as a whole, empty book");
        let p = pass(&second, &host.mock.client()).await;
        assert!(matches!(&p, Pass::Refused(_)), "{p:?}");
        assert_eq!(acts(&host.mock), Vec::<String>::new(), "the second start in the outage started something");
    }

    /// **Off is off**: heldViewMaxAge 0s.
    #[tokio::test]
    async fn a_zero_age_turns_the_path_off() {
        let host = Host::new(Duration::from_secs(0)).await;
        let gates = Gates { max_age: Duration::ZERO, ..host.gates() };
        assert!(matches!(pass(&gates, &host.mock.client()).await, Pass::Refused(_)));
        assert_eq!(acts(&host.mock), Vec::<String>::new());
    }

    /// **Only Running, and never past its lease.**
    #[test]
    fn only_running_machines_within_their_lease_are_started() {
        let lease: crate::lease::Shared = Arc::new(Mutex::new(crate::lease::Book::default()));
        let dir = tempfile::tempdir().unwrap();
        let lf = dir.path().join("run-lease.json");
        let past = unix(SystemTime::now()) - 10;
        let ahead = unix(SystemTime::now()) + 600;
        std::fs::write(
            &lf,
            serde_json::json!({"leases": [{"id": "expired", "until_unix": past}, {"id": "leased", "until_unix": ahead}]}).to_string(),
        )
        .unwrap();
        assert_eq!(crate::lease::resumed(&lease, &lf), Ok(2));
        let p = persisted(
            SystemTime::now(),
            &[
                ("leased", Lifecycle::Running),
                ("expired", Lifecycle::Running),
                ("free", Lifecycle::Running),
                ("off", Lifecycle::Stopped),
                ("gone", Lifecycle::Absent),
            ],
        );
        let ids: Vec<String> = to_start(&p, &lease, Instant::now()).into_iter().map(|s| s.id).collect();
        assert_eq!(ids, ["leased", "free"]);
    }
}
