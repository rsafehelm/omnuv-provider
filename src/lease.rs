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
//! An agent that is dead stops nothing. The file this task writes
//! (`run-lease.json`, each leased machine's wall-clock deadline) is for a
//! host timer that does; the timer is not built yet (the plan's "Not in this
//! phase"), so restart elsewhere must stay off where agents may die.

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

impl Client {
    /// **A leased machine stopped**: every guest carrying its claim tag and
    /// its whole stamp, stopped when its node says it is not. A guest with
    /// the tag and another stamp is left alone and said. Returns how many
    /// were stopped.
    pub(crate) async fn stop_leased(&self, id: &str) -> anyhow::Result<usize> {
        let tag = crate::names::TAG_INSTANCE;
        let mut n = 0;
        for g in self.claimed_guests(tag, id).await? {
            let config: serde_json::Value =
                self.get_json(&format!("/nodes/{}/qemu/{}/config", g.node, g.vm.vmid)).await?;
            let first = config.get("description").and_then(|d| d.as_str()).and_then(|d| d.lines().next());
            if first != Some(crate::names::stamped(tag, id).as_str()) {
                eprintln!("run lease: vm {} on {} carries {id}'s tag but not its stamp; not stopped", g.vm.vmid, g.node);
                continue;
            }
            if self.live_status(&g.node, g.vm.vmid).await? == "stopped" {
                continue;
            }
            let upid: String = self
                .post_form(&format!("/nodes/{}/qemu/{}/status/stop", g.node, g.vm.vmid), &[] as &[(String, String)])
                .await?;
            self.wait_task(&g.node, &upid).await?;
            n += 1;
        }
        Ok(n)
    }
}

/// One look: every expired lease's machine stopped, and the file written.
pub async fn check(book: &Shared, driver: &Client, file: &std::path::Path) {
    for id in expired(book, Instant::now()) {
        match driver.stop_leased(&id).await {
            Ok(n) => {
                stopped(book, &id);
                crate::audit::record("instance.lease", "agent", &id, "stopped", Some(&n.to_string()));
                println!("run lease: {id} ran past its lease without a view from Core; stopped ({n})");
            }
            Err(e) => eprintln!("run lease: {id} past its lease was not stopped: {e:#}"),
        }
    }
    let body = file_body(book).to_string();
    let tmp = file.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp, body).and_then(|_| std::fs::rename(&tmp, file)) {
        eprintln!("run lease: {} not written: {e}", file.display());
    }
}

/// The lease task: beside the reconcile loop, never inside it, because it
/// must run exactly when Core cannot be reached. Every 30 s.
pub fn spawn(book: Shared, driver: Arc<Client>, file: std::path::PathBuf) {
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(30));
        loop {
            every.tick().await;
            check(&book, &driver, &file).await;
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
