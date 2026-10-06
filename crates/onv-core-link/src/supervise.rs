//! **Every task the agent spawns is watched, and a panic ends the process
//! with 70** (omnuv's modular design, A4).
//!
//! A `tokio::spawn` whose handle is dropped turns a panic into silence: the
//! task is gone and nothing says so. The tunnel, the image mirror and the card
//! scrub were spawned that way, so one panic lost that function until the
//! next restart while the agent went on heartbeating as if it had it. Only
//! the lease task was watched (lease.rs), and that watcher is now this one.
//!
//! A panic is a bug, and the agent cannot know what it left half done, so it
//! does not try to carry on without the function: it says which task, records
//! it in the audit log, and exits with [`PANIC_EXIT`] (EX_SOFTWARE). systemd
//! starts it again (`Restart=always`); a restarted agent resumes its leases
//! from their file and its desired state from Core. Exit 3, "stop for good",
//! is the one code the unit does not restart (`RestartPreventExitStatus=3`).
//!
//! `clippy.toml` refuses `tokio::spawn` outside this module, so a task spawned
//! anywhere else in the agent's production code fails the lint.
//!
//! **Here, not in onv-agent-lib**, which would be its natural floor: that crate
//! has no tokio, and giving it one moved onv-workloadd's digest (measured,
//! 6 October 2026: fdeb27d8… on main, 2abb4b24… with the edge), which reboots
//! every running inference worker once (PROVIDER-31). This crate already
//! depends on tokio and on onv-agent-lib, and every crate that spawns already
//! depends on it.

use std::future::Future;

use tokio::task::JoinHandle;

/// EX_SOFTWARE in sysexits.h: an internal software error. What the lease
/// task's watcher used before this module, kept.
pub const PANIC_EXIT: i32 = 70;

/// Spawns `fut` and watches it: a panic ends the process with
/// [`PANIC_EXIT`]. The handle returned behaves as `tokio::spawn`'s does for
/// everything but a panic: it yields the task's output, and aborting it (or
/// dropping the watcher with the runtime) aborts the task.
pub fn spawn<F>(name: &'static str, fut: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    spawn_with(name, fut, exit_on_panic)
}

fn exit_on_panic(name: &'static str) {
    // The panic's own message is already on stderr, from the default hook.
    eprintln!("supervise: the task `{name}` panicked; the agent exits {PANIC_EXIT} so systemd starts it whole");
    onv_agent_lib::audit::record("agent.panic", "agent", name, "error", Some("the process exits 70 and is restarted"));
    std::process::exit(PANIC_EXIT);
}

/// [`spawn`], with what a panic does given: the tests' seam. After
/// `on_panic` returns, the watcher never completes, so nothing awaiting the
/// handle reads a panic as an ordinary end.
fn spawn_with<F>(name: &'static str, fut: F, on_panic: fn(&'static str)) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    // The one place the agent spawns directly; everything else comes here.
    #[allow(clippy::disallowed_methods)]
    let task = tokio::spawn(fut);
    #[allow(clippy::disallowed_methods)]
    tokio::spawn(watch(name, task, on_panic))
}

/// Aborts the task it holds when dropped: aborting the watcher's handle
/// drops its future, and with it this, so the task goes too.
struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn watch<T>(name: &'static str, task: JoinHandle<T>, on_panic: fn(&'static str)) -> T {
    let mut held = AbortOnDrop(task);
    match (&mut held.0).await {
        Ok(out) => out,
        Err(e) if e.is_panic() => {
            on_panic(name);
            std::future::pending().await
        }
        // Cancelled: only by the guard above, which runs when this future is
        // itself dropped, or by the runtime shutting down. Neither is a
        // panic, and nobody is left to read an answer.
        Err(_) => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    static PANICKED: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

    fn note(name: &'static str) {
        onv_agent_lib::poison::lock(&PANICKED, "test").push(name);
    }

    /// The environment variable that makes the exit test its own child.
    const CHILD: &str = "ONV_SUPERVISE_PANIC_CHILD";

    /// **A task that panics ends the process with 70** (A4's acceptance).
    /// The real `spawn`, in a child process: this test re-runs itself with
    /// [`CHILD`] set, the child spawns a task that panics and then waits, and
    /// the parent reads the child's exit status. Unwatched, the child's wait
    /// ends and the test inside it passes, so its status is 0 and this fails.
    #[test]
    fn a_task_that_panics_ends_the_process_with_70() {
        if std::env::var_os(CHILD).is_some() {
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
            rt.block_on(async {
                let _task = super::spawn("a test task that panics", async { panic!("panicking on purpose") });
                // ceiling: the panic is immediate; 20 s only bounds a child
                // that, wrongly, was not ended by it.
                tokio::time::sleep(Duration::from_secs(20)).await;
            });
            return;
        }
        let me = std::env::current_exe().expect("the test binary");
        let out = std::process::Command::new(me)
            .args(["--exact", "supervise::tests::a_task_that_panics_ends_the_process_with_70", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .expect("the child runs");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(super::PANIC_EXIT), "the child's status; its stderr:\n{stderr}");
        assert!(stderr.contains("the task `a test task that panics` panicked"), "{stderr}");
    }

    /// The watcher calls its hook with the task's name, and then never
    /// completes: an awaiting caller does not read a panic as an end.
    #[tokio::test]
    async fn a_panic_is_said_by_name_and_the_handle_never_completes() {
        let mut handle = super::spawn_with("named", async { panic!("on purpose") }, note);
        // ceiling: the hook runs as soon as the watcher is scheduled; 10 s
        // only bounds a hook that, wrongly, is never called. Polled, so a
        // loaded host waits longer instead of failing.
        let said = async {
            while !onv_agent_lib::poison::lock(&PANICKED, "test").contains(&"named") {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(10), said).await.expect("the hook named the task");
        // Once the panic is said, the handle still does not complete.
        let waited = tokio::time::timeout(Duration::from_millis(300), &mut handle).await;
        assert!(waited.is_err(), "the handle completed after a panic: {waited:?}");
    }

    /// Everything but a panic is as `tokio::spawn`: the output comes back,
    /// and nothing is said.
    #[tokio::test]
    async fn a_task_that_ends_yields_its_output() {
        let handle = super::spawn_with("ends", async { 42 }, note);
        assert_eq!(handle.await.unwrap(), 42);
        assert!(!onv_agent_lib::poison::lock(&PANICKED, "test").contains(&"ends"));
    }

    /// Aborting the handle aborts the task (the tunnel's Cancel does this to
    /// a request), rather than detaching it.
    #[tokio::test]
    async fn aborting_the_handle_aborts_the_task() {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = super::spawn_with(
            "aborted",
            async move {
                let _held = tx;
                std::future::pending::<()>().await
            },
            note,
        );
        tokio::task::yield_now().await;
        handle.abort();
        // The sender is dropped only when the task is: an error here is the
        // task gone. A detached task would hold it, and this would time out.
        let gone = tokio::time::timeout(Duration::from_secs(5), rx).await;
        assert!(matches!(gone, Ok(Err(_))), "the task outlived its aborted handle: {gone:?}");
        assert!(!onv_agent_lib::poison::lock(&PANICKED, "test").contains(&"aborted"));
    }
}
