//! A Proxmox API that answers from a test's own routing function.
//!
//! **Test-only.** The agent's create, delete and reap paths are long chains of
//! hypervisor calls, and until this existed they were compiled and linted but
//! never exercised: a rollback, a cluster-wide lookup or a refusal was a claim
//! in a commit message. This serves `/api2/json/...` over plain HTTP on
//! loopback, answers each call with what the routing function returns, wraps
//! it in Proxmox's `{"data": ...}` envelope, and records every call so a test
//! can assert what was, and was not, asked for.

use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One call the agent made: method, path (after `/api2/json`, query included)
/// and the raw body.
#[derive(Debug, Clone)]
pub struct Call {
    pub method: String,
    pub path: String,
    pub body: String,
}

type Route = dyn Fn(&str, &str, &str) -> (u16, serde_json::Value) + Send + Sync;

pub struct Mock {
    pub base: String,
    pub calls: Arc<Mutex<Vec<Call>>>,
}

impl Mock {
    /// `route(method, path, body)` answers every call. Task status for any
    /// UPID is answered as finished and OK unless the route says otherwise.
    ///
    /// Two facts every create asks (PROVIDER-30) are answered here, before
    /// the route: the agent runs on `n1`, and its snippet storage is shared,
    /// so a test about placement is not also a test about first-boot files.
    /// A test about those uses `start_raw`.
    pub async fn start(route: impl Fn(&str, &str, &str) -> (u16, serde_json::Value) + Send + Sync + 'static) -> Mock {
        Self::start_raw(move |method, path, body| {
            if method == "GET" && path == "/cluster/status" {
                return (200, serde_json::json!([{"type": "node", "name": "n1", "local": 1, "online": 1}]));
            }
            if method == "GET" && path.starts_with("/nodes/") && path.ends_with("/storage/onv-snippets/status") {
                return (200, serde_json::json!({"shared": 1, "type": "dir", "active": 1}));
            }
            route(method, path, body)
        })
        .await
    }

    /// `start` without the two answers it supplies.
    pub async fn start_raw(route: impl Fn(&str, &str, &str) -> (u16, serde_json::Value) + Send + Sync + 'static) -> Mock {
        let route: Arc<Route> = Arc::new(route);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let calls: Arc<Mutex<Vec<Call>>> = Default::default();
        let recorded = calls.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else { return };
                let (route, recorded) = (route.clone(), recorded.clone());
                tokio::spawn(async move {
                    let Some((method, path, body)) = read_request(&mut s).await else { return };
                    let path = path.strip_prefix("/api2/json").unwrap_or(&path).to_string();
                    recorded.lock().unwrap().push(Call { method: method.clone(), path: path.clone(), body: body.clone() });
                    let (status, data) = route(&method, &path, &body);
                    let payload = serde_json::json!({ "data": data }).to_string();
                    let head = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        payload.len()
                    );
                    let _ = s.write_all(head.as_bytes()).await;
                    let _ = s.write_all(payload.as_bytes()).await;
                });
            }
        });
        Mock { base, calls }
    }

    /// A client for this mock. The fingerprint is never used over plain HTTP.
    ///
    /// **The start gate is short here**: two looks 50 ms apart, because under
    /// test nothing becomes ready by waiting. A test value, kept in the test
    /// code: it was a `#[cfg(test)]` constant in `proxmox.rs` until the gate
    /// became `timings.startGate*`, and a test value is not a configuration.
    pub fn client(&self) -> crate::proxmox::Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        crate::proxmox::Client::new(
            &self.base,
            Some(&"AB".repeat(32)),
            "onv@pve!agent",
            "secret",
            None,
            crate::config::Contribution::default(),
            None,
            None,
            None,
        )
        .expect("client")
        .with_timings(crate::timings::Timings {
            start_gate_looks: 2,
            start_gate_every: crate::dur::Dur::millis(50),
            ..Default::default()
        })
    }

    /// The body of the first call with this method and path.
    pub fn body_of(&self, method: &str, path: &str) -> Option<String> {
        self.calls.lock().unwrap().iter().find(|c| c.method == method && c.path == path).map(|c| c.body.clone())
    }

    pub fn called(&self, method: &str, path: &str) -> bool {
        self.calls.lock().unwrap().iter().any(|c| c.method == method && c.path == path)
    }
}

/// The start gate's reads (`Client::start_blockers`) answered with nothing
/// blocking: no task in flight, a machine with no bridges and no cards, no
/// SDN networks. For a test about something else that ends in a start; a test
/// of the gate answers these itself.
pub fn gate_clear(method: &str, path: &str) -> Option<(u16, serde_json::Value)> {
    if method != "GET" {
        return None;
    }
    if path.contains("/tasks?source=active") || path == "/cluster/sdn/vnets" {
        return Some((200, serde_json::json!([])));
    }
    if path.starts_with("/nodes/") && path.contains("/qemu/") && path.ends_with("/config") {
        return Some((200, serde_json::json!({})));
    }
    None
}

/// The routing a task-driven call needs: every UPID's status is "stopped, OK".
pub fn task_ok(path: &str) -> Option<(u16, serde_json::Value)> {
    (path.contains("/tasks/") && path.ends_with("/status"))
        .then(|| (200, serde_json::json!({"status": "stopped", "exitstatus": "OK"})))
}

async fn read_request(s: &mut tokio::net::TcpStream) -> Option<(String, String, String)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let mut first = lines.next()?.split_whitespace();
    let (method, path) = (first.next()?.to_string(), first.next()?.to_string());
    let len = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&buf[head_end..(head_end + len).min(buf.len())]).to_string();
    Some((method, path, body))
}
