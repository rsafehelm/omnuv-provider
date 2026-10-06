//! A Proxmox API that answers from a test's own routing function: the
//! agent's `pvemock`, cut to what the timer asks, and recording which token
//! asked. **Test-only.** Serves `/api2/json/...` over plain HTTP on loopback,
//! wraps each answer in Proxmox's `{"data": ...}` envelope, and records every
//! call so a test can assert what was, and was not, asked for.

use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One call: method, path (after `/api2/json`, query included), and the
/// `Authorization` header it carried.
#[derive(Debug, Clone)]
pub struct Call {
    pub method: String,
    pub path: String,
    pub auth: String,
}

type Route = dyn Fn(&str, &str) -> (u16, serde_json::Value) + Send + Sync;

pub struct Mock {
    pub base: String,
    pub calls: Arc<Mutex<Vec<Call>>>,
}

impl Mock {
    pub async fn start(route: impl Fn(&str, &str) -> (u16, serde_json::Value) + Send + Sync + 'static) -> Mock {
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
                    let Some((method, path, auth)) = read_request(&mut s).await else { return };
                    let path = path.strip_prefix("/api2/json").unwrap_or(&path).to_string();
                    recorded.lock().unwrap().push(Call { method: method.clone(), path: path.clone(), auth });
                    let (status, data) = route(&method, &path);
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

    /// The timer's client for this mock, as `onv@pve!lease`. The fingerprint
    /// is never used over plain HTTP.
    pub fn client(&self) -> crate::Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        crate::Client::new(&self.base, Some(&"AB".repeat(32)), "onv@pve!lease", "secret").expect("client")
    }

    pub fn called(&self, method: &str, path: &str) -> bool {
        self.calls.lock().unwrap().iter().any(|c| c.method == method && c.path == path)
    }
}

/// Every task's status is "stopped, OK".
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
    let headers: Vec<(&str, &str)> = lines.filter_map(|l| l.split_once(':')).collect();
    let header = |name: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim());
    let len = header("content-length").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
    let auth = header("authorization").unwrap_or("").to_string();
    while buf.len() < head_end + len {
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Some((method, path, auth))
}
