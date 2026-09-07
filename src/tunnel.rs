//! Outbound tunnel to Core.
//!
//! The agent dials Core and holds the connection open; Core sends work down it.
//! Nothing here listens, so the provider needs no inbound firewall rule, no port
//! forward and no public address. A provider behind CGNAT participates with no
//! configuration at all.
//!
//! Every request arriving over this connection is audited locally before it is
//! acted on, because Core asking this machine to do something is exactly the
//! event a provider needs to be able to review.

use std::collections::HashMap;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use omnu_protocol::TunnelFrame;
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::audit;

/// Resolves a marketplace worker id to the endpoint it serves on locally.
/// Core never learns the provider's addressing; it names the worker, the agent
/// knows where that is.
pub type ResolveWorker = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

pub async fn run(
    core_url: &str,
    token: &str,
    resolve: ResolveWorker,
    nudge: Arc<tokio::sync::Notify>,
) {
    let ws_url = core_url
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1)
        + "/provider/v1/tunnel";

    let mut backoff = 2u64;
    loop {
        match connect(&ws_url, token, resolve.clone(), nudge.clone()).await {
            Ok(()) => {
                audit::record("tunnel.closed", "agent", "core", "ok", None);
                backoff = 2;
            }
            Err(e) => {
                audit::record("tunnel.error", "agent", "core", "error", Some(&e.to_string()));
                eprintln!("tunnel: {e}");
            }
        }
        // Bounded backoff: a provider that cannot reach Core must not spin, but
        // must also recover quickly once the path returns.
        tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(60);
    }
}

/// Honours `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`, so a provider on a network
/// that only permits egress through a proxy can still join. Without this the
/// tunnel would be the one component that cannot phone home.
fn proxy_for(url: &str) -> Option<String> {
    let insecure = url.starts_with("ws://");
    let names: &[&str] = if insecure {
        &["http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"]
    } else {
        &["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"]
    };
    names
        .iter()
        .find_map(|n| std::env::var(n).ok())
        .filter(|v| !v.trim().is_empty())
}

/// Opens a TCP stream to the destination, through an HTTP CONNECT proxy when
/// one is configured.
async fn open_stream(url: &url_lite::Parts, proxy: Option<&str>) -> anyhow::Result<tokio::net::TcpStream> {
    let Some(proxy) = proxy else {
        return Ok(tokio::net::TcpStream::connect((url.host.as_str(), url.port)).await?);
    };

    let p = url_lite::parse(proxy)?;
    let mut stream = tokio::net::TcpStream::connect((p.host.as_str(), p.port)).await?;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let target = format!("{}:{}", url.host, url.port);
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await?;

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;
    let head = String::from_utf8_lossy(&buf[..n]);
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        anyhow::bail!("proxy refused CONNECT to {target}: {}", head.lines().next().unwrap_or_default());
    }
    Ok(stream)
}

/// Minimal URL split. A full URL crate would be a dependency for four fields.
mod url_lite {
    pub struct Parts {
        pub host: String,
        pub port: u16,
    }

    pub fn parse(url: &str) -> anyhow::Result<Parts> {
        let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
        let tls = matches!(scheme, "https" | "wss");
        let authority = rest.split(['/', '?']).next().unwrap_or(rest);
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h, p.parse()?),
            _ => (authority, if tls { 443 } else { 80 }),
        };
        let _ = tls;
        Ok(Parts { host: host.to_string(), port })
    }
}

async fn connect(
    ws_url: &str,
    token: &str,
    resolve: ResolveWorker,
    nudge: Arc<tokio::sync::Notify>,
) -> anyhow::Result<()> {
    let mut request = ws_url.into_client_request()?;
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {token}").parse()?);

    let parts = url_lite::parse(ws_url)?;
    let proxy = proxy_for(ws_url);
    if let Some(p) = &proxy {
        println!("tunnel: connecting through proxy {p}");
    }
    let stream = open_stream(&parts, proxy.as_deref()).await?;
    let (socket, _) = tokio_tungstenite::client_async_tls(request, stream).await?;
    audit::record("tunnel.open", "agent", "core", "ok", None);
    println!("tunnel connected to core");

    let (mut sink, mut stream) = socket.split();
    let (out_tx, mut out_rx) = mpsc::channel::<TunnelFrame>(256);
    let inflight: Arc<Mutex<HashMap<String, tokio::task::JoinHandle<()>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Keepalive: an idle WebSocket through a NAT or proxy is reaped silently,
    // and a dead tunnel that still looks alive is worse than a closed one.
    {
        let ping = out_tx.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(20));
            loop {
                tick.tick().await;
                if ping.send(TunnelFrame::Ping).await.is_err() {
                    break;
                }
            }
        });
    }

    let writer = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            let Ok(text) = serde_json::to_string(&frame) else { continue };
            if sink.send(Message::text(text)).await.is_err() {
                break;
            }
        }
    });

    while let Some(msg) = stream.next().await {
        let msg = msg?;
        let text = match msg {
            Message::Text(t) => t.to_string(),
            Message::Close(_) => break,
            _ => continue,
        };
        let Ok(frame) = serde_json::from_str::<TunnelFrame>(&text) else {
            continue;
        };

        match frame {
            TunnelFrame::Request { id, worker_id, path, body } => {
                let Some(endpoint) = resolve(&worker_id) else {
                    audit::record("tunnel.request", "core", &worker_id, "rejected", Some("unknown worker"));
                    let _ = out_tx
                        .send(TunnelFrame::Error {
                            id,
                            message: "no such worker on this provider".into(),
                        })
                        .await;
                    continue;
                };
                // Recorded before the work starts, so a request that kills the
                // agent still leaves evidence it arrived.
                audit::record("tunnel.request", "core", &worker_id, "accepted", Some(&path));

                let tx = out_tx.clone();
                let key = id.clone();
                let handle = tokio::spawn(async move {
                    forward(&endpoint, &path, body, id, tx).await;
                });
                inflight.lock().await.insert(key, handle);
            }
            TunnelFrame::Cancel { id } => {
                if let Some(h) = inflight.lock().await.remove(&id) {
                    h.abort();
                    audit::record("tunnel.cancel", "core", &id, "ok", None);
                }
            }
            TunnelFrame::Reconcile => {
                // Core says desired state moved. Wake the loop rather than
                // waiting out the poll interval.
                audit::record("reconcile.requested", "core", "desired-state", "ok", None);
                nudge.notify_one();
            }
            TunnelFrame::Ping => {
                let _ = out_tx.send(TunnelFrame::Pong).await;
            }
            _ => {}
        }
    }

    writer.abort();
    Ok(())
}

/// Runs one tunnelled request against the local worker and streams the response
/// back frame by frame, so token-by-token delivery survives the hop.
async fn forward(
    endpoint: &str,
    path: &str,
    body: String,
    id: String,
    out: mpsc::Sender<TunnelFrame>,
) {
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{endpoint}{path}"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await;

    let res = match res {
        Ok(r) => r,
        Err(e) => {
            audit::record("tunnel.forward", "core", path, "error", Some(&e.to_string()));
            let _ = out.send(TunnelFrame::Error { id, message: e.to_string() }).await;
            return;
        }
    };

    let status = res.status().as_u16();
    if out.send(TunnelFrame::Head { id: id.clone(), status }).await.is_err() {
        return;
    }

    let mut bytes = 0usize;
    let mut stream = res.bytes_stream();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(b) => {
                bytes += b.len();
                let data = String::from_utf8_lossy(&b).to_string();
                if out.send(TunnelFrame::Chunk { id: id.clone(), data }).await.is_err() {
                    return;
                }
            }
            Err(e) => {
                let _ = out.send(TunnelFrame::Error { id, message: e.to_string() }).await;
                return;
            }
        }
    }

    // Size and status only: buyer payloads are never written to a provider's
    // disk by this agent.
    audit::record("tunnel.forward", "core", path, "ok", Some(&format!("status={status} bytes={bytes}")));
    let _ = out.send(TunnelFrame::End { id }).await;
}

#[cfg(test)]
mod tests {
    use super::url_lite;

    #[test]
    fn splits_urls_and_defaults_the_port_by_scheme() {
        let a = url_lite::parse("ws://core.example:8410/provider/v1/tunnel").unwrap();
        assert_eq!((a.host.as_str(), a.port), ("core.example", 8410));
        // Default ports matter: a proxy CONNECT needs an explicit port even
        // when the URL omits one.
        assert_eq!(url_lite::parse("wss://core.example/x").unwrap().port, 443);
        assert_eq!(url_lite::parse("ws://core.example/x").unwrap().port, 80);
        // Credentials in a proxy URL must not be mistaken for the host.
        assert_eq!(url_lite::parse("http://user:pw@proxy:3128").unwrap().host, "proxy");
    }
}
