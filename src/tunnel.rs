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
use omnuv_protocol::TunnelFrame;
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::audit;
use crate::console::{ConsoleInput, ConsoleOpener};

/// Resolves a marketplace worker id to the endpoint it serves on locally.
/// Core never learns the provider's addressing; it names the worker, the agent
/// knows where that is.
pub type ResolveWorker = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Records a request's task so a Cancel can end it, and forgets every task
/// that has already finished (PROVIDER-14). The map was cleaned only on Cancel,
/// and Core sends Cancel only for what it abandons, so every completed request
/// stayed for the life of the tunnel. Pruning here rather than having a task
/// remove itself: a task can finish before it is inserted, and would then be
/// left behind for good.
async fn track(
    inflight: &Mutex<HashMap<String, tokio::task::JoinHandle<()>>>,
    key: String,
    handle: tokio::task::JoinHandle<()>,
) {
    let mut map = inflight.lock().await;
    map.retain(|_, h| !h.is_finished());
    map.insert(key, handle);
}

/// The tunnel's two clocks: `timings.tunnelPing` and `timings.tunnelSilence`
/// in the agent's file. `timings.rs` holds them to Core's own: a ping at most
/// every 20 s, because Core leaves a tunnel it has heard nothing on for its
/// `tunnel.silence`, at least a minute, and needs three pings in it; and a
/// silence of at least three pings, because Core answers each one.
#[derive(Clone, Copy, Debug)]
pub struct Keepalive {
    /// How often this agent pings Core.
    pub ping: std::time::Duration,
    /// How long Core may say nothing before the tunnel is taken as gone.
    pub silence: std::time::Duration,
}

impl Default for Keepalive {
    fn default() -> Self {
        Self::from(&crate::timings::Timings::default())
    }
}

impl From<&crate::timings::Timings> for Keepalive {
    fn from(t: &crate::timings::Timings) -> Self {
        Self { ping: t.tunnel_ping.std(), silence: t.tunnel_silence.std() }
    }
}

pub async fn run(
    core_url: &str,
    token: &omnuv_protocol::Redacted,
    session: crate::session::Session,
    resolve: ResolveWorker,
    nudge: Arc<tokio::sync::Notify>,
    consoles: Arc<dyn ConsoleOpener>,
    keepalive: Keepalive,
) {
    let ws_url = core_url
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1)
        + "/provider/v1/tunnel";

    let mut backoff = 2u64;
    loop {
        match connect(&ws_url, token, &session, resolve.clone(), nudge.clone(), consoles.clone(), keepalive).await {
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

/// What one connection holds per request: the tasks a Cancel can end, and the
/// open consoles' inputs. Per connection, so dropped with it; passed in rather
/// than made inside, so a test can ask what an ending left behind (leak
/// assertions, the operator's first class-closing item of 24 September 2026).
#[derive(Clone, Default)]
struct Tables {
    inflight: Arc<Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>,
    /// Open consoles, by tunnel id: where a buyer's keystrokes go. Dropping
    /// the sender ends the session at the hypervisor.
    sessions: Arc<Mutex<HashMap<String, mpsc::Sender<ConsoleInput>>>>,
}

impl Tables {
    /// Open consoles, and tasks still running. Idle, both are zero.
    #[cfg(test)]
    async fn held(&self) -> (usize, usize) {
        let consoles = self.sessions.lock().await.len();
        let running = self.inflight.lock().await.values().filter(|h| !h.is_finished()).count();
        (consoles, running)
    }
}

async fn connect(
    ws_url: &str,
    token: &omnuv_protocol::Redacted,
    session: &crate::session::Session,
    resolve: ResolveWorker,
    nudge: Arc<tokio::sync::Notify>,
    consoles: Arc<dyn ConsoleOpener>,
    keepalive: Keepalive,
) -> anyhow::Result<()> {
    connect_with(ws_url, token, session, resolve, nudge, consoles, Tables::default(), keepalive).await
}

#[allow(clippy::too_many_arguments)]
async fn connect_with(
    ws_url: &str,
    token: &omnuv_protocol::Redacted,
    session: &crate::session::Session,
    resolve: ResolveWorker,
    nudge: Arc<tokio::sync::Notify>,
    consoles: Arc<dyn ConsoleOpener>,
    tables: Tables,
    keepalive: Keepalive,
) -> anyhow::Result<()> {
    let mut request = ws_url.into_client_request()?;
    request
        .headers_mut()
        // `.expose()` rather than `{token}`: `Redacted`'s `Display` prints
        // `<redacted>`, so interpolating it would build a header that is
        // perfectly well formed and that Core refuses — an agent reconnecting
        // into a 401 forever, with the reason redacted out of its own log.
        .insert("authorization", format!("Bearer {}", token.expose()).parse()?);
    // The session, when Core minted one (lifecycle phase 7, RC12): the tunnel
    // is a call like any other, and Core takes it only from the holder.
    if let Some(s) = crate::session::current(session) {
        request.headers_mut().insert(crate::session::HEADER, s.parse()?);
    }

    let parts = url_lite::parse(ws_url)?;
    let proxy = proxy_for(ws_url);
    if let Some(p) = &proxy {
        println!("tunnel: connecting through proxy {p}");
    }
    let stream = open_stream(&parts, proxy.as_deref()).await?;
    let (socket, _) = tokio_tungstenite::client_async_tls(request, stream).await?;
    audit::record("tunnel.open", "agent", "core", "ok", None);
    println!("tunnel connected to core");
    serve_socket(socket, resolve, nudge, consoles, tables, keepalive).await
}

/// Serves one connection to Core until it closes, fails or goes silent.
/// Generic over the transport, so a simulated network can carry it
/// (`mod partition`).
///
/// Core may say nothing for `keepalive.silence` before its tunnel is taken as
/// gone. Core answers each of this agent's pings, so the default minute with
/// no frame is three answers missed to the default 20-second pings.
async fn serve_socket<S>(
    socket: tokio_tungstenite::WebSocketStream<S>,
    resolve: ResolveWorker,
    nudge: Arc<tokio::sync::Notify>,
    consoles: Arc<dyn ConsoleOpener>,
    tables: Tables,
    keepalive: Keepalive,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sink, mut stream) = socket.split();
    let (out_tx, mut out_rx) = mpsc::channel::<TunnelFrame>(256);
    let Tables { inflight, sessions } = tables;

    // Keepalive: an idle WebSocket through a NAT or proxy is reaped silently,
    // and a dead tunnel that still looks alive is worse than a closed one.
    {
        let ping = out_tx.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(keepalive.ping);
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

    // **Silence ends a tunnel** (turmoil, 24 September 2026). A link cut with
    // nothing closed never errors a socket: this waited on it until TCP gave
    // up, about fifteen minutes, while Core could reach nothing on this host.
    // An error sends `run` back to reconnect.
    loop {
        let msg = match tokio::time::timeout(keepalive.silence, stream.next()).await {
            Ok(Some(msg)) => msg?,
            Ok(None) => break,
            Err(_) => {
                writer.abort();
                anyhow::bail!("Core said nothing for {} s; reconnecting", keepalive.silence.as_secs());
            }
        };
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
                track(&inflight, key, handle).await;
            }
            TunnelFrame::ConsoleOpen { id, instance_id, kind } => {
                // Recorded before anything is opened: a console is a
                // root-equivalent path into a machine on this host.
                audit::record("console.request", "core", &instance_id, "accepted", Some(kind.as_str()));
                let tx = out_tx.clone();
                let opener = consoles.clone();
                let table = sessions.clone();
                let key = id.clone();
                let handle = tokio::spawn(async move {
                    let stream = match opener.open(&instance_id, kind).await {
                        Ok(s) => s,
                        Err(e) => {
                            audit::record("console.request", "core", &instance_id, "error", Some(&e.to_string()));
                            let _ = tx.send(TunnelFrame::Error { id, message: e.to_string() }).await;
                            return;
                        }
                    };
                    table.lock().await.insert(id.clone(), stream.to_vm);
                    if tx.send(TunnelFrame::Head { id: id.clone(), status: 200 }).await.is_err() {
                        table.lock().await.remove(&id);
                        return;
                    }
                    if let Some(password) = stream.credential {
                        let _ = tx.send(TunnelFrame::ConsoleCredential { id: id.clone(), password }).await;
                    }
                    let mut from_vm = stream.from_vm;
                    while let Some(bytes) = from_vm.recv().await {
                        use base64::Engine as _;
                        let data = base64::engine::general_purpose::STANDARD.encode(&bytes);
                        if tx.send(TunnelFrame::ConsoleData { id: id.clone(), data }).await.is_err() {
                            break;
                        }
                    }
                    table.lock().await.remove(&id);
                    let _ = tx.send(TunnelFrame::End { id }).await;
                });
                track(&inflight, key, handle).await;
            }
            // **Never wait on one console in the loop that serves them all.**
            // This awaited the console's bounded input, with the sessions lock
            // still held as a temporary of the `if let`, so a machine that did
            // not drain its input (a paste into a slow serial line) stopped
            // every frame for this provider: inference, Cancel, Ping, the other
            // consoles. Core fixed the same shape in PROVIDER-19; the source
            // review of 24 September 2026 found it here. The sender is taken
            // out of the lock first, and a console whose input is full is cut,
            // as Core's own `deliver` does: its End tells Core, and the buyer's
            // page, that it closed.
            TunnelFrame::ConsoleData { id, data } => {
                use base64::Engine as _;
                let to_vm = sessions.lock().await.get(&id).cloned();
                if let (Some(to_vm), Ok(bytes)) = (to_vm, base64::engine::general_purpose::STANDARD.decode(data))
                    && let Err(mpsc::error::TrySendError::Full(_)) = to_vm.try_send(ConsoleInput::Data(bytes))
                {
                    sessions.lock().await.remove(&id);
                    if let Some(h) = inflight.lock().await.remove(&id) {
                        h.abort();
                    }
                    audit::record("console.cut", "core", &id, "failed", Some("the machine did not read its input"));
                    let _ = out_tx.send(TunnelFrame::End { id }).await;
                }
            }
            TunnelFrame::ConsoleResize { id, cols, rows } => {
                // A resize that does not fit is dropped: the next one carries
                // the size that matters.
                let to_vm = sessions.lock().await.get(&id).cloned();
                if let Some(to_vm) = to_vm {
                    let _ = to_vm.try_send(ConsoleInput::Resize { cols, rows });
                }
            }
            TunnelFrame::Cancel { id } => {
                // A console's sender goes too, which is what closes it.
                sessions.lock().await.remove(&id);
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
/// Decodes a byte stream to text across chunk boundaries.
///
/// Each chunk was decoded alone with `from_utf8_lossy`, so a multi-byte
/// character that arrived half in one chunk and half in the next became two
/// replacement characters in the answer a buyer streams: an accented word or
/// an emoji, broken at random. An incomplete sequence at the end of a chunk is
/// held back and prefixed to the next; genuinely invalid bytes are still
/// replaced, as before.
#[derive(Default)]
struct Utf8Carry {
    pending: Vec<u8>,
}

impl Utf8Carry {
    /// What is left when the stream ends: an incomplete character that will
    /// never be completed, replaced rather than dropped.
    fn finish(&mut self) -> Option<String> {
        (!self.pending.is_empty()).then(|| String::from_utf8_lossy(&std::mem::take(&mut self.pending)).into_owned())
    }

    fn push(&mut self, chunk: &[u8]) -> String {
        self.pending.extend_from_slice(chunk);
        let mut out = String::new();
        loop {
            match std::str::from_utf8(&self.pending) {
                Ok(s) => {
                    out.push_str(s);
                    self.pending.clear();
                    return out;
                }
                Err(e) => {
                    let good = e.valid_up_to();
                    out.push_str(std::str::from_utf8(&self.pending[..good]).unwrap_or_default());
                    match e.error_len() {
                        // Incomplete at the end: keep it for the next chunk.
                        None => {
                            self.pending.drain(..good);
                            return out;
                        }
                        // Invalid, not incomplete: replace it and go on.
                        Some(bad) => {
                            out.push(char::REPLACEMENT_CHARACTER);
                            self.pending.drain(..good + bad);
                        }
                    }
                }
            }
        }
    }
}

/// The worker paths Core may ask this agent to reach.
///
/// **An allowlist, because the path is appended to the endpoint.** It was used
/// as given, so a path such as `@elsewhere.example/` turned
/// `http://127.0.0.1:8000` into a URL whose host is somebody else's, and a
/// Core that was wrong, or not Core, could make this agent dial anything its
/// host can reach. Core sends `/v1/chat/completions`; the other two are the
/// OpenAI routes a worker serves beside it.
const FORWARDABLE: &[&str] = &["/v1/chat/completions", "/v1/completions", "/v1/embeddings"];

fn forwardable(path: &str) -> bool {
    FORWARDABLE.contains(&path)
}

async fn forward(
    endpoint: &str,
    path: &str,
    body: String,
    id: String,
    out: mpsc::Sender<TunnelFrame>,
) {
    if !forwardable(path) {
        audit::record("tunnel.forward", "core", path, "refused", Some("not a worker path this agent forwards"));
        let _ = out
            .send(TunnelFrame::Error { id, message: format!("{path} is not a path this agent forwards") })
            .await;
        return;
    }
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
    // A character split across two network chunks is carried to the next one,
    // not decoded in halves. See `Utf8Carry`.
    let mut carry = Utf8Carry::default();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(b) => {
                bytes += b.len();
                let data = carry.push(&b);
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

    if let Some(data) = carry.finish()
        && out.send(TunnelFrame::Chunk { id: id.clone(), data }).await.is_err()
    {
        return;
    }

    // Size and status only: buyer payloads are never written to a provider's
    // disk by this agent.
    audit::record("tunnel.forward", "core", path, "ok", Some(&format!("status={status} bytes={bytes}")));
    let _ = out.send(TunnelFrame::End { id }).await;
}

#[cfg(test)]
mod tests {
    use super::Utf8Carry;

    #[test]
    fn a_character_split_across_chunks_arrives_whole() {
        let text = "café 🙂 ok";
        let bytes = text.as_bytes();
        // Every split point, including inside the four-byte emoji.
        for cut in 0..=bytes.len() {
            let mut c = Utf8Carry::default();
            let joined = c.push(&bytes[..cut]) + &c.push(&bytes[cut..]);
            assert_eq!(joined, text, "split at byte {cut}");
        }
        // Invalid bytes are still replaced, not held forever.
        let mut c = Utf8Carry::default();
        assert_eq!(c.push(b"a\xffb"), "a\u{fffd}b");
        // A character the stream never finished is replaced at the end.
        let mut c = Utf8Carry::default();
        assert_eq!(c.push(&"é".as_bytes()[..1]), "");
        assert_eq!(c.finish().as_deref(), Some("\u{fffd}"));
        assert_eq!(c.finish(), None);
    }

    use super::forwardable;

    #[test]
    fn only_a_worker_path_is_forwarded() {
        assert!(forwardable("/v1/chat/completions"));
        for bad in ["@evil.example/v1/chat/completions", "/v1/chat/completions/../../admin",
                    "//evil.example/", "/v1/models?x=@y", "", "/metrics", "/v1/chat/completions#x"] {
            assert!(!forwardable(bad), "{bad} would have been forwarded");
        }
    }

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

    /// **A redacted secret is still a JSON string on the wire.**
    ///
    /// `ConsoleCredential.password` became `Redacted` so that no `{:?}` can
    /// print it. That type is `#[serde(transparent)]`, so the bytes are
    /// unchanged and `PROTOCOL_VERSION` does not move — but "unchanged" is a
    /// claim about somebody else's crate, fetched by tag, and this is the one
    /// frame the agent builds that carries one. Asserted against a literal
    /// rather than a round-trip: a round-trip through the same two impls agrees
    /// with itself no matter what either of them does, which is the shape that
    /// confirms nothing.
    ///
    /// If this ever fails, the fix is in `omnuv-protocol` and it is a wire
    /// break — not a `.to_string()` here to paper over it.
    #[test]
    fn a_redacted_secret_leaves_the_agent_as_a_plain_json_string() {
        let frame = omnuv_protocol::TunnelFrame::ConsoleCredential {
            id: "c-1".into(),
            password: "vnc-secret-9f2a".into(),
        };
        assert_eq!(
            serde_json::to_string(&frame).expect("a frame must serialize"),
            r#"{"t":"console_credential","id":"c-1","password":"vnc-secret-9f2a"}"#
        );
    }
}

#[cfg(test)]
mod inflight_is_bounded {
    use super::*;

    /// **PROVIDER-14: the map holds what is running, not what ever ran.** A
    /// thousand requests that finished leave one entry — the one just added
    /// — and a request still running is kept, so a Cancel can still end it.
    #[tokio::test]
    async fn finished_requests_are_forgotten_and_running_ones_kept() {
        let inflight: Mutex<HashMap<String, tokio::task::JoinHandle<()>>> = Mutex::new(HashMap::new());
        let running = tokio::spawn(std::future::pending::<()>());
        track(&inflight, "running".into(), running).await;
        for i in 0..1000 {
            let done = tokio::spawn(async {});
            while !done.is_finished() {
                tokio::task::yield_now().await;
            }
            track(&inflight, format!("r{i}"), done).await;
        }
        let map = inflight.lock().await;
        assert!(map.contains_key("running"), "a running request was forgotten");
        assert!(map.len() <= 2, "{} entries for one running request", map.len());
        map.get("running").unwrap().abort();
    }
}

#[cfg(test)]
mod stalled_console {
    use super::*;
    use crate::console::{ConsoleInput, ConsoleOpener, ConsoleStream};
    use futures_util::future::BoxFuture;

    /// A console whose machine side never reads its input, as a termproxy
    /// behind a slow serial line does: its receiver is kept alive and never
    /// polled.
    struct Stalled(std::sync::Mutex<Vec<mpsc::Receiver<ConsoleInput>>>, std::sync::Mutex<Vec<mpsc::Sender<Vec<u8>>>>);
    impl ConsoleOpener for Stalled {
        fn open<'a>(&'a self, _: &'a str, _: omnuv_protocol::ConsoleKind) -> BoxFuture<'a, anyhow::Result<ConsoleStream>> {
            Box::pin(async move {
                let (to_vm, input) = mpsc::channel::<ConsoleInput>(64);
                let (output, from_vm) = mpsc::channel::<Vec<u8>>(256);
                self.0.lock().unwrap().push(input);
                self.1.lock().unwrap().push(output);
                Ok(ConsoleStream { to_vm, from_vm, credential: None })
            })
        }
    }

    /// One stalled console no longer stops the tunnel: after a paste larger
    /// than the machine takes in, Core's Ping is still answered, and the
    /// stalled console is ended rather than left hanging. Before the fix the
    /// Ping got no Pong in 3 s (the source review of 24 September 2026, with
    /// this harness: a fake Core over a real websocket).
    #[tokio::test]
    async fn a_stalled_console_is_cut_and_the_tunnel_answers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let core = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let (mut sink, mut stream) = ws.split();
            let send = |f: TunnelFrame| Message::text(serde_json::to_string(&f).unwrap());
            sink.send(send(TunnelFrame::ConsoleOpen {
                id: "c1".into(),
                instance_id: "m1".into(),
                kind: omnuv_protocol::ConsoleKind::Serial,
            }))
            .await
            .unwrap();
            loop {
                let m = stream.next().await.unwrap().unwrap();
                if matches!(serde_json::from_str::<TunnelFrame>(&m.to_string()), Ok(TunnelFrame::Head { .. })) {
                    break;
                }
            }
            // A buyer pastes more than the machine takes in: 80 frames into
            // an input that holds 64 and is never read.
            for _ in 0..80 {
                sink.send(send(TunnelFrame::ConsoleData { id: "c1".into(), data: "YQ==".into() })).await.unwrap();
            }
            sink.send(send(TunnelFrame::Ping)).await.unwrap();
            let (mut ended, mut pong) = (false, false);
            let _ = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                while let Some(Ok(m)) = stream.next().await {
                    match serde_json::from_str::<TunnelFrame>(&m.to_string()) {
                        Ok(TunnelFrame::End { id }) if id == "c1" => ended = true,
                        Ok(TunnelFrame::Pong) => pong = true,
                        _ => {}
                    }
                    if ended && pong {
                        break;
                    }
                }
            })
            .await;
            (pong, ended)
        });
        let consoles: Arc<dyn ConsoleOpener> = Arc::new(Stalled(Default::default(), Default::default()));
        let url = format!("ws://127.0.0.1:{port}/provider/v1/tunnel");
        let tables = Tables::default();
        let held = tables.clone();
        let agent = tokio::spawn(async move {
            let token: omnuv_protocol::Redacted = "t".to_string().into();
            connect_with(&url, &token, &Default::default(), Arc::new(|_: &str| None), Arc::new(tokio::sync::Notify::new()), consoles, tables, Keepalive::default()).await
        });
        let (pong, ended) = core.await.unwrap();
        assert!(pong, "a stalled console stopped the tunnel: Core's Ping was not answered in 3 s");
        assert!(ended, "the stalled console was left open rather than ended");
        assert_eq!(held.held().await, (0, 0), "the cut console left its session or task behind");
        agent.abort();
    }

    /// **Every way a console ends leaves nothing held** (leak assertions, 24
    /// September 2026): Core's Cancel, and the machine side closing. Core's
    /// Ping is answered after each, so each ending has been read before the
    /// tables are asked.
    #[tokio::test]
    async fn every_console_ending_leaves_nothing_held() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let opener = Arc::new(Stalled(Default::default(), Default::default()));
        let machine = opener.clone();
        let tables = Tables::default();
        let held = tables.clone();
        let core = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let (mut sink, mut stream) = ws.split();
            let send = |f: TunnelFrame| Message::text(serde_json::to_string(&f).unwrap());
            // Reads until `want` says yes; three seconds at most.
            async fn until(
                stream: &mut (impl futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin),
                want: impl Fn(&TunnelFrame) -> bool,
            ) -> bool {
                tokio::time::timeout(std::time::Duration::from_secs(3), async {
                    while let Some(Ok(m)) = stream.next().await {
                        if serde_json::from_str::<TunnelFrame>(&m.to_string()).is_ok_and(|f| want(&f)) {
                            return true;
                        }
                    }
                    false
                })
                .await
                .unwrap_or(false)
            }
            let open = |id: &str| TunnelFrame::ConsoleOpen {
                id: id.into(),
                instance_id: "m1".into(),
                kind: omnuv_protocol::ConsoleKind::Serial,
            };
            let mut seen = Vec::new();

            // Cancelled by Core.
            sink.send(send(open("c1"))).await.unwrap();
            assert!(until(&mut stream, |f| matches!(f, TunnelFrame::Head { id, .. } if id == "c1")).await);
            sink.send(send(TunnelFrame::Cancel { id: "c1".into() })).await.unwrap();
            sink.send(send(TunnelFrame::Ping)).await.unwrap();
            assert!(until(&mut stream, |f| matches!(f, TunnelFrame::Pong)).await);
            seen.push(("a cancel", held.held().await));

            // Closed by the machine.
            sink.send(send(open("c2"))).await.unwrap();
            assert!(until(&mut stream, |f| matches!(f, TunnelFrame::Head { id, .. } if id == "c2")).await);
            machine.1.lock().unwrap().clear();
            assert!(until(&mut stream, |f| matches!(f, TunnelFrame::End { id } if id == "c2")).await,
                    "the machine closed and Core was not told");
            sink.send(send(TunnelFrame::Ping)).await.unwrap();
            assert!(until(&mut stream, |f| matches!(f, TunnelFrame::Pong)).await);
            tokio::task::yield_now().await;
            seen.push(("the machine closing", held.held().await));
            seen
        });
        let url = format!("ws://127.0.0.1:{port}/provider/v1/tunnel");
        let consoles: Arc<dyn ConsoleOpener> = opener;
        let agent = tokio::spawn(async move {
            let token: omnuv_protocol::Redacted = "t".to_string().into();
            connect_with(&url, &token, &Default::default(), Arc::new(|_: &str| None), Arc::new(tokio::sync::Notify::new()), consoles, tables, Keepalive::default()).await
        });
        let seen = core.await.unwrap();
        agent.abort();
        for (ending, left) in seen {
            assert_eq!(left.0, 0, "{ending} left the console's session held");
            assert_eq!(left.1, 0, "{ending} left its task running");
        }
    }
}

/// **Fault injection over a simulated network** (turmoil; the operator's
/// class-closing item 2, 24 September 2026). The agent's real connection
/// loop over turmoil's TCP, against a fake Core. Time is simulated.
#[cfg(test)]
mod partition {
    use super::*;
    use crate::console::{ConsoleOpener, ConsoleStream};
    use futures_util::future::BoxFuture;
    use std::time::Duration;

    struct NoConsoles;
    impl ConsoleOpener for NoConsoles {
        fn open<'a>(&'a self, _: &'a str, _: omnuv_protocol::ConsoleKind) -> BoxFuture<'a, anyhow::Result<ConsoleStream>> {
            Box::pin(async { anyhow::bail!("no consoles here") })
        }
    }

    /// The agent's side: connects, serves until the connection ends, and
    /// reports how long that took and whether it ended in an error.
    fn run(
        core: impl Fn() -> BoxFuture<'static, turmoil::Result> + 'static,
        keepalive: Keepalive,
    ) -> (Duration, Result<(), String>) {
        let mut sim = turmoil::Builder::new().simulation_duration(Duration::from_secs(1200)).build();
        sim.host("core", core);
        let (told, heard) = std::sync::mpsc::channel();
        sim.client("agent", async move {
            let tcp = turmoil::net::TcpStream::connect("core:443").await?;
            let (ws, _) = tokio_tungstenite::client_async("ws://core/provider/v1/tunnel", tcp).await?;
            let started = tokio::time::Instant::now();
            let ended = tokio::time::timeout(
                Duration::from_secs(900),
                serve_socket(
                    ws,
                    Arc::new(|_: &str| None),
                    Arc::new(tokio::sync::Notify::new()),
                    Arc::new(NoConsoles),
                    Tables::default(),
                    keepalive,
                ),
            )
            .await;
            let _ = told.send((started.elapsed(), match ended {
                Ok(r) => r.map_err(|e| e.to_string()),
                Err(_) => Err("still serving after 900 s".to_string()),
            }));
            Ok(())
        });
        sim.run().unwrap();
        heard.try_recv().expect("the agent never reported")
    }

    /// Accepts the agent, then answers each Ping with a Pong for `answer_for`
    /// and afterwards is cut off from it with nothing closed.
    fn core(answer_for: Duration, then_close: bool) -> impl Fn() -> BoxFuture<'static, turmoil::Result> {
        move || {
            Box::pin(async move {
                let listener = turmoil::net::TcpListener::bind("0.0.0.0:443").await?;
                let (tcp, _) = listener.accept().await?;
                let mut ws = tokio_tungstenite::accept_async(tcp).await?;
                let until = tokio::time::Instant::now() + answer_for;
                while let Ok(Some(Ok(m))) = tokio::time::timeout_at(until, ws.next()).await {
                    if matches!(serde_json::from_str::<TunnelFrame>(&m.to_string()), Ok(TunnelFrame::Ping)) {
                        ws.send(Message::text(serde_json::to_string(&TunnelFrame::Pong)?)).await?;
                    }
                }
                if then_close {
                    ws.close(None).await?;
                    return Ok(());
                }
                turmoil::partition("core", "agent");
                tokio::time::sleep(Duration::from_secs(1100)).await;
                Ok(())
            })
        }
    }

    /// **A Core that goes silent is left, so the agent can reconnect.**
    /// Before this, the agent waited on the dead link for as long as the
    /// simulation ran.
    #[test]
    fn a_silent_core_is_left_within_a_minute_and_a_half() {
        let (after, ended) = run(core(Duration::from_secs(30), false), Keepalive::default());
        assert!(ended.is_err(), "the agent did not leave a silent Core: {ended:?} after {after:?}");
        assert!(after <= Duration::from_secs(120), "it took {after:?}");
    }

    /// **The silence and the ping are the agent's file's to set**
    /// (`timings.tunnelSilence`, `timings.tunnelPing`; constants until 26
    /// September 2026). Pinging every 10 s and leaving after 30 s of silence,
    /// a Core cut off after 30 s of answers is left at about 50 s; the default
    /// minute, measured beside it, leaves at about 80.
    #[test]
    fn a_configured_silence_is_the_one_kept() {
        let quick = Keepalive { ping: Duration::from_secs(10), silence: Duration::from_secs(30) };
        let (after, ended) = run(core(Duration::from_secs(30), false), quick);
        assert!(ended.is_err(), "the agent did not leave a silent Core: {ended:?} after {after:?}");
        assert!(after <= Duration::from_secs(65), "a 30 s silence took {after:?}");
        let (after, _) = run(core(Duration::from_secs(30), false), Keepalive::default());
        assert!(after > Duration::from_secs(65), "the default silence is not a minute: {after:?}");
    }

    /// The control: a Core that answers every ping for five minutes is kept,
    /// and a close ends the connection cleanly.
    #[test]
    fn a_core_that_answers_is_kept() {
        let (after, ended) = run(core(Duration::from_secs(300), true), Keepalive::default());
        assert!(ended.is_ok(), "a healthy connection ended in an error: {ended:?}");
        // The two clocks start a handshake apart; the point is "well past a minute".
        assert!(after >= Duration::from_secs(290), "it ended early: {after:?}");
    }
}
