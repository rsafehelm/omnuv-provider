//! Console access to a machine, out of band.
//!
//! The hypervisor's own console — serial for machines that log in on a tty,
//! VNC for ones that need a screen — bridged to the tunnel so Core can stream
//! it to the buyer's browser. It works when the machine's network does not,
//! and nothing runs in the guest for it.
//!
//! On Proxmox the serial console is `termproxy` behind the API's websocket
//! endpoint, reached over the node's own loopback with the agent's token: the
//! bytes never touch the buyer's network or the provider's LAN. The token can
//! open a console only on machines in the buyer pool (`VM.Console` is granted
//! there and nowhere else), so a provider's own machines are out of reach by
//! construction.

use std::sync::Arc;

use futures_util::future::BoxFuture;
use futures_util::{SinkExt, StreamExt};
use omnuv_protocol::ConsoleKind;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::audit;
use crate::proxmox::Client;

const NO_FORM: &[(String, String)] = &[];

/// What a buyer's terminal sends toward the machine.
#[derive(Debug)]
pub enum ConsoleInput {
    Data(Vec<u8>),
    Resize { cols: u16, rows: u16 },
}

/// An open console: bytes to the machine, bytes from it. Dropping `to_vm`
/// ends the session.
pub struct ConsoleStream {
    pub to_vm: mpsc::Sender<ConsoleInput>,
    pub from_vm: mpsc::Receiver<Vec<u8>>,
    /// A secret the viewer authenticates with inside the protocol (VNC), for
    /// this session only.
    pub credential: Option<omnuv_protocol::Redacted>,
}

/// The runtime-neutral face of a console, so the tunnel never sees the
/// hypervisor. KubeVirt and OpenStack implement the same shape.
pub trait ConsoleOpener: Send + Sync {
    fn open<'a>(
        &'a self,
        instance_id: &'a str,
        kind: ConsoleKind,
    ) -> BoxFuture<'a, anyhow::Result<ConsoleStream>>;
}

#[derive(serde::Deserialize)]
struct TermProxy {
    port: serde_json::Value,
    /// One session's authorization to the hypervisor, spent twice below: once
    /// in the websocket URL and once in the login line. Redacted because these
    /// two structs are `Deserialize`-only today by nobody's decision — there
    /// was no rule keeping `Debug` off them, only the fact that no one had
    /// needed it yet.
    ticket: omnuv_protocol::Redacted,
    user: String,
}

#[derive(serde::Deserialize)]
struct VncProxy {
    port: serde_json::Value,
    ticket: omnuv_protocol::Redacted,
    /// The VNC password the hypervisor minted for this proxy session.
    #[serde(default)]
    password: Option<omnuv_protocol::Redacted>,
}

impl Client {
    pub async fn open_console(
        &self,
        instance_id: &str,
        kind: ConsoleKind,
    ) -> anyhow::Result<ConsoleStream> {
        // **Wherever the machine is (PROVIDER-7).** This asked the configured
        // node alone, so with no node configured — which documents itself as
        // "the whole cluster" — every console asked `/nodes//qemu` and failed,
        // and on a cluster a machine on any other host had no console at all.
        let Some((node, vm)) = self
            .find_tagged_vm_anywhere(crate::instance::TAG, &crate::instance::short_tag(instance_id))
            .await?
        else {
            anyhow::bail!("no such machine on this provider");
        };
        let node = node.as_str();
        // Live, from the node: the cluster-wide listing lags by seconds, and a
        // console refused for a machine that has just started reads as broken.
        let status: serde_json::Value =
            self.get_json(&format!("/nodes/{node}/qemu/{}/status/current", vm.vmid)).await?;
        if status.get("status").and_then(|s| s.as_str()) != Some("running") {
            anyhow::bail!("the machine is not running");
        }

        if kind == ConsoleKind::Vnc {
            return self.open_vnc(node, instance_id, vm.vmid).await;
        }
        // One ticket, one websocket: the ticket is only good for this machine's
        // console and only briefly.
        let tp: TermProxy =
            self.post_form(&format!("/nodes/{node}/qemu/{}/termproxy", vm.vmid), NO_FORM).await?;
        let port = tp.port.as_str().map(str::to_string).unwrap_or_else(|| tp.port.to_string());
        let host = self.base.split("://").nth(1).unwrap_or(&self.base);
        let url = format!(
            "wss://{host}/api2/json/nodes/{node}/qemu/{}/vncwebsocket?port={}&vncticket={}",
            vm.vmid,
            urlencode(&port),
            urlencode(tp.ticket.expose())
        );
        let mut request = url.into_client_request()?;
        request.headers_mut().insert("authorization", self.auth.expose().parse()?);
        request.headers_mut().insert("sec-websocket-protocol", "binary".parse()?);
        let connector = tokio_tungstenite::Connector::Rustls(self.tls.clone());
        let (socket, _) =
            tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector))
                .await
                .map_err(|e| anyhow::anyhow!("console websocket: {e}"))?;
        let (mut sink, mut stream) = socket.split();

        // termproxy's handshake: `user:ticket`, answered with "OK" and then
        // the terminal's bytes.
        sink.send(Message::text(format!("{}:{}\n", tp.user, tp.ticket.expose()))).await?;
        let first = tokio::time::timeout(std::time::Duration::from_secs(10), stream.next())
            .await
            .map_err(|_| anyhow::anyhow!("console did not answer"))?
            .ok_or_else(|| anyhow::anyhow!("console closed during handshake"))??
            .into_data();
        if !first.starts_with(b"OK") {
            anyhow::bail!("console refused the ticket");
        }

        let (to_vm, mut input) = mpsc::channel::<ConsoleInput>(64);
        let (output, from_vm) = mpsc::channel::<Vec<u8>>(256);
        if first.len() > 2 {
            let _ = output.send(first[2..].to_vec()).await;
        }
        audit::record("console.open", "core", instance_id, "ok", Some(&format!("vmid={}", vm.vmid)));

        let id = instance_id.to_string();
        tokio::spawn(async move {
            // termproxy drops a session it has not heard from; the same
            // interval the hypervisor's own console uses.
            let mut ping = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                tokio::select! {
                    msg = stream.next() => match msg {
                        Some(Ok(Message::Binary(b))) => {
                            if output.send(b.to_vec()).await.is_err() { break }
                        }
                        Some(Ok(Message::Text(t))) => {
                            if output.send(t.as_bytes().to_vec()).await.is_err() { break }
                        }
                        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                        Some(Ok(_)) => {}
                    },
                    next = input.recv() => match next {
                        // termproxy's framing: `0:<len>:<bytes>` for input,
                        // `1:<cols>:<rows>:` for a resize.
                        Some(ConsoleInput::Data(d)) => {
                            let mut m = format!("0:{}:", d.len()).into_bytes();
                            m.extend_from_slice(&d);
                            if sink.send(Message::binary(m)).await.is_err() { break }
                        }
                        Some(ConsoleInput::Resize { cols, rows }) => {
                            if sink.send(Message::text(format!("1:{cols}:{rows}:"))).await.is_err() { break }
                        }
                        // Core let go of the session.
                        None => break,
                    },
                    _ = ping.tick() => {
                        if sink.send(Message::text("2")).await.is_err() { break }
                    }
                }
            }
            let _ = sink.close().await;
            audit::record("console.close", "core", &id, "ok", None);
        });

        Ok(ConsoleStream { to_vm, from_vm, credential: None })
    }

    /// The machine's screen: the hypervisor's VNC server behind the same API
    /// websocket, as a raw RFB stream. The viewer speaks RFB itself and
    /// authenticates with the password the hypervisor minted for this session.
    async fn open_vnc(&self, node: &str, instance_id: &str, vmid: u32) -> anyhow::Result<ConsoleStream> {
        let vp: VncProxy = self
            .post_form(&format!("/nodes/{node}/qemu/{vmid}/vncproxy"), &[("websocket".to_string(), "1".to_string())])
            .await?;
        let port = vp.port.as_str().map(str::to_string).unwrap_or_else(|| vp.port.to_string());
        let host = self.base.split("://").nth(1).unwrap_or(&self.base);
        let url = format!(
            "wss://{host}/api2/json/nodes/{node}/qemu/{vmid}/vncwebsocket?port={}&vncticket={}",
            urlencode(&port),
            urlencode(vp.ticket.expose())
        );
        let mut request = url.into_client_request()?;
        request.headers_mut().insert("authorization", self.auth.expose().parse()?);
        request.headers_mut().insert("sec-websocket-protocol", "binary".parse()?);
        let connector = tokio_tungstenite::Connector::Rustls(self.tls.clone());
        let (socket, _) =
            tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector))
                .await
                .map_err(|e| anyhow::anyhow!("screen websocket: {e}"))?;
        let (mut sink, mut stream) = socket.split();

        let (to_vm, mut input) = mpsc::channel::<ConsoleInput>(64);
        let (output, from_vm) = mpsc::channel::<Vec<u8>>(256);
        audit::record("console.open", "core", instance_id, "ok", Some(&format!("vmid={vmid} kind=vnc")));

        let id = instance_id.to_string();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = stream.next() => match msg {
                        Some(Ok(Message::Binary(b))) => {
                            if output.send(b.to_vec()).await.is_err() { break }
                        }
                        Some(Ok(Message::Text(t))) => {
                            if output.send(t.as_bytes().to_vec()).await.is_err() { break }
                        }
                        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                        Some(Ok(_)) => {}
                    },
                    next = input.recv() => match next {
                        // Raw RFB both ways; the viewer owns the protocol.
                        Some(ConsoleInput::Data(d)) => {
                            if sink.send(Message::binary(d)).await.is_err() { break }
                        }
                        Some(ConsoleInput::Resize { .. }) => {}
                        None => break,
                    },
                }
            }
            let _ = sink.close().await;
            audit::record("console.close", "core", &id, "ok", Some("kind=vnc"));
        });

        Ok(ConsoleStream { to_vm, from_vm, credential: vp.password })
    }
}

/// The driver's consoles, handed to the tunnel as the runtime-neutral opener.
pub struct DriverConsoles {
    pub driver: Arc<Client>,
}

impl ConsoleOpener for DriverConsoles {
    fn open<'a>(
        &'a self,
        instance_id: &'a str,
        kind: ConsoleKind,
    ) -> BoxFuture<'a, anyhow::Result<ConsoleStream>> {
        Box::pin(self.driver.open_console(instance_id, kind))
    }
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn encodes_ticket_characters() {
        // A VNC ticket carries ':' and base64 ('+', '/', '='), all of which
        // must survive the query string.
        assert_eq!(super::urlencode("PVEVNC:ab/c+d=="), "PVEVNC%3Aab%2Fc%2Bd%3D%3D");
    }
}
