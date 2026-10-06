//! **The runtime-neutral face of a console**: what the tunnel holds, so it
//! never sees the hypervisor. The Proxmox side (termproxy, vncproxy and the
//! driver's opener) stays with the driver in the agent's `console` module.
//!
//! Moved out of the agent's `console.rs` with no behaviour change (omnuv's
//! modular design, work package A1b).

use futures_util::future::BoxFuture;
use omnuv_protocol::ConsoleKind;
use tokio::sync::mpsc;

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
