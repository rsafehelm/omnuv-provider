//! **The agent's tunnel to Core**: consoles and inference relayed over one
//! websocket, and the runtime-neutral face of a console it holds.
//!
//! Moved out of the agent's crate with no behaviour change (omnuv's modular
//! design, work package A1b). The Proxmox consoles behind `ConsoleOpener` stay
//! with the driver in the agent.

pub mod console;
pub mod tunnel;
