//! **The agent's link to Core**: the TLS it speaks, the session it holds,
//! the report period Core sets, restore mode, and the install watch.
//!
//! Moved out of the agent's crate with no behaviour change (omnuv's modular
//! design, work package A1b). The Core client itself (`agent::Core`) carries
//! other modules' state on every call and stays in the agent until that is
//! untangled; the handshake's capability list stays in the agent's `session`.

pub mod installwatch;
pub mod report;
pub mod restore;
pub mod session;
pub mod supervise;
pub mod tls;
