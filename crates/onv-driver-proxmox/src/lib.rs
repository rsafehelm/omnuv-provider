//! **The Proxmox driver's parts that stand alone**: the driver trait, the
//! pending-clone journal, the reboot and password records, the snippet sweep,
//! and the streaming machine's device list.
//!
//! Moved out of the agent's crate with no behaviour change (omnuv's modular
//! design, work package A1b). The client and its lifecycle (`proxmox`,
//! `instance`, `worker`, `teardown`) form one cycle with the agent and stay
//! there until it is broken; that is not a move. The one part of it two
//! binaries share, a leased machine's stop, is here over a trait the client
//! answers (`leased`, A3).

pub mod driver;
pub mod leased;
pub mod passwords;
pub mod pending;
pub mod reboots;
pub mod snippets;
pub mod stream_devices;
