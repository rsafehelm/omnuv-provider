//! **The host's network**: the provider opening (its configuration, its book
//! of ports, its nftables rules and their applier) and the bridge's
//! neighbours.
//!
//! Moved out of the agent's crate with no behaviour change (omnuv's modular
//! design, work package A1b), with the SDN segments' names and choice. The
//! SDN calls are methods on the Proxmox client and stay with it; the one egress
//! policy is later work, not a move.

pub mod neighbours;
pub mod opening;
pub mod sdn;
