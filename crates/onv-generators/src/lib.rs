//! **What a machine's first boot reads**, rendered: a Linux machine's
//! cloud-config and network config, a Windows machine's cloudbase-init
//! user-data and meta-data, the provider opening's `netbird up`, and the
//! scripts and units they carry (`guest/`).
//!
//! Pure: nothing here speaks to Proxmox, to Core or to a disk. Every byte is a
//! contract with every machine already built, since a byte that moves is a
//! drive refreshed, so the output is pinned by golden files at the workspace
//! root (`tests/linux/`, `tests/windows/`) and checked by `tests/goldens.rs`.
//!
//! Moved out of the agent's crate with no behaviour change (omnuv's modular
//! design, work package A1): the agent re-exports each module under the name
//! it always had.

pub mod linux;
pub mod opening;
pub mod segment;
pub mod windows;
