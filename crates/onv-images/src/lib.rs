//! **The image store's rules**: an artefact's file and volume names, its
//! digest and where a template records it, the template's shape, and which
//! catalogue entries are still owed.
//!
//! Moved out of the agent's crate with no behaviour change (omnuv's modular
//! design, work package A1b). Tagging, reading and importing templates speak
//! to Proxmox and stay in the agent's `images`.

pub mod images;
