//! **The floor every agent crate stands on**: the names every resource on a
//! provider carries, how a time is written, the timings in force, the lock
//! that survives a poisoned holder, and the audit sink.
//!
//! Moved out of the agent's crate with no behaviour change (omnuv's modular
//! design, work package A1b). The agent imports each module under the name it
//! always had, so `crate::names` and the rest still resolve there.

pub mod audit;
pub mod dur;
pub mod lease_token;
pub mod names;
pub mod poison;
pub mod run_lease;
pub mod secrets;
pub mod timings;
pub mod workload_config;
