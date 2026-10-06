//! **A GPU card's scrub, as data**: what Core wants scrubbed, what the scrub
//! guest reports, what one look at it concludes, and the wire Core answers on.
//!
//! Moved out of the agent's crate with no behaviour change (omnuv's modular
//! design, work package A1b). The guest's lifecycle (clone, start, read,
//! remove) is methods on the Proxmox client and stays in the agent's `scrub`.

pub mod scrub;
