//! The provider driver boundary.
//!
//! CLAUDE.md requires runtime branching to live behind this interface rather
//! than in marketplace logic, and requires third parties to be able to add a
//! runtime without access to Omnu Core. The trait therefore carries only the
//! operations that are actually implemented; KubeVirt and OpenStack will
//! implement the same shape, and lifecycle methods land here in the phase that
//! builds them rather than as unimplemented stubs today.

use omnu_protocol::{InventoryReport, RuntimeKind};

pub trait ComputeDriver {
    fn kind(&self) -> RuntimeKind;

    /// Normalized capabilities and marketplace-allocatable inventory.
    fn inventory(
        &self,
    ) -> impl std::future::Future<Output = anyhow::Result<InventoryReport>> + Send;
}
