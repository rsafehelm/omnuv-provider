//! The provider driver boundary.
//!
//! CLAUDE.md requires runtime branching to live behind this interface rather
//! than in marketplace logic, and requires third parties to be able to add a
//! runtime without access to Omnuv Core. The trait therefore carries only the
//! operations that are actually implemented; KubeVirt and OpenStack will
//! implement the same shape, and lifecycle methods land here in the phase that
//! builds them rather than as unimplemented stubs today.

use omnuv_protocol::{DesiredState, InventoryReport, RuntimeKind};

pub trait ComputeDriver {
    fn kind(&self) -> RuntimeKind;

    /// Normalized physical supply after excluding foreign claims. Current
    /// authenticated desired state accounts for devices already allocated by
    /// Core, so those stay in inventory without becoming newly available.
    fn inventory(
        &self,
        desired: &DesiredState,
    ) -> impl std::future::Future<Output = anyhow::Result<InventoryReport>> + Send;
}

/// A shared driver is still the driver: the agent hands one `Arc` to the
/// tunnel (for consoles) and keeps using it for everything else.
impl<T: ComputeDriver + Sync> ComputeDriver for std::sync::Arc<T> {
    fn kind(&self) -> RuntimeKind {
        (**self).kind()
    }

    fn inventory(
        &self,
        desired: &DesiredState,
    ) -> impl std::future::Future<Output = anyhow::Result<InventoryReport>> + Send {
        (**self).inventory(desired)
    }
}
