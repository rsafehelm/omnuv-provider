//! A machine's address on its segment: written into its first boot, and
//! read by the agent's `names` (`SEGMENT_RANGE` is there).

/// A machine's address on its project's segment on this provider.
///
/// Keyed on the VMID because that is what the hypervisor guarantees unique, and
/// uniqueness is only needed within one segment. `.0` and `.255` are skipped so
/// the result is always a usable host address.
pub fn segment_address(vmid: u32) -> String {
    let host = vmid % 254 + 1;
    let third = (vmid / 254) % 256;
    format!("10.216.{third}.{host}")
}
