//! **Pairing by certificate, the agent's half** (omnuv's
//! docs/plans/pairing-by-certificate.md, phase 3; protocol v0.27.0; the
//! operator's P-1, 5 October 2026: the agent writes Sunshine's paired list at
//! the buyer's request).
//!
//! Core sends each streaming machine the devices allowed to stream from it, by
//! certificate. The agent hands that list to the machine as one file, and the
//! machine's own converger (installed by its recipe) writes it into Sunshine's
//! paired list and restarts Sunshine only while no client streams. The machine
//! writes back what Sunshine is and which devices it admits; the agent reads
//! that file and reports it. Two known paths, a write and a read: nothing runs
//! inside the buyer's machine at the agent's word.
use omnuv_protocol::{StreamDevice, StreamIdentity};

/// Where the converger reads the list and writes the identity, by guest kind.
pub const LINUX_DEVICES: &str = "/etc/onv/stream-devices.json";
pub const LINUX_IDENTITY: &str = "/etc/onv/stream-identity.json";
pub const WINDOWS_DEVICES: &str = r"C:\ProgramData\onv\stream-devices.json";
pub const WINDOWS_IDENTITY: &str = r"C:\ProgramData\onv\stream-identity.json";

/// The list as the converger reads it: devices sorted by id, so the same set
/// is always the same bytes and an unchanged list is never written again.
pub fn desired_file(devices: &[StreamDevice]) -> String {
    let mut sorted: Vec<&StreamDevice> = devices.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    let list: Vec<serde_json::Value> = sorted
        .iter()
        .map(|d| serde_json::json!({ "id": d.id, "certificate": d.certificate }))
        .collect();
    serde_json::json!({ "devices": list }).to_string()
}

/// The identity the converger wrote, or None for anything that is not one: a
/// machine whose Sunshine has not minted its certificate yet writes nothing,
/// and a file without an id or a certificate is not reported as one.
pub fn identity_from(raw: &str) -> Option<StreamIdentity> {
    let seen: StreamIdentity =
        serde_json::from_str(raw.trim_start_matches('\u{feff}').trim()).ok()?;
    (!seen.unique_id.trim().is_empty() && seen.certificate.contains("BEGIN CERTIFICATE"))
        .then_some(seen)
}

/// The machine does not yet admit exactly the devices Core sent it: the
/// agent looks again soon (`installwatch::STREAM_MAX`). No list from Core is
/// nothing to wait for; an identity not read yet is still waiting.
pub fn pending(want: Option<&[StreamDevice]>, seen: Option<&StreamIdentity>) -> bool {
    let Some(want) = want else { return false };
    let mut want: Vec<&str> = want.iter().map(|d| d.id.as_str()).collect();
    want.sort_unstable();
    let mut got: Vec<&str> = seen.map(|s| s.devices.iter().map(String::as_str).collect()).unwrap_or_default();
    got.sort_unstable();
    seen.is_none() || want != got
}
