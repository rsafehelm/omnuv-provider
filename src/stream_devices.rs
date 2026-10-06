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
pub(crate) const LINUX_DEVICES: &str = "/etc/onv/stream-devices.json";
pub(crate) const LINUX_IDENTITY: &str = "/etc/onv/stream-identity.json";
pub(crate) const WINDOWS_DEVICES: &str = r"C:\ProgramData\onv\stream-devices.json";
pub(crate) const WINDOWS_IDENTITY: &str = r"C:\ProgramData\onv\stream-identity.json";

/// The list as the converger reads it: devices sorted by id, so the same set
/// is always the same bytes and an unchanged list is never written again.
pub(crate) fn desired_file(devices: &[StreamDevice]) -> String {
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
pub(crate) fn identity_from(raw: &str) -> Option<StreamIdentity> {
    let seen: StreamIdentity =
        serde_json::from_str(raw.trim_start_matches('\u{feff}').trim()).ok()?;
    (!seen.unique_id.trim().is_empty() && seen.certificate.contains("BEGIN CERTIFICATE"))
        .then_some(seen)
}

/// The machine does not yet admit exactly the devices Core sent it: the
/// agent looks again soon (`installwatch::STREAM_MAX`). No list from Core is
/// nothing to wait for; an identity not read yet is still waiting.
pub(crate) fn pending(want: Option<&[StreamDevice]>, seen: Option<&StreamIdentity>) -> bool {
    let Some(want) = want else { return false };
    let mut want: Vec<&str> = want.iter().map(|d| d.id.as_str()).collect();
    want.sort_unstable();
    let mut got: Vec<&str> = seen.map(|s| s.devices.iter().map(String::as_str).collect()).unwrap_or_default();
    got.sort_unstable();
    seen.is_none() || want != got
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(id: &str) -> StreamDevice {
        StreamDevice {
            id: id.into(),
            certificate: format!("-----BEGIN CERTIFICATE-----\n{id}\n-----END CERTIFICATE-----\n"),
        }
    }

    #[test]
    fn the_same_set_is_the_same_bytes_in_any_order() {
        let a = desired_file(&[device("b"), device("a")]);
        let b = desired_file(&[device("a"), device("b")]);
        assert_eq!(a, b);
        let v: serde_json::Value = serde_json::from_str(&a).unwrap();
        assert_eq!(v["devices"][0]["id"], "a");
        assert_eq!(
            desired_file(&[]),
            r#"{"devices":[]}"#,
            "an empty list is written, so entries are removed"
        );
    }

    fn spec(windows: bool, devices: Option<Vec<StreamDevice>>) -> omnuv_protocol::InstanceSpec {
        let desired: serde_json::Value =
            serde_json::from_str(include_str!("../tests/from-core/desired-state.json")).unwrap();
        let mut s: omnuv_protocol::InstanceSpec =
            serde_json::from_value(desired["instances"][0].clone()).unwrap();
        if windows {
            s.image = omnuv_protocol::ImageSpec {
                id: "windows-11-gaming".into(),
                os_family: omnuv_protocol::OsFamily::Windows,
                first_boot: omnuv_protocol::FirstBoot::CloudbaseInit,
                default_user: "omnuv".into(),
                auth_mode: omnuv_protocol::AuthMode::SshKey,
            };
        }
        s.stream_devices = devices;
        s
    }

    /// The list is written where the guest's converger reads it only when the
    /// guest holds something else, the identity is read back, and a Windows
    /// machine is asked at its own paths. Fixtures: a Proxmox that remembers.
    #[tokio::test]
    async fn the_list_is_written_once_and_the_identity_read_back() {
        use std::sync::{Arc, Mutex};
        let identity = r#"{"unique_id":"U1","certificate":"-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n","devices":["a"]}"#;
        for windows in [false, true] {
            let (devices_path, identity_path) = if windows {
                (WINDOWS_DEVICES, WINDOWS_IDENTITY)
            } else {
                (LINUX_DEVICES, LINUX_IDENTITY)
            };
            let files: Arc<Mutex<std::collections::HashMap<String, String>>> = Arc::default();
            files
                .lock()
                .unwrap()
                .insert(identity_path.to_string(), identity.to_string());
            let held = files.clone();
            let mock = crate::pvemock::Mock::start(move |method, path, body| {
                let q = |p: &str| crate::proxmox::urlencode(p).replace("%2F", "/");
                if method == "GET" && path.contains("/agent/file-read?file=") {
                    let asked = path.split("file=").nth(1).unwrap().to_string();
                    let found = held
                        .lock()
                        .unwrap()
                        .iter()
                        .find(|(k, _)| q(k) == asked)
                        .map(|(_, v)| v.clone());
                    return match found {
                        Some(content) => (200, serde_json::json!({ "content": content })),
                        None => (500, serde_json::Value::Null),
                    };
                }
                if method == "POST" && path.ends_with("/agent/file-write") {
                    let form: std::collections::HashMap<String, String> =
                        reqwest::Url::parse(&format!("http://x/?{body}"))
                            .unwrap()
                            .query_pairs()
                            .into_owned()
                            .collect();
                    held.lock()
                        .unwrap()
                        .insert(form["file"].clone(), form["content"].clone());
                    return (200, serde_json::Value::Null);
                }
                (404, serde_json::Value::Null)
            })
            .await;
            let s = spec(windows, Some(vec![device("b"), device("a")]));
            let seen = mock
                .client()
                .stream_identity("n1", 700, &s)
                .await
                .expect("the identity");
            assert_eq!(seen.unique_id, "U1");
            assert_eq!(
                files.lock().unwrap().get(devices_path).cloned(),
                Some(desired_file(&s.stream_devices.clone().unwrap()))
            );
            // The same list again writes nothing.
            mock.client().stream_identity("n1", 700, &s).await;
            let writes = mock
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.path.ends_with("/agent/file-write"))
                .count();
            assert_eq!(
                writes, 1,
                "windows={windows}: an unchanged list was written again"
            );
            // No list from Core: nothing is written, the identity is still read.
            let quiet = spec(windows, None);
            assert!(
                mock.client()
                    .stream_identity("n1", 700, &quiet)
                    .await
                    .is_some()
            );
            let writes = mock
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.path.ends_with("/agent/file-write"))
                .count();
            assert_eq!(writes, 1);
        }
    }

    #[test]
    fn pending_until_the_machine_admits_exactly_what_was_sent() {
        let seen = |devices: &[&str]| StreamIdentity {
            unique_id: "U".into(),
            certificate: "C".into(),
            devices: devices.iter().map(|d| d.to_string()).collect(),
        };
        let sent = [device("b"), device("a")];
        assert!(!pending(None, Some(&seen(&["a"]))), "nothing sent is nothing to wait for");
        assert!(pending(Some(&sent), None), "an identity not read yet is not applied");
        assert!(pending(Some(&sent), Some(&seen(&["a"]))));
        assert!(!pending(Some(&sent), Some(&seen(&["a", "b"]))));
        assert!(!pending(Some(&sent), Some(&seen(&["b", "a"]))), "order is not a difference");
        assert!(pending(Some(&[]), Some(&seen(&["a"]))), "a revoked device still admitted");
        assert!(!pending(Some(&[]), Some(&seen(&[]))));
    }

    #[test]
    fn only_a_whole_identity_is_reported() {
        let whole = r#"{"unique_id":"E014F010","certificate":"-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n","devices":["d1"]}"#;
        let seen = identity_from(whole).expect("an identity");
        assert_eq!(
            (seen.unique_id.as_str(), seen.devices.as_slice()),
            ("E014F010", ["d1".to_string()].as_slice())
        );
        // PowerShell's UTF-8 with a byte-order mark reads the same.
        assert!(identity_from(&format!("\u{feff}{whole}")).is_some());
        for broken in [
            "",
            "{}",
            r#"{"unique_id":"","certificate":"-----BEGIN CERTIFICATE-----"}"#,
            r#"{"unique_id":"U","certificate":"nothing"}"#,
            "not json",
        ] {
            assert!(identity_from(broken).is_none(), "{broken:?} was reported");
        }
    }
}
