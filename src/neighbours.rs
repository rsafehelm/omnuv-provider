//! What the host has actually seen on its own bridges.
//!
//! Until this existed, Core knew a machine's address because the agent asked
//! the *guest* for it, through the guest agent, and passed it on — `source:
//! reported`, `observed: never`. The console's own footnote had to admit what
//! that was worth: an address being listed "means the ledger holds it, not that
//! a packet has ever crossed it".
//!
//! The host knows better and is never asked. Its neighbour table is the record
//! of which addresses have answered on which bridge, and consulting it:
//!
//! - costs one file read per reconcile, no API call and no guest round trip,
//! - needs no guest agent, so it still works on a machine whose agent is dead
//!   or was never installed — which is exactly when somebody wants to know
//!   whether a machine is on the network at all,
//! - and *discovers* the address rather than believing one, because the match
//!   is made on the MAC the hypervisor configured, which the guest cannot lie
//!   about without losing its own traffic.
//!
//! **What it does not give is a precise age.** `/proc/net/arp` has no
//! timestamp. A complete entry means the kernel currently holds a resolved
//! neighbour, and the kernel expires those, so it means *recently* — not this
//! instant. Saying "recently" honestly is worth more than a precise number that
//! came from somewhere else.

use omnuv_protocol::AdapterStatus;
use std::collections::HashMap;

/// `0x2` is `ATF_COM`: the entry resolved to a hardware address. An incomplete
/// entry is the kernel having *asked* and not been answered, which is the
/// opposite of an observation and must never be read as one.
const ATF_COM: u32 = 0x2;

/// Address and bridge, keyed by the MAC the host resolved them to.
#[derive(Debug, Default, Clone)]
pub(crate) struct Neighbours(HashMap<String, (String, String)>);

impl Neighbours {
    /// Read the host's table. A host that cannot be read yields an empty table,
    /// which reports nothing as observed — the safe direction. Claiming an
    /// address works because we failed to check is how a blind spot becomes a
    /// wrong answer.
    pub(crate) fn read() -> Self {
        std::fs::read_to_string("/proc/net/arp").map(|s| Self::parse(&s)).unwrap_or_default()
    }

    pub(crate) fn parse(table: &str) -> Self {
        let mut out = HashMap::new();
        for line in table.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            // IP, HW type, Flags, HW address, Mask, Device
            let [ip, _hw, flags, mac, _mask, device] = f[..] else { continue };
            let Ok(flags) = u32::from_str_radix(flags.trim_start_matches("0x"), 16) else {
                continue;
            };
            if flags & ATF_COM == 0 {
                continue;
            }
            out.insert(normalise(mac), (ip.to_string(), device.to_string()));
        }
        Self(out)
    }

    pub(crate) fn get(&self, mac: &str) -> Option<&(String, String)> {
        self.0.get(&normalise(mac))
    }
}

fn normalise(mac: &str) -> String {
    mac.trim().to_ascii_lowercase()
}

/// Every `netN` on a machine, with the address the host has seen behind it.
///
/// `believed` is what the guest agent said, if anything. It is kept as a
/// fallback so an adapter still reports an address on a host whose neighbour
/// table has aged the entry out — but only the neighbour table sets
/// `observed_at_unix`, because only the neighbour table is evidence.
pub(crate) fn adapters(
    config: &serde_json::Value,
    seen: &Neighbours,
    believed: Option<&str>,
    now: u64,
) -> Vec<AdapterStatus> {
    let Some(map) = config.as_object() else { return Vec::new() };
    let mut out: Vec<AdapterStatus> = Vec::new();
    for (key, value) in map {
        if !key.starts_with("net") || !key[3..].chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Some(raw) = value.as_str() else { continue };
        let Some(mac) = mac_of(raw) else { continue };
        let hit = seen.get(&mac);
        out.push(AdapterStatus {
            name: key.clone(),
            address: hit
                .map(|(ip, _)| ip.clone())
                // Only one adapter can claim the believed address, and the
                // guest agent reports the machine's primary. Attaching it to
                // every NIC would invent addresses.
                .or_else(|| believed.filter(|_| out.is_empty()).map(str::to_string)),
            mac: Some(mac),
            observed_at_unix: hit.map(|_| now),
            observed_by: hit.map(|_| "neighbour".to_string()),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// `virtio=BC:24:11:3A:4B:5C,bridge=vmbr0,firewall=1` — the model is whatever
/// the hypervisor chose and is not worth enumerating; the MAC is the first
/// value, whichever model name precedes it.
fn mac_of(raw: &str) -> Option<String> {
    let first = raw.split(',').next()?;
    let mac = first.split('=').nth(1)?;
    (mac.matches(':').count() == 5).then(|| normalise(mac))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "IP address       HW type     Flags       HW address            Mask     Device
192.168.100.103  0x1         0x2         bc:24:11:3a:4b:5c     *        vmbr0
10.200.99.5      0x1         0x2         BC:24:11:00:00:01     *        omnuvbr1
10.200.99.9      0x1         0x0         00:00:00:00:00:00     *        omnuvbr1
";

    fn cfg(v: serde_json::Value) -> serde_json::Value {
        v
    }

    #[test]
    fn an_unanswered_arp_is_not_an_observation() {
        let n = Neighbours::parse(TABLE);
        // .9 is in the table, flagged incomplete: the kernel asked and nothing
        // replied. That is the opposite of evidence.
        assert!(n.get("00:00:00:00:00:00").is_none());
        assert!(n.get("bc:24:11:3a:4b:5c").is_some());
    }

    #[test]
    fn the_case_of_a_mac_does_not_decide_whether_we_saw_it() {
        // Proxmox writes them upper, the kernel writes them lower.
        let n = Neighbours::parse(TABLE);
        assert_eq!(n.get("BC:24:11:3A:4B:5C").map(|(ip, _)| ip.as_str()), Some("192.168.100.103"));
        assert_eq!(n.get("bc:24:11:00:00:01").map(|(ip, _)| ip.as_str()), Some("10.200.99.5"));
    }

    #[test]
    fn an_address_the_host_has_answered_is_observed() {
        let n = Neighbours::parse(TABLE);
        let a = adapters(
            &cfg(serde_json::json!({ "net1": "virtio=BC:24:11:00:00:01,bridge=omnuvbr1" })),
            &n,
            None,
            42,
        );
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].address.as_deref(), Some("10.200.99.5"));
        assert_eq!(a[0].observed_at_unix, Some(42));
        assert_eq!(a[0].observed_by.as_deref(), Some("neighbour"));
    }

    /// The distinction the whole module exists for: an address we were told
    /// about is reported, but never stamped as seen.
    #[test]
    fn an_address_only_the_guest_claimed_is_reported_but_not_observed() {
        let a = adapters(
            &cfg(serde_json::json!({ "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0" })),
            &Neighbours::default(),
            Some("192.168.1.50"),
            42,
        );
        assert_eq!(a[0].address.as_deref(), Some("192.168.1.50"));
        assert_eq!(a[0].observed_at_unix, None, "believing is not seeing");
    }

    #[test]
    fn a_second_adapter_does_not_inherit_the_first_ones_address() {
        let a = adapters(
            &cfg(serde_json::json!({
                "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0",
                "net1": "virtio=11:22:33:44:55:66,bridge=omnuvbr1",
            })),
            &Neighbours::default(),
            Some("192.168.1.50"),
            42,
        );
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].name, "net0");
        assert_eq!(a[1].address, None, "net1 has no address of its own to report");
    }

    #[test]
    fn nothing_but_network_keys_is_read_as_a_network() {
        let a = adapters(
            &cfg(serde_json::json!({
                "netcfg": "not-an-adapter",
                "name": "vm",
                "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0",
            })),
            &Neighbours::default(),
            None,
            1,
        );
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].name, "net0");
    }

    #[test]
    fn an_unreadable_host_observes_nothing_rather_than_everything() {
        let n = Neighbours::parse("");
        let a = adapters(
            &cfg(serde_json::json!({ "net0": "virtio=BC:24:11:00:00:01,bridge=omnuvbr1" })),
            &n,
            None,
            1,
        );
        assert_eq!(a[0].observed_at_unix, None);
    }
}
