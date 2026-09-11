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

/// Every address the host has resolved, grouped by MAC.
///
/// One MAC, many addresses — which is not a corner case. VM 105 on Pluto had
/// two entries for one NIC within a minute of this shipping: a live lease and a
/// dead one the kernel had not yet aged out. Keying this one-to-one picked
/// whichever arrived last and called a silent address "observed".
#[derive(Debug, Default, Clone)]
pub(crate) struct Neighbours(HashMap<String, Vec<String>>);

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
            let _ = device;
            out.entry(normalise(mac)).or_insert_with(Vec::new).push(ip.to_string());
        }
        Self(out)
    }

    pub(crate) fn get(&self, mac: &str) -> &[String] {
        self.0.get(&normalise(mac)).map(Vec::as_slice).unwrap_or_default()
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
        let resolved = seen.get(&mac);

        // Only one adapter can claim the believed address: the guest agent
        // reports the machine's primary, and attaching it to every NIC would
        // invent addresses.
        let mine = believed.filter(|_| out.is_empty());

        // **An observation corroborates a belief; it never silently replaces
        // it.** The host's table holds entries the kernel has not aged out, so
        // an address in it may be a dead lease — Pluto held one for a minute
        // after this shipped, and substituting it would have replaced a working
        // address with a silent one and stamped it `observed`.
        //
        // So: if the host has seen the address we believe, that is
        // corroboration and the adapter is observed. If it has seen only
        // *other* addresses, the belief stands unobserved and the others are
        // reported as a note — a divergence for a person to read, never a
        // substitution nobody was told about.
        let corroborated = mine.is_some_and(|b| resolved.iter().any(|a| a == b));
        let address = match (mine, resolved.first()) {
            (Some(b), _) => Some(b.to_string()),
            // No belief at all: the host's reading is the only thing we have,
            // and reporting it unobserved is better than reporting nothing.
            (None, Some(first)) => Some(first.clone()),
            (None, None) => None,
        };
        let also: Vec<&String> =
            resolved.iter().filter(|a| Some(a.as_str()) != address.as_deref()).collect();

        out.push(AdapterStatus {
            address,
            mac: Some(mac),
            observed_at_unix: corroborated.then_some(now),
            observed_by: corroborated.then(|| "neighbour".to_string()),
            name: if also.is_empty() {
                key.clone()
            } else {
                // Carried on the name because the contract has nowhere else for
                // it, and losing it would hide exactly the finding this whole
                // module exists to produce.
                format!(
                    "{key} (host has also seen {})",
                    also.iter().map(|a| a.as_str()).collect::<Vec<_>>().join(", ")
                )
            },
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
192.168.100.103  0x1         0x2         bc:24:11:bb:6a:89     *        vmbr0
192.168.100.101  0x1         0x2         BC:24:11:BB:6A:89     *        vmbr0
10.200.99.5      0x1         0x2         bc:24:11:00:00:01     *        omnuvbr1
10.200.99.9      0x1         0x0         00:00:00:00:00:00     *        omnuvbr1
";

    fn net(n: &str, mac: &str) -> serde_json::Value {
        serde_json::json!({ n: format!("virtio={mac},bridge=vmbr0") })
    }

    #[test]
    fn an_unanswered_arp_is_not_an_observation() {
        // .9 is in the table flagged incomplete: the kernel asked and nothing
        // replied, which is the opposite of evidence.
        assert!(Neighbours::parse(TABLE).get("00:00:00:00:00:00").is_empty());
    }

    #[test]
    fn the_case_of_a_mac_does_not_decide_whether_we_saw_it() {
        let n = Neighbours::parse(TABLE);
        assert_eq!(n.get("BC:24:11:00:00:01"), ["10.200.99.5"]);
    }

    /// One NIC, two entries. Pluto's worker had exactly this within a minute of
    /// the first version shipping: a live lease and one the kernel had not aged
    /// out, and keying this one-to-one picked whichever landed last.
    #[test]
    fn one_mac_can_hold_more_than_one_address() {
        let n = Neighbours::parse(TABLE);
        assert_eq!(n.get("bc:24:11:bb:6a:89").len(), 2);
    }

    /// The whole point. The host seeing the address we already believe is
    /// corroboration — and the strongest thing this module can say.
    #[test]
    fn seeing_the_believed_address_corroborates_it() {
        let a = adapters(
            &net("net0", "BC:24:11:BB:6A:89"),
            &Neighbours::parse(TABLE),
            Some("192.168.100.103"),
            42,
        );
        assert_eq!(a[0].address.as_deref(), Some("192.168.100.103"));
        assert_eq!(a[0].observed_at_unix, Some(42));
    }

    /// **An observation never silently replaces a belief.** A stale entry for a
    /// dead lease is indistinguishable from a live one in `/proc/net/arp`, so
    /// substituting would have swapped a working address for a silent one and
    /// stamped it observed. The extra is reported instead, for a person.
    #[test]
    fn an_extra_address_is_reported_never_substituted() {
        let a = adapters(
            &net("net0", "BC:24:11:BB:6A:89"),
            &Neighbours::parse(TABLE),
            Some("192.168.100.103"),
            42,
        );
        assert_eq!(a[0].address.as_deref(), Some("192.168.100.103"), "the belief stands");
        assert!(a[0].name.contains("192.168.100.101"), "and the divergence is visible: {}", a[0].name);
    }

    /// A belief the host has not corroborated stays a belief.
    #[test]
    fn an_address_only_the_guest_claimed_is_reported_but_not_observed() {
        let a = adapters(&net("net0", "AA:BB:CC:DD:EE:FF"), &Neighbours::default(), Some("192.168.1.50"), 42);
        assert_eq!(a[0].address.as_deref(), Some("192.168.1.50"));
        assert_eq!(a[0].observed_at_unix, None, "believing is not seeing");
    }

    /// With nothing believed, the host's reading is all there is — and it is
    /// still not stamped as corroborating anything.
    #[test]
    fn with_no_belief_the_host_reading_is_reported_unobserved() {
        let a = adapters(&net("net1", "BC:24:11:00:00:01"), &Neighbours::parse(TABLE), None, 42);
        assert_eq!(a[0].address.as_deref(), Some("10.200.99.5"));
        assert_eq!(a[0].observed_at_unix, None);
    }

    #[test]
    fn a_second_adapter_does_not_inherit_the_first_ones_address() {
        let cfg = serde_json::json!({
            "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0",
            "net1": "virtio=11:22:33:44:55:66,bridge=omnuvbr1",
        });
        let a = adapters(&cfg, &Neighbours::default(), Some("192.168.1.50"), 42);
        assert_eq!(a.len(), 2);
        assert_eq!(a[1].address, None, "net1 has no address of its own to report");
    }

    #[test]
    fn nothing_but_network_keys_is_read_as_a_network() {
        let cfg = serde_json::json!({
            "netcfg": "not-an-adapter",
            "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0",
        });
        assert_eq!(adapters(&cfg, &Neighbours::default(), None, 1).len(), 1);
    }

    #[test]
    fn an_unreadable_host_observes_nothing_rather_than_everything() {
        let a = adapters(&net("net0", "BC:24:11:00:00:01"), &Neighbours::parse(""), None, 1);
        assert_eq!(a[0].observed_at_unix, None);
    }
}
