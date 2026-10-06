//! **The provider opening, in a machine's first boot**: what the machine is
//! told and the `netbird up` it runs. The applier's side, the port book and
//! the nftables table, stay in the agent's `src/opening.rs`.

use std::net::Ipv4Addr;

/// What a machine's first boot is told: listen here, say you are there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opened {
    pub port: u16,
    pub public: Ipv4Addr,
}

/// The machine's `netbird up`, opened: its WireGuard on the port this host
/// forwards, and its egress interface's address announced as the public one.
///
/// `--wireguard-port` and `--external-ip-map` are NetBird 0.78.1's
/// (`client/cmd/up.go:73`, `client/cmd/root.go:207`); the map feeds pion's
/// `NAT1To1IPs` (`client/internal/peer/ice/agent.go:59`), so the host
/// candidate on that interface is announced as `<public>:<port>`. The map
/// names the interface, found by the egress MAC at boot, because the distro
/// names it; an address would not be known until DHCP. When the interface is
/// not found the map is left out, which `netbird up` accepts and which
/// enrols the machine unopened rather than not at all.
///
/// A block scalar, for the reason `instance::resolve_dev` gives.
pub fn netbird_up(base: &str, opened: &Opened, egress_mac: &str) -> String {
    format!(
        "  - |\n    {dev}; {base} --wireguard-port {port} ${{DEV:+--external-ip-map {public}/$DEV}} \
         >/var/log/onv-overlay.log 2>&1 || true\n",
        dev = crate::linux::resolve_dev(egress_mac),
        port = opened.port,
        public = opened.public,
    )
}
