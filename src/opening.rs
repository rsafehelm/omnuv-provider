//! **The provider opening** (option P1 of omnuv's
//! `docs/research/2026-10-04-overlay-path-and-upnp.md`): one UDP port on this
//! host's public side for each buyer machine, so a peer behind any NAT can
//! reach the machine's WireGuard directly instead of through the relay.
//!
//! **Off unless the provider turns it on**, in `agent.yaml`'s `opening`
//! block, which deploy-agent.yml renders from the inventory's `onv_opening`.
//! The file is never edited by hand: a change is the inventory and the play,
//! which restarts the agent and re-applies the rules.
//!
//! ```text
//! the agent (user onv)   gives each machine it builds one port of the range,
//!                        by the machine's id, kept in /var/lib/onv/opening.json;
//!                        puts `--wireguard-port N --external-ip-map <public>/<dev>`
//!                        in the machine's `netbird up`; learns the machine's
//!                        egress address from the host's neighbour table;
//!                        releases the port when the machine is proven gone
//! the applier (root)     `onv-provider apply-opening`, run by onv-opening.path
//!                        when that file changes and by the play: reads the
//!                        `opening` block and the file, checks every entry,
//!                        and replaces table `inet onv_opening` in one nft
//!                        transaction; off, or anything it cannot trust,
//!                        removes the table
//! onv_egress (the play)  admits `ct status dnat` ahead of its
//!                        `oifname onvnat0 ct state new drop`
//! ```
//!
//! **What stays true.** The machine stays on the NAT bridge and `@private`
//! stays dropped, so it is still not on the provider's LAN: a LAN source is
//! not translated at all, and a reply to one would be dropped anyway. Exactly
//! one UDP port reaches each machine, the port its WireGuard listens on, and
//! WireGuard answers nothing unauthenticated. Ports and the public address are
//! this provider's own and never reach Core; Core sees one self-check,
//! `opening`, saying on or off and how many machines are opened.
//!
//! **What it does not do.** A machine built while the opening was off is not
//! opened later, and one built while it was on keeps advertising its port
//! after it is turned off: its `netbird up` ran once, at first boot, and a
//! buyer's machine is never reconfigured or rebooted for a marketplace change.
//! Its peers then try the dead candidate, fail, and use the paths they had
//! before. Off still removes every rule and every port at once.
//!
//! **One node.** The rules are this host's, and a machine is translated only
//! once this host's own neighbour table has seen it on its egress bridge. In
//! a cluster, a machine placed on another node holds a port that is never
//! translated (it shows as "not yet seen" in the check) until that node runs
//! its own agent and opening. Every provider today is one node.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// **The default range: 31820-31970, 151 ports.**
///
/// ```text
/// 151        one for every address the egress bridge can lease
///            (10.201.0.100-250, deploy-agent.yml's onv_egress_dhcp_*),
///            so the range is never what stops a machine being opened
/// below      Linux's ephemeral range (32768-60999): the host's own sockets
///  32768     and the egress masquerade never pick one of these ports, so a
///            port of the range is never also a translation of something else
/// clear of   NetBird's 51820 (a guest that is not opened listens there) and
///            of the well-known ports
/// ```
///
/// A provider whose router forwards fewer sets a smaller range; a machine that
/// finds the range used up is built without an opening and the `opening`
/// check says so.
pub const DEFAULT_PORTS: &str = "31820-31970";
/// The host's uplink, where forwarded packets arrive. Proxmox's default bridge.
pub const DEFAULT_INTERFACE: &str = "vmbr0";
/// More rules than this is a configuration mistake, not a provider.
pub const MAX_PORTS: u32 = 1024;
/// The egress bridge's subnet (`join.rs`, deploy-agent.yml's
/// `onv_egress_subnet`): the only addresses a port may be translated to.
pub const EGRESS_NET: (Ipv4Addr, u8) = (Ipv4Addr::new(10, 201, 0, 0), 24);
/// Where the agent keeps the ports it gave, beside its other state.
pub fn file(snippet_dir: &str) -> PathBuf {
    Path::new(snippet_dir).parent().unwrap_or(Path::new("/var/lib/onv")).join("opening.json")
}

/// How the range reaches this host from the internet. Required when the
/// opening is on: a host with no public address and no forward has nothing to
/// open, and an opening that cannot be reached is a candidate every peer
/// tries and fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Reach {
    /// The host holds `publicAddress` on `interface` itself.
    Public,
    /// The provider's router forwards UDP `ports` to this host, port for port.
    Forwarded,
}

/// `agent.yaml`'s `opening` block.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpeningConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub reach: Option<Reach>,
    /// The address peers reach this host at: its own, or its router's.
    #[serde(default)]
    pub public_address: Option<String>,
    #[serde(default = "default_interface")]
    pub interface: String,
    /// `first-last`, inclusive.
    #[serde(default = "default_ports")]
    pub ports: String,
}

fn default_interface() -> String {
    DEFAULT_INTERFACE.into()
}

fn default_ports() -> String {
    DEFAULT_PORTS.into()
}

impl Default for OpeningConfig {
    fn default() -> Self {
        Self { enabled: false, reach: None, public_address: None, interface: default_interface(), ports: default_ports() }
    }
}

/// `first-last` as two ports.
pub fn parse_ports(s: &str) -> Result<(u16, u16), String> {
    let (a, b) = s.trim().split_once('-').ok_or_else(|| format!("opening.ports is {s:?}; it must be first-last, e.g. {DEFAULT_PORTS}"))?;
    let a: u16 = a.trim().parse().map_err(|_| format!("opening.ports is {s:?}; {a:?} is not a port"))?;
    let b: u16 = b.trim().parse().map_err(|_| format!("opening.ports is {s:?}; {b:?} is not a port"))?;
    if a < 1024 || a > b {
        return Err(format!("opening.ports is {s:?}; it must be first-last with 1024 <= first <= last"));
    }
    if u32::from(b - a) + 1 > MAX_PORTS {
        return Err(format!("opening.ports is {s:?}: {} ports, more than {MAX_PORTS}", u32::from(b - a) + 1));
    }
    Ok((a, b))
}

/// Why an address cannot be reached from the internet, or `None` when it can.
/// Documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24) pass: they
/// are what tests and examples use, and no router hands one out.
pub fn not_public(ip: Ipv4Addr) -> Option<&'static str> {
    let o = ip.octets();
    if ip.is_private() {
        Some("a private (RFC 1918) address")
    } else if ip.is_loopback() {
        Some("a loopback address")
    } else if ip.is_link_local() {
        Some("a link-local address")
    } else if o[0] == 100 && (o[1] & 0xc0) == 64 {
        Some("a carrier-grade NAT (100.64.0.0/10) address")
    } else if ip.is_multicast() || ip.is_broadcast() || ip.is_unspecified() || o[0] == 0 || o[0] >= 240 {
        Some("not a unicast address")
    } else {
        None
    }
}

fn valid_interface(name: &str) -> bool {
    !name.is_empty() && name.len() <= 15 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

/// The port range, the public address and how it is reached, once checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub first: u16,
    pub last: u16,
    pub public: Ipv4Addr,
    pub reach: Reach,
    pub interface: String,
}

impl OpeningConfig {
    /// Every key's syntax always, and when on, what being on needs. Names the
    /// key, never quietly falls back: an opening the provider believes is on
    /// and is not is the failure this exists to prevent.
    pub fn check(&self) -> Result<Option<Checked>, Vec<String>> {
        let mut bad = Vec::new();
        let range = parse_ports(&self.ports).map_err(|e| bad.push(e)).ok();
        if !valid_interface(&self.interface) {
            bad.push(format!("opening.interface is {:?}; it must be a network interface name", self.interface));
        }
        let public = match &self.public_address {
            None => None,
            Some(s) if s.trim().is_empty() => None,
            Some(s) => match s.trim().parse::<Ipv4Addr>() {
                Ok(ip) => match not_public(ip) {
                    Some(why) => {
                        bad.push(format!("opening.publicAddress {ip} is {why}: no peer outside could reach it"));
                        None
                    }
                    None => Some(ip),
                },
                Err(_) => {
                    bad.push(format!("opening.publicAddress is {s:?}; it must be an IPv4 address"));
                    None
                }
            },
        };
        if !self.enabled {
            return if bad.is_empty() { Ok(None) } else { Err(bad) };
        }
        if public.is_none() && self.public_address.as_deref().is_none_or(|s| s.trim().is_empty()) {
            bad.push("opening.enabled is true and opening.publicAddress is not set: the address peers reach this host at".into());
        }
        if self.reach.is_none() {
            bad.push(format!(
                "opening.enabled is true and opening.reach is not declared: this host has no public address and no \
                 forward was declared. Set reach: public when the public address is on {}, or reach: forwarded when \
                 your router forwards UDP {} to this host",
                self.interface, self.ports
            ));
        }
        match (bad.is_empty(), range, public, self.reach) {
            (true, Some((first, last)), Some(public), Some(reach)) => {
                Ok(Some(Checked { first, last, public, reach, interface: self.interface.clone() }))
            }
            _ => Err(bad),
        }
    }
}

// ---------- the book: which machine holds which port ----------

/// One machine's port, and the address its egress interface was last seen at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slot {
    pub port: u16,
    #[serde(default)]
    pub address: Option<Ipv4Addr>,
}

/// `/var/lib/onv/opening.json`. The agent is its one writer; the applier reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// Machine id -> its slot. By the whole id, never a name.
    #[serde(default)]
    pub machines: BTreeMap<String, Slot>,
}

pub use onv_generators::opening::Opened;

/// The agent's side. Held by the driver; every change is written through
/// before it is used, so a port named in a machine's first boot is on disk
/// before the machine exists.
#[derive(Debug)]
pub struct Book {
    on: Option<Checked>,
    path: Option<PathBuf>,
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    state: State,
    /// The file could not be read: nothing is allocated or written until it
    /// can, since starting from empty would hand out ports machines hold.
    refused: Option<String>,
    /// The bytes last written, so an unchanged pass writes nothing and does
    /// not wake the applier.
    written: Option<Vec<u8>>,
    /// Machines built without an opening because the range was used up.
    exhausted: BTreeSet<String>,
}

impl Default for Book {
    fn default() -> Self {
        Self::off()
    }
}

impl Book {
    /// Off, with nowhere to write: tests, and the host timer.
    pub fn off() -> Self {
        Self { on: None, path: None, inner: Mutex::new(Inner::default()) }
    }

    /// Reads what the file holds. Writes nothing: the host timer builds a
    /// driver too, and must not touch the file. `settle` is the agent's.
    pub fn load(cfg: &OpeningConfig, path: PathBuf) -> Self {
        let on = cfg.check().ok().flatten();
        let mut inner = Inner::default();
        match std::fs::read(&path) {
            Ok(raw) => match serde_json::from_slice::<State>(&raw) {
                Ok(s) => {
                    inner.state = s;
                    inner.written = Some(raw);
                }
                Err(e) => inner.refused = Some(format!("{} could not be read: {e}", path.display())),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => inner.refused = Some(format!("{} could not be read: {e}", path.display())),
        }
        Self { on, path: Some(path), inner: Mutex::new(inner) }
    }

    #[cfg(test)]
    pub fn is_on(&self) -> bool {
        self.on.is_some()
    }

    /// At the agent's start: off releases every port; on drops what is
    /// outside the range now configured (a range made smaller). Either way
    /// the file is written, so the applier converges on it.
    pub fn settle(&self) -> anyhow::Result<()> {
        let mut g = crate::poison::lock(&self.inner, "opening");
        if g.refused.is_some() && self.on.is_some() {
            return Ok(());
        }
        match &self.on {
            None => {
                g.state.machines.clear();
                g.refused = None;
            }
            Some(c) => g.state.machines.retain(|_, s| (c.first..=c.last).contains(&s.port)),
        }
        self.persist(&mut g)
    }

    /// The port this machine holds, giving it the lowest free one if it has
    /// none. `None` when off, when the file was refused, or when the range is
    /// used up (said by `check`).
    pub fn allocate(&self, id: &str) -> anyhow::Result<Option<Opened>> {
        let Some(c) = &self.on else { return Ok(None) };
        let mut g = crate::poison::lock(&self.inner, "opening");
        if g.refused.is_some() {
            return Ok(None);
        }
        if let Some(s) = g.state.machines.get(id) {
            return Ok(Some(Opened { port: s.port, public: c.public }));
        }
        let used: HashSet<u16> = g.state.machines.values().map(|s| s.port).collect();
        let Some(port) = (c.first..=c.last).find(|p| !used.contains(p)) else {
            g.exhausted.insert(id.to_string());
            return Ok(None);
        };
        g.state.machines.insert(id.to_string(), Slot { port, address: None });
        g.exhausted.remove(id);
        self.persist(&mut g)?;
        crate::audit::record("opening.allocate", "agent", id, "ok", Some(&port.to_string()));
        Ok(Some(Opened { port, public: c.public }))
    }

    /// The port a machine already holds; never gives one. For a refresh of an
    /// existing machine's first-boot data.
    pub fn opened(&self, id: &str) -> Option<Opened> {
        let c = self.on.as_ref()?;
        let g = crate::poison::lock(&self.inner, "opening");
        g.state.machines.get(id).map(|s| Opened { port: s.port, public: c.public })
    }

    /// The machine is proven gone: its port is free again.
    pub fn release(&self, id: &str) -> anyhow::Result<()> {
        let mut g = crate::poison::lock(&self.inner, "opening");
        g.exhausted.remove(id);
        if g.state.machines.remove(id).is_some() {
            self.persist(&mut g)?;
            crate::audit::record("opening.release", "agent", id, "ok", None);
        }
        Ok(())
    }

    /// Releases every port whose machine `keep` does not name. The caller
    /// passes a complete listing or does not call: "could not ask" is never
    /// "gone" (R1 rule 9).
    pub fn sweep(&self, keep: impl Fn(&str) -> bool) -> anyhow::Result<Vec<String>> {
        let mut g = crate::poison::lock(&self.inner, "opening");
        let gone: Vec<String> = g.state.machines.keys().filter(|id| !keep(id)).cloned().collect();
        for id in &gone {
            g.state.machines.remove(id);
            crate::audit::record("opening.release", "agent", id, "ok", Some("no longer on this host"));
        }
        g.exhausted.retain(|id| keep(id));
        if !gone.is_empty() {
            self.persist(&mut g)?;
        }
        Ok(gone)
    }

    /// Each machine's egress address, as the host's neighbour table resolves
    /// its egress MAC. Kept when the table says nothing (an entry the kernel
    /// aged out), changed when it names a different address in the subnet.
    pub fn observe(&self, addresses: impl Fn(&str) -> Vec<String>) -> anyhow::Result<()> {
        let mut g = crate::poison::lock(&self.inner, "opening");
        if g.refused.is_some() {
            return Ok(());
        }
        let mut moved = false;
        for (id, slot) in g.state.machines.iter_mut() {
            let seen: Vec<Ipv4Addr> = addresses(&crate::instance::egress_mac(id))
                .iter()
                .filter_map(|a| a.parse().ok())
                .filter(|a| in_egress(*a))
                .collect();
            if seen.is_empty() || slot.address.is_some_and(|a| seen.contains(&a)) {
                continue;
            }
            let mut seen = seen;
            seen.sort();
            slot.address = Some(seen[0]);
            moved = true;
        }
        if moved {
            self.persist(&mut g)?;
        }
        Ok(())
    }

    /// The self-check Core is sent: on or off, how many machines are opened,
    /// and whether anything stopped one being opened. No port, no address.
    pub fn check(&self) -> omnuv_protocol::SelfCheck {
        use omnuv_protocol::{CheckKind, CheckResult, SelfCheck};
        let g = crate::poison::lock(&self.inner, "opening");
        let (result, detail) = match (&self.on, &g.refused) {
            (None, _) => (CheckResult::Pass, "off: no machine on this host is opened".to_string()),
            (Some(_), Some(why)) => (CheckResult::Fail, format!("on, but no port is given: {why}")),
            (Some(c), None) => {
                let size = u32::from(c.last - c.first) + 1;
                let held = g.state.machines.len();
                let waiting = g.state.machines.values().filter(|s| s.address.is_none()).count();
                let reach = match c.reach {
                    Reach::Public => "the host's own public address",
                    Reach::Forwarded => "a forward on the provider's router",
                };
                if g.exhausted.is_empty() {
                    (
                        CheckResult::Pass,
                        format!("on, through {reach}: {held} machine(s) opened of {size}, {waiting} not yet seen on the bridge"),
                    )
                } else {
                    (
                        CheckResult::Fail,
                        format!(
                            "on, through {reach}: all {size} port(s) are held, and {} machine(s) were built without an opening",
                            g.exhausted.len()
                        ),
                    )
                }
            }
        };
        SelfCheck { name: "opening".into(), kind: CheckKind::Presence, result, detail: Some(detail), subject: None }
    }

    #[cfg(test)]
    pub fn state(&self) -> State {
        crate::poison::lock(&self.inner, "opening").state.clone()
    }

    /// Written whole, to a file beside it and renamed over it, so the applier
    /// (woken by the rename) never reads half of one; and only when the bytes
    /// moved.
    fn persist(&self, g: &mut Inner) -> anyhow::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let mut body = serde_json::to_vec_pretty(&g.state)?;
        body.push(b'\n');
        if g.written.as_deref() == Some(&body[..]) {
            return Ok(());
        }
        let tmp = path.with_extension("json.new");
        crate::names::write_private(&tmp.to_string_lossy(), &body, 0o640)
            .map_err(|e| anyhow::anyhow!("writing {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| anyhow::anyhow!("renaming {} over {}: {e}", tmp.display(), path.display()))?;
        g.written = Some(body);
        Ok(())
    }
}

pub fn in_egress(a: Ipv4Addr) -> bool {
    let (net, len) = EGRESS_NET;
    let mask = u32::MAX << (32 - u32::from(len));
    (u32::from(a) & mask) == u32::from(net)
}

// ---------- the guest's side ----------

#[allow(unused_imports)] // its tests below reach it by this name
pub use onv_generators::opening::netbird_up;

// ---------- the applier's side ----------

/// The nftables table, whole: the script `nft -f` loads as one transaction.
/// Created empty and deleted first, so the script replaces the table whether
/// or not it existed, and a failed load leaves the old one in place.
///
/// ```text
/// prerouting   a packet for this host (fib daddr type local), arriving on the
///              uplink, from a source that is not private, to UDP port N:
///              translated to the machine holding N, port N
/// postrouting  that machine's packets from UDP port N, leaving by the uplink:
///              masqueraded to port N, ahead of Proxmox's SNAT (srcnat - 5),
///              so what the machine sends from N leaves from N and the router's
///              forward of N matches it
/// ```
///
/// Entries sorted by port, so the same book renders the same bytes.
pub fn render(c: &Checked, entries: &[(u16, Ipv4Addr)]) -> String {
    let t = crate::names::OPENING_TABLE;
    let iface = &c.interface;
    let mut entries = entries.to_vec();
    entries.sort();
    let mut pre = String::new();
    let mut post = String::new();
    for (port, addr) in &entries {
        pre.push_str(&format!(
            "        iifname \"{iface}\" fib daddr type local ip saddr != @private udp dport {port} dnat ip to {addr}:{port}\n"
        ));
        post.push_str(&format!(
            "        oifname \"{iface}\" ip saddr {addr} udp sport {port} masquerade to :{port}\n"
        ));
    }
    format!(
        "# Generated by onv-provider apply-opening. Do not edit: it is replaced whole.\n\
         table inet {t} {{}}\n\
         delete table inet {t}\n\
         table inet {t} {{\n    \
         set private {{\n        type ipv4_addr\n        flags interval\n        \
         elements = {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10, 127.0.0.0/8 }}\n    }}\n\n    \
         chain prerouting {{\n        type nat hook prerouting priority dstnat; policy accept;\n{pre}    }}\n\n    \
         chain postrouting {{\n        type nat hook postrouting priority srcnat - 5; policy accept;\n{post}    }}\n\
         }}\n"
    )
}

/// The entries the applier will translate, after checking every one against
/// the configuration. Any entry it cannot trust refuses the whole file: one
/// writer wrote it, so a bad entry means the writer is not to be believed.
pub fn entries(c: &Checked, state: &State) -> Result<Vec<(u16, Ipv4Addr)>, String> {
    let mut ports = HashSet::new();
    let mut addrs = HashSet::new();
    let mut out = Vec::new();
    for (id, s) in &state.machines {
        if !(c.first..=c.last).contains(&s.port) {
            return Err(format!("machine {id}: port {} is outside {}-{}", s.port, c.first, c.last));
        }
        if !ports.insert(s.port) {
            return Err(format!("port {} is given twice", s.port));
        }
        let Some(a) = s.address else { continue };
        if !in_egress(a) || a.octets()[3] == 0 || a.octets()[3] == 1 || a.octets()[3] == 255 {
            return Err(format!("machine {id}: {a} is not a machine's address on the egress bridge"));
        }
        if !addrs.insert(a) {
            return Err(format!("{a} is given two ports"));
        }
        out.push((s.port, a));
    }
    out.sort();
    Ok(out)
}

/// The two parts of `agent.yaml` the applier reads. Never the credentials:
/// it needs none, and runs as root.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ForApplier {
    #[serde(default)]
    opening: OpeningConfig,
    #[serde(default)]
    proxmox: Option<ProxmoxPaths>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxmoxPaths {
    #[serde(default)]
    snippet_dir: Option<String>,
}

/// Whether `ip` is on `interface`, asked of the kernel (getifaddrs).
fn holds(interface: &str, ip: Ipv4Addr) -> bool {
    let mut found = false;
    // SAFETY: getifaddrs fills a list freed by freeifaddrs below; every node
    // and address pointer is checked before it is read.
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return false;
        }
        let mut cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() && i32::from((*ifa.ifa_addr).sa_family) == libc::AF_INET {
                let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy();
                let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                if name == interface && Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)) == ip {
                    found = true;
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    found
}

fn nft(script: &str) -> Result<(), String> {
    use std::io::Write as _;
    let mut child = std::process::Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("nft could not be run: {e}"))?;
    child
        .stdin
        .take()
        .ok_or("nft took no input")?
        .write_all(script.as_bytes())
        .map_err(|e| format!("writing to nft: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("nft: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("nft refused it: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

/// The table as the kernel holds it now, or `None` when there is none.
fn listed() -> Result<Option<String>, String> {
    let out = std::process::Command::new("nft")
        .args(["list", "table", "inet", crate::names::OPENING_TABLE])
        .output()
        .map_err(|e| format!("nft could not be run: {e}"))?;
    if out.status.success() {
        return Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()));
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("No such file or directory") {
        Ok(None)
    } else {
        Err(format!("nft list: {}", err.trim()))
    }
}

/// Removes the table, and proves it is gone.
fn remove() -> Result<&'static str, String> {
    let t = crate::names::OPENING_TABLE;
    nft(&format!("table inet {t} {{}}\ndelete table inet {t}\n"))?;
    match listed()? {
        None => Ok("removed"),
        Some(_) => Err(format!("table inet {t} is still listed after its delete")),
    }
}

/// `onv-provider apply-opening`: run as root by onv-opening.service. Exit 0
/// when the kernel holds what the files say (the table, or no table when
/// off), 1 when it fell back to no table, 2 when the configuration refused.
/// `--print` renders the script and changes nothing.
pub fn apply_main(config: &str, state_override: Option<&str>, print: bool) -> i32 {
    let say = |verdict: &str| println!("apply-opening: {verdict}");
    let raw = match std::fs::read_to_string(config) {
        Ok(r) => r,
        Err(e) => {
            say(&format!("{config} could not be read ({e}); the table is removed"));
            return fallback(print, 1);
        }
    };
    let parsed: ForApplier = match serde_yaml_ng::from_str(&raw) {
        Ok(p) => p,
        Err(_) => {
            say(&format!("{config} could not be parsed (`onv-provider check-config` names the key); the table is removed"));
            return fallback(print, 2);
        }
    };
    let checked = match parsed.opening.check() {
        Ok(Some(c)) => c,
        Ok(None) => {
            if print {
                say("off: nothing to load");
                return 0;
            }
            return match remove() {
                Ok(_) => {
                    say("off: table inet onv_opening is absent");
                    0
                }
                Err(e) => {
                    say(&format!("off, but the table could not be removed: {e}"));
                    1
                }
            };
        }
        Err(bad) => {
            say(&format!("refused: {}; the table is removed", bad.join("; ")));
            return fallback(print, 2);
        }
    };
    if checked.reach == Reach::Public && !print && !holds(&checked.interface, checked.public) {
        say(&format!(
            "refused: reach is public and {} is not on {}; the table is removed",
            checked.public, checked.interface
        ));
        return fallback(print, 1);
    }
    let path = state_override.map(PathBuf::from).unwrap_or_else(|| {
        file(parsed.proxmox.and_then(|p| p.snippet_dir).as_deref().unwrap_or("/var/lib/onv/snippets"))
    });
    let state = match std::fs::read(&path) {
        Ok(raw) => match serde_json::from_slice::<State>(&raw) {
            Ok(s) => s,
            Err(e) => {
                say(&format!("{} could not be read ({e}); the table is removed", path.display()));
                return fallback(print, 1);
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
        Err(e) => {
            say(&format!("{} could not be read ({e}); the table is removed", path.display()));
            return fallback(print, 1);
        }
    };
    let entries = match entries(&checked, &state) {
        Ok(e) => e,
        Err(why) => {
            say(&format!("{} refused: {why}; the table is removed", path.display()));
            return fallback(print, 1);
        }
    };
    let script = render(&checked, &entries);
    if print {
        print!("{script}");
        return 0;
    }
    if let Err(e) = nft(&script) {
        say(&format!("{e}; the table is removed"));
        return fallback(false, 1);
    }
    // Read back: the rules the kernel holds, counted, not nft's exit code.
    match listed() {
        Ok(Some(t)) if t.matches(" dnat ip to ").count() == entries.len() && t.matches(" masquerade to ").count() == entries.len() => {
            say(&format!(
                "on ({:?}): {} machine(s) opened of {} held, ports {}-{} on {}",
                checked.reach,
                entries.len(),
                state.machines.len(),
                checked.first,
                checked.last,
                checked.interface
            ));
            0
        }
        Ok(other) => {
            say(&format!(
                "the table read back does not hold the {} rule pair(s) loaded ({}); the table is removed",
                entries.len(),
                if other.is_some() { "different rules" } else { "no table" }
            ));
            fallback(false, 1)
        }
        Err(e) => {
            say(&format!("{e}; the table is removed"));
            fallback(false, 1)
        }
    }
}

/// Anything not trusted ends with no table: closed, the state before the
/// opening existed.
fn fallback(print: bool, code: i32) -> i32 {
    if print {
        return code;
    }
    // A String, nft's own words: no causes to drop.
    if let Err(why) = remove() {
        println!("apply-opening: and the table could not be removed: {why}");
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on() -> OpeningConfig {
        OpeningConfig {
            enabled: true,
            reach: Some(Reach::Forwarded),
            public_address: Some("203.0.113.7".into()),
            interface: "vmbr0".into(),
            ports: "31820-31822".into(),
        }
    }

    fn book(cfg: &OpeningConfig) -> (tempfile::TempDir, PathBuf, Book) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opening.json");
        let b = Book::load(cfg, path.clone());
        (dir, path, b)
    }

    #[test]
    fn off_is_the_default_and_needs_nothing_else() {
        let c = OpeningConfig::default();
        assert!(!c.enabled);
        assert_eq!(c.ports, DEFAULT_PORTS);
        assert_eq!(c.check(), Ok(None));
        // And the block the template writes when off parses to the same.
        let y: OpeningConfig =
            serde_yaml_ng::from_str("enabled: false\nreach: null\npublicAddress: null\ninterface: vmbr0\nports: 31820-31970\n").unwrap();
        assert_eq!(y, c);
    }

    #[test]
    fn the_default_range_is_one_port_per_bridge_lease_and_below_the_ephemeral_range() {
        let (a, b) = parse_ports(DEFAULT_PORTS).unwrap();
        // deploy-agent.yml's onv_egress_dhcp_start/end: 10.201.0.100-250.
        assert_eq!(u32::from(b - a) + 1, 250 - 100 + 1);
        assert!(b < 32768, "inside Linux's ephemeral range");
        assert!(!(a..=b).contains(&51820), "NetBird's own port");
    }

    #[test]
    fn on_without_a_reach_is_refused_in_words() {
        let mut c = on();
        c.reach = None;
        let e = c.check().unwrap_err().join("; ");
        assert!(e.contains("no public address and no forward was declared"), "{e}");
        let mut c = on();
        c.public_address = None;
        assert!(c.check().unwrap_err().join("; ").contains("publicAddress is not set"));
    }

    #[test]
    fn a_public_address_that_is_not_public_is_refused() {
        for (ip, why) in [
            ("192.168.100.78", "private"),
            ("10.111.0.4", "private"),
            ("100.64.1.1", "carrier-grade"),
            ("127.0.0.1", "loopback"),
            ("169.254.1.1", "link-local"),
            ("0.0.0.0", "unicast"),
            ("not-an-ip", "IPv4"),
        ] {
            let mut c = on();
            c.public_address = Some(ip.into());
            let e = c.check().unwrap_err().join("; ");
            assert!(e.contains(why), "{ip}: {e}");
        }
        // The nearest thing it must accept.
        let mut c = on();
        c.public_address = Some("193.137.26.160".into());
        assert!(c.check().unwrap().is_some());
    }

    #[test]
    fn a_bad_range_or_interface_is_refused_even_when_off() {
        for bad in ["31820", "80-90", "31900-31800", "1024-9999", "a-b"] {
            let c = OpeningConfig { ports: bad.into(), ..OpeningConfig::default() };
            assert!(c.check().is_err(), "{bad} passed");
        }
        let c = OpeningConfig { interface: "vmbr0; rm".into(), ..OpeningConfig::default() };
        assert!(c.check().is_err());
        assert!(serde_yaml_ng::from_str::<OpeningConfig>("enabled: true\npublicAdress: 1.2.3.4\n").is_err(), "a misspelt key");
    }

    #[test]
    fn ports_are_given_lowest_first_by_id_kept_and_released() {
        let (_d, path, b) = book(&on());
        assert_eq!(b.allocate("m-a").unwrap().unwrap().port, 31820);
        assert_eq!(b.allocate("m-b").unwrap().unwrap().port, 31821);
        // Asked again, the same port: by id, not by turn.
        assert_eq!(b.allocate("m-a").unwrap().unwrap().port, 31820);
        assert_eq!(b.opened("m-b").unwrap().port, 31821);
        assert_eq!(b.opened("m-c"), None, "opened never gives");
        b.release("m-a").unwrap();
        assert_eq!(b.allocate("m-c").unwrap().unwrap().port, 31820, "a released port is given again");
        // Persisted, and read back by a new book as the restarted agent would.
        let again = Book::load(&on(), path);
        assert_eq!(again.opened("m-b").unwrap().port, 31821);
        assert_eq!(again.opened("m-c").unwrap().port, 31820);
        assert_eq!(again.opened("m-a"), None);
    }

    #[test]
    fn a_used_up_range_builds_unopened_and_says_so() {
        let (_d, _p, b) = book(&on());
        for id in ["a", "b", "c"] {
            assert!(b.allocate(id).unwrap().is_some());
        }
        assert_eq!(b.allocate("d").unwrap(), None);
        let c = b.check();
        assert_eq!(c.result, omnuv_protocol::CheckResult::Fail);
        assert!(c.detail.as_deref().unwrap().contains("1 machine(s) were built without an opening"), "{c:?}");
        b.release("a").unwrap();
        b.sweep(|id| ["b", "c"].contains(&id)).unwrap();
        assert_eq!(b.check().result, omnuv_protocol::CheckResult::Pass);
    }

    #[test]
    fn off_gives_nothing_and_settling_off_releases_every_port() {
        let (_d, path, b) = book(&on());
        b.allocate("m-a").unwrap();
        b.allocate("m-b").unwrap();
        let off = Book::load(&OpeningConfig::default(), path.clone());
        assert!(!off.is_on());
        assert_eq!(off.allocate("m-c").unwrap(), None);
        assert_eq!(off.opened("m-a"), None);
        off.settle().unwrap();
        let s: State = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(s.machines.is_empty(), "off left ports: {s:?}");
        assert!(off.check().detail.unwrap().starts_with("off"));
    }

    #[test]
    fn a_smaller_range_drops_what_is_outside_it_at_start() {
        let (_d, path, b) = book(&on());
        for id in ["a", "b", "c"] {
            b.allocate(id).unwrap();
        }
        let smaller = OpeningConfig { ports: "31820-31821".into(), ..on() };
        let b = Book::load(&smaller, path);
        b.settle().unwrap();
        assert_eq!(b.state().machines.keys().cloned().collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn an_unreadable_book_gives_nothing_rather_than_starting_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opening.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let b = Book::load(&on(), path.clone());
        assert_eq!(b.allocate("m").unwrap(), None);
        b.settle().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{ not json", "a refused book was overwritten");
        assert_eq!(b.check().result, omnuv_protocol::CheckResult::Fail);
    }

    #[test]
    fn the_sweep_keeps_what_it_is_told_and_nothing_else() {
        let (_d, _p, b) = book(&on());
        b.allocate("kept").unwrap();
        b.allocate("gone").unwrap();
        let gone = b.sweep(|id| id == "kept").unwrap();
        assert_eq!(gone, vec!["gone"]);
        assert_eq!(b.state().machines.keys().cloned().collect::<Vec<_>>(), vec!["kept"]);
    }

    #[test]
    fn the_address_is_learnt_by_the_egress_mac_and_only_in_the_bridge_subnet() {
        let (_d, _p, b) = book(&on());
        b.allocate("m-a").unwrap();
        let mac = crate::instance::egress_mac("m-a");
        // A LAN address under the same MAC is not an egress address.
        b.observe(|m| if m == mac { vec!["192.168.100.9".into()] } else { vec![] }).unwrap();
        assert_eq!(b.state().machines["m-a"].address, None);
        b.observe(|m| if m == mac { vec!["10.201.0.105".into()] } else { vec![] }).unwrap();
        assert_eq!(b.state().machines["m-a"].address, Some(Ipv4Addr::new(10, 201, 0, 105)));
        // Silence keeps it; a stale entry beside the live one keeps it too.
        b.observe(|_| vec![]).unwrap();
        b.observe(|m| if m == mac { vec!["10.201.0.199".into(), "10.201.0.105".into()] } else { vec![] }).unwrap();
        assert_eq!(b.state().machines["m-a"].address, Some(Ipv4Addr::new(10, 201, 0, 105)));
    }

    #[test]
    fn an_unchanged_book_is_not_written_again() {
        let (_d, path, b) = book(&on());
        b.allocate("m-a").unwrap();
        let before = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        b.allocate("m-a").unwrap();
        b.observe(|_| vec![]).unwrap();
        b.sweep(|id| id == "m-a").unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), before, "a pass that changed nothing woke the applier");
    }

    #[test]
    fn rendering_is_idempotent_and_names_one_port_per_machine() {
        let c = on().check().unwrap().unwrap();
        let e = vec![(31821, Ipv4Addr::new(10, 201, 0, 120)), (31820, Ipv4Addr::new(10, 201, 0, 105))];
        let one = render(&c, &e);
        let mut reversed = e.clone();
        reversed.reverse();
        assert_eq!(one, render(&c, &reversed), "order of the book changed the bytes");
        assert!(one.contains(
            "iifname \"vmbr0\" fib daddr type local ip saddr != @private udp dport 31820 dnat ip to 10.201.0.105:31820"
        ));
        assert!(one.contains("oifname \"vmbr0\" ip saddr 10.201.0.105 udp sport 31820 masquerade to :31820"));
        assert_eq!(one.matches(" dnat ip to ").count(), 2);
        assert!(!one.contains("tcp"), "only UDP is opened");
        // Replaces, never appends: created, deleted, then written.
        assert!(one.starts_with("# Generated") && one.contains("table inet onv_opening {}\ndelete table inet onv_opening\n"));
        // Empty: the table with no rules.
        assert_eq!(render(&c, &[]).matches("dnat").count(), 0);
    }

    #[test]
    fn the_applier_refuses_a_book_it_cannot_trust() {
        let c = on().check().unwrap().unwrap();
        let slot = |port, a: Option<[u8; 4]>| Slot { port, address: a.map(Ipv4Addr::from) };
        let st = |v: Vec<(&str, Slot)>| State { machines: v.into_iter().map(|(k, s)| (k.to_string(), s)).collect() };
        assert!(entries(&c, &st(vec![("a", slot(80, Some([10, 201, 0, 105])))])).unwrap_err().contains("outside"));
        assert!(entries(&c, &st(vec![("a", slot(31820, Some([192, 168, 100, 5])))])).unwrap_err().contains("egress bridge"));
        assert!(entries(&c, &st(vec![("a", slot(31820, Some([10, 201, 0, 1])))])).unwrap_err().contains("egress bridge"), "the gateway");
        assert!(
            entries(&c, &st(vec![("a", slot(31820, Some([10, 201, 0, 105]))), ("b", slot(31820, Some([10, 201, 0, 106])))]))
                .unwrap_err()
                .contains("twice")
        );
        assert!(
            entries(&c, &st(vec![("a", slot(31820, Some([10, 201, 0, 105]))), ("b", slot(31821, Some([10, 201, 0, 105])))]))
                .unwrap_err()
                .contains("two ports")
        );
        // Not yet seen on the bridge: held, not translated.
        assert_eq!(entries(&c, &st(vec![("a", slot(31820, None))])).unwrap(), vec![]);
    }

    #[test]
    fn the_egress_subnet_is_the_one_join_and_the_play_create() {
        assert!(in_egress(Ipv4Addr::new(10, 201, 0, 100)) && in_egress(Ipv4Addr::new(10, 201, 0, 250)));
        assert!(!in_egress(Ipv4Addr::new(10, 201, 1, 1)) && !in_egress(Ipv4Addr::new(192, 168, 100, 78)));
        assert_eq!(format!("{}/{}", EGRESS_NET.0, EGRESS_NET.1), crate::join::EGRESS_SUBNET);
    }

    #[test]
    fn the_applier_prints_what_it_would_load_and_refuses_in_words() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("agent.yaml");
        let state = dir.path().join("opening.json");
        std::fs::write(
            &state,
            serde_json::to_vec(&State {
                machines: [("m".to_string(), Slot { port: 31820, address: Some(Ipv4Addr::new(10, 201, 0, 105)) })].into(),
            })
            .unwrap(),
        )
        .unwrap();
        let yaml = |opening: &str| format!("core:\n  url: https://x\nproxmox:\n  apiUrl: https://127.0.0.1:8006\n  tokenId: t\n{opening}");
        std::fs::write(&cfg, yaml("opening:\n  enabled: true\n  reach: forwarded\n  publicAddress: 203.0.113.7\n  ports: 31820-31822\n")).unwrap();
        assert_eq!(apply_main(cfg.to_str().unwrap(), Some(state.to_str().unwrap()), true), 0);
        std::fs::write(&cfg, yaml("opening:\n  enabled: true\n  publicAddress: 203.0.113.7\n")).unwrap();
        assert_eq!(apply_main(cfg.to_str().unwrap(), Some(state.to_str().unwrap()), true), 2, "no reach declared");
        std::fs::write(&cfg, yaml("")).unwrap();
        assert_eq!(apply_main(cfg.to_str().unwrap(), Some(state.to_str().unwrap()), true), 0, "absent is off");
    }

    #[test]
    fn the_opened_netbird_up_listens_on_its_port_and_maps_its_egress_interface() {
        let mac = crate::instance::egress_mac("m-a");
        let line = netbird_up(
            "netbird up --management-url https://m --setup-key K --hostname h",
            &Opened { port: 31820, public: Ipv4Addr::new(203, 0, 113, 7) },
            &mac,
        );
        assert!(line.starts_with("  - |\n    DEV="), "{line}");
        assert!(line.contains(&mac.to_lowercase()), "the egress interface, by its MAC");
        assert!(line.contains("--wireguard-port 31820 ${DEV:+--external-ip-map 203.0.113.7/$DEV}"), "{line}");
        assert!(line.trim_end().ends_with("|| true"));
    }
}
