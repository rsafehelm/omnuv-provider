//! Every name the marketplace puts on a provider, in one place.
//!
//! **The prefix is `onv`, and `CLAUDE.md` says why**: *never delete what is not
//! ours* is only checkable if ours is recognisable at a glance, on somebody
//! else's hypervisor, by somebody who did not build it.
//!
//! ## Why this module exists rather than fifty string literals
//!
//! This is the **second** rename. The first, `omnu` to `omnuv`, left its older
//! self behind in places nobody found for months — an `omnu_egress` nftables
//! table beside `omnuv_egress`, an `omnu-egress.service` beside
//! `omnuv-egress.service`, on both providers, and a `LEGACY_TAG_PREFIX`
//! compatibility shim still in this crate. A teardown on 11 September 2026 met
//! all three.
//!
//! A rename is a migration, not an edit: the old object keeps running under the
//! old name until something removes it. Scattered literals make that migration
//! unreviewable, because nobody can see the whole set at once. Here it is the
//! whole set, and the next rename is this file plus a removal play that knows
//! both names.
//!
//! ## What is not here
//!
//! The product, the domain and the crates: `api.omnuv.com`, `omnuv-protocol`,
//! this repository. Those are identity, not resources — nothing is created on a
//! provider called any of them, so nothing has to be recognised or removed.

// **Several constants below are read by no Rust at all**, and that is
// deliberate: they name things the *playbooks* create — the service account,
// the egress unit and table, the paths, the Proxmox user. They are this
// repository's statement of the naming contract, and the test at the bottom of
// this file asserts the prefix rule over every one of them. A name that lives
// in Ansible and nowhere else is a name nothing can check.
#![allow(dead_code)]


/// The prefix itself. Nothing below should hard-code it; a name is built from
/// this so that a grep for `onv` finds the definition rather than forty uses.
pub const PREFIX: &str = "onv";

// ---------------------------------------------------------------------------
// On the provider's host
// ---------------------------------------------------------------------------

/// The agent's package, binary, and systemd unit.
pub const AGENT: &str = "onv-provider";
/// The unit that loads the buyer-egress nftables rules.
pub const EGRESS_UNIT: &str = "onv-egress";
/// Our nftables table. A table of our own, so removing it cannot reach the
/// host's rules or Proxmox's.
pub const EGRESS_TABLE: &str = "onv_egress";

/// Configuration, state, and the audit log the provider keeps.
pub const ETC: &str = "/etc/onv";
pub const VAR: &str = "/var/lib/onv";
pub const LOG: &str = "/var/log/onv";
/// Where a machine the marketplace owns writes what it wants read. `tmpfs`, so
/// a reboot cannot leave yesterday's report looking current.
pub const RUN: &str = "/run/onv";

/// The Proxmox account the agent authenticates as, and its API token.
pub const PVE_USER: &str = "onv@pve";

/// The pools. Marketplace-owned machines in one, buyers' in the other, because
/// the console privilege is granted on the second and nothing else.
pub const POOL: &str = "onv";
pub const POOL_BUYERS: &str = "onv-buyers";

/// The Proxmox storage pointing at the snippets directory, which is how
/// cloud-init reaches generated user-data. Named, because on 11 September a
/// storage nobody had inventoried silently recreated the directory it pointed
/// at, a minute after the directory was deleted.
pub const STORAGE_SNIPPETS: &str = "onv-snippets";

/// The SDN zones: marketplace segments, and the buyer-egress NAT bridge.
pub const SDN_ZONE: &str = "onv";
pub const SDN_ZONE_NAT: &str = "onvnat";
/// The egress bridge every buyer machine's first interface sits on.
///
/// **`onvnat0`, not `onat0`.** It was shortened on the belief that a Proxmox
/// SDN id is at most eight characters and `onvnat0` was nine. It is seven. The
/// dropped `v` bought nothing and cost the one thing the prefix rule exists
/// for: a name an operator recognises at a glance as ours.
///
/// The older name is still swept by `remove-provider.yml` and still re-pointed
/// by the agent, because a rename is a migration — see `ensure_egress`.
pub const NAT_VNET: &str = "onvnat0";

/// The egress bridge's name before 12 September 2026. Machines built under it
/// are re-pointed rather than left on a bridge that is about to be removed.
pub const NAT_VNET_LEGACY: &str = "onat0";

// ---------------------------------------------------------------------------
// Tags, which are how a machine says whose it is
// ---------------------------------------------------------------------------

pub const TAG_INSTANCE: &str = "onv-instance";
pub const TAG_GATEWAY: &str = "onv-gateway";
pub const TAG_WORKER: &str = "onv-worker";

/// Prefixes of earlier generations, kept **only** so a removal play and the
/// reconciler can still recognise a machine built before a rename. Never used
/// to name anything new.
///
/// Two entries, because there have been two renames. When a third is needed,
/// add to this list rather than replacing it: a provider running last month's
/// agent is exactly the peer this exists for.
pub const LEGACY_PREFIXES: &[&str] = &["omnuv-", "omnu-"];

/// A buyer machine's name on the hypervisor, and a gateway's.
pub fn instance(name: &str) -> String {
    format!("{PREFIX}-{name}")
}

/// A marketplace-owned worker's name on the hypervisor.
pub fn worker(worker_id: &str) -> String {
    format!("{PREFIX}-worker-{}", &worker_id[..worker_id.len().min(8)])
}

/// A Proxmox PCI resource mapping for one offered card.
///
/// **`deploy-agent.yml` writes these and this reads them**, so the two move
/// together or neither does — which is exactly what went wrong when the pool
/// was renamed on one side only.
pub fn gpu_mapping(pci: &str) -> String {
    format!("{PREFIX}-gpu-{}", pci.replace([':', '.'], "-"))
}

/// The short tag that keys a machine to its marketplace id.
///
/// Proxmox tags cannot hold a hyphenated UUID cleanly, so a truncated form
/// keys the association. Collisions are implausible at this scale and would
/// only ever affect this agent's own machines.
pub fn short_tag(id: &str) -> String {
    format!("{PREFIX}-{}", id.replace('-', "").chars().take(12).collect::<String>())
}

/// Every tag a machine this agent creates carries, in one place.
///
/// Three things, answering three different questions:
///
/// ```text
/// onv-instance   what this is, and that the marketplace owns it. The claim
/// onv-<12 hex>   which marketplace resource it is. The key
/// onv-<env>      which deployment built it: prod, test, dev. Not a claim
/// ```
///
/// **The environment is not a claim, and that distinction is load-bearing.**
/// `onv-test` says where a machine lives and authorizes nothing; only the first
/// tag makes a machine the marketplace's to remove. A sweep that matched
/// anything beginning `onv-` would eat a build rig, which is why matching is by
/// whole token against the three claim constants and never by prefix.
///
/// **One function, because two call sites is how a grammar drifts.** The
/// instance driver and the worker driver each built this string themselves, and
/// a third kind would have built it a third way. A machine created before an
/// environment was configured carries two tags and is still matched: the claim
/// and the key are what anything looks for.
pub fn tags(claim: &str, id: &str, environment: Option<&str>) -> String {
    let mut out = format!("{claim};{}", short_tag(id));
    if let Some(env) = environment.map(str::trim).filter(|e| !e.is_empty()) {
        out.push_str(&format!(";{PREFIX}-{env}"));
    }
    out
}

/// The cloud-init snippet a machine of each kind reads at first boot.
pub fn snippet_instance(id: &str) -> String {
    format!("{PREFIX}-instance-{id}.yaml")
}

/// The cloud-init **network** config a machine reads, before networkd starts.
///
/// Separate from the user-data snippet because cloud-init reads them at
/// different times, and that difference is the whole reason this file exists:
/// network config is rendered in `init-local`, *before* `systemd-networkd`,
/// while `bootcmd` in the user data runs later, in `init`, after cloud-init has
/// already tried and failed to wait for the network.
pub fn snippet_network(id: &str) -> String {
    format!("{PREFIX}-net-{id}.yaml")
}

/// The cloud-init snippet an inference worker reads at first boot.
///
/// **Named for its kind, as of 13 September 2026.** It used to be
/// `onv-<id>.yaml` — the prefix and a uuid, and nothing saying what it was. The
/// other two snippets carry their kind (`onv-instance-…`, `onv-net-…`), and a
/// sweep needs the same of this one: without it, the only way to recognise a
/// worker snippet is to subtract the patterns you do know and delete the rest,
/// which is the shape that eats something it did not understand.
///
/// A rename is a migration, so `snippet_worker_legacy` still exists and every
/// removal path matches both. Drop it only once no provider can be holding one,
/// which is not a date anybody can predict — so it stays.
pub fn snippet_worker(id: &str) -> String {
    format!("{PREFIX}-worker-{id}.yaml")
}

/// What `snippet_worker` produced before it carried its kind. Recognised for
/// removal, never written.
pub fn snippet_worker_legacy(id: &str) -> String {
    format!("{PREFIX}-{id}.yaml")
}

/// Is this filename one of ours, and for which marketplace id?
///
/// **Recognition, not authority.** A prefix says a file looks like ours; the
/// caller still has to hold a valid claim on the id before touching it. This
/// returns the id so the caller *can* check, and `None` for anything whose
/// grammar we do not know — which is reported rather than collected.
pub fn snippet_owner(filename: &str) -> Option<(SnippetKind, &str)> {
    let rest = filename.strip_prefix(PREFIX)?.strip_prefix('-')?;
    let body = rest.strip_suffix(".yaml")?;
    for (prefix, kind) in [
        ("instance-", SnippetKind::Instance),
        ("net-", SnippetKind::Network),
        ("worker-", SnippetKind::Worker),
    ] {
        if let Some(id) = body.strip_prefix(prefix) {
            return (!id.is_empty()).then_some((kind, id));
        }
    }
    // No kind: the legacy worker name. Only a uuid-shaped body qualifies, so
    // `onv-snippets` itself or a hand-made `onv-notes.yaml` is not mistaken for
    // a machine's file.
    let uuidish = body.len() == 36
        && body.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
        && body.matches('-').count() == 4;
    uuidish.then_some((SnippetKind::WorkerLegacy, body))
}

/// Which kind of machine a snippet belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnippetKind {
    Instance,
    Network,
    Worker,
    /// A worker snippet written before the rename. Its origin is ours by
    /// grammar, but a file of uncertain origin is reported rather than removed.
    WorkerLegacy,
}

/// The range this provider numbers its marketplace segments from.
///
/// **The driver's choice, as of protocol 5**, because a segment is
/// per-project, per-provider and has no uplink: an address on it needs to be
/// unique on that one wire and nowhere else. Core used to send the address and
/// the prefix, which made it responsible for numbering a network it cannot
/// see — the same mistake as naming the bridge, one field along.
///
/// The same range on every provider and in every project on purpose. Two
/// segments never meet: different vnets, no routing between them, and nothing
/// beyond this provider is reached over the segment at all. What must not
/// collide is two machines *on one segment*, and `segment_address` keys that on
/// the VMID, which Proxmox guarantees unique per node.
///
/// Outside the marketplace's own pools (`10.200.0.0/13` for project networks,
/// `10.208.0.0/13` for overlay peers) so that a capture is never ambiguous
/// about which layer an address belongs to.
pub const SEGMENT_RANGE: &str = "10.216.0.0/16";

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

/// The per-network segment on this provider.
///
/// A Proxmox SDN id is at most eight alphanumerics starting with a letter, so
/// `onv` plus five hex digits of the network id fits exactly where the old `o`
/// plus seven did — and reads as ours rather than as line noise.
///
/// **The same network gets the same name on every provider it touches, and
/// those bridges have no relationship whatsoever.** A segment is only
/// meaningful qualified by its provider; `CLAUDE.md` carries that as a rule,
/// and Core is forbidden from deriving this name at all.
pub fn vnet(network_id: &str) -> String {
    let hex: String = network_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(5)
        .collect::<String>()
        .to_ascii_lowercase();
    format!("{PREFIX}{hex}")
}

/// Writes a file that holds a secret, with `mode` from the moment it exists.
///
/// `fs::write` creates a file with the process umask (world-readable under the
/// usual 022) and a `chmod` afterwards leaves a window in which anyone on the
/// host can read it; and a file that already existed keeps whatever mode it
/// had. So the file is created with `mode`, and re-tightened if it existed.
pub fn write_private(path: &str, contents: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)?;
    f.set_permissions(std::fs::Permissions::from_mode(mode))?;
    f.write_all(contents)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::write_private;

    /// Born with its mode, and a file that already existed wider is tightened.
    #[test]
    fn a_secret_file_is_never_wider_than_its_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("onv-private-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret");
        let p = path.to_str().unwrap();

        write_private(p, b"one", 0o600).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(p, b"two", 0o640).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o640);
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    use super::*;

    #[test]
    fn everything_we_create_says_onv() {
        // The rule in CLAUDE.md, as a test. It has been half-true three times:
        // tags renamed but not machine names, the pool renamed in the agent but
        // not in the play, the nft table renamed in the unit but not in the
        // template it loads. A prefix that holds only where somebody remembered
        // is not a prefix you can check a host against at two in the morning.
        assert!(instance("gpu-1").starts_with("onv-"));
        assert!(worker("2f8a1c0d-dead-beef-0000-000000000000").starts_with("onv-"));
        assert!(gpu_mapping("0000:21:00.0").starts_with("onv-"));
        assert!(short_tag("2f8a1c0d-dead-beef").starts_with("onv-"));
        assert!(snippet_instance("x").starts_with("onv-"));
        assert!(snippet_network("x").starts_with("onv-"));
        assert!(snippet_worker("x").starts_with("onv-worker-"));
        assert_eq!(snippet_worker_legacy("x"), "onv-x.yaml");
        assert!(vnet("c4d90fd2-be3d").starts_with("onv"));
        for n in [POOL, POOL_BUYERS, STORAGE_SNIPPETS, SDN_ZONE, SDN_ZONE_NAT,
                  TAG_INSTANCE, TAG_GATEWAY, TAG_WORKER, AGENT, EGRESS_TABLE] {
            assert!(n.starts_with(PREFIX), "{n} does not start with {PREFIX}");
        }
        for p in [ETC, VAR, LOG, RUN] {
            assert!(p.ends_with("/onv"), "{p} is not an onv path");
        }
    }

    #[test]
    fn the_gpu_mapping_is_what_proxmox_accepts_as_an_id() {
        // Colons and dots are not allowed in a mapping id; the play builds the
        // same string with `tr ':.' '--'`.
        assert_eq!(gpu_mapping("0000:21:00.0"), "onv-gpu-0000-21-00-0");
    }

    #[test]
    fn a_vnet_id_fits_what_proxmox_accepts() {
        let v = vnet("c4d90fd2-be3d-4225-a4a6-265138a76e49");
        assert_eq!(v, "onvc4d90");
        // Proxmox: at most 8 alphanumerics, starting with a letter.
        assert!(v.len() <= 8, "{v} is longer than Proxmox allows");
        assert!(v.chars().next().unwrap().is_ascii_alphabetic());
        assert!(v.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn hyphens_do_not_eat_the_digits() {
        // The id arrives hyphenated; filtering non-alphanumerics before taking
        // five is what stops `onvc4d9` losing a digit to a separator.
        assert_eq!(vnet("c4d9-0fd2"), "onvc4d90");
    }

    /// **Two machines on one segment must never share an address**, and a
    /// segment holds one project's machines on one provider — so uniqueness is
    /// needed per VMID, which is what the hypervisor guarantees.
    #[test]
    fn no_two_vmids_on_a_segment_share_an_address() {
        use std::collections::HashSet;
        // A provider will not run 4 000 marketplace machines, and this is the
        // range Proxmox actually hands out.
        let seen: HashSet<String> = (100..4_000).map(segment_address).collect();
        assert_eq!(seen.len(), 3_900, "two VMIDs collided");
    }

    /// Never a network or broadcast address, whatever the VMID.
    #[test]
    fn every_segment_address_is_a_usable_host() {
        for vmid in [100u32, 353, 354, 607, 100_000] {
            let a = segment_address(vmid);
            let last: u32 = a.rsplit('.').next().unwrap().parse().unwrap();
            assert!((1..=254).contains(&last), "{a} is not a host address");
            assert!(a.starts_with("10.216."), "{a} is outside the segment range");
        }
    }

    /// It is a pure function of the VMID: the same machine gets the same
    /// address on every pass, so a reconcile never renumbers it.
    #[test]
    fn the_segment_address_is_stable() {
        assert_eq!(segment_address(103), segment_address(103));
        assert_ne!(segment_address(103), segment_address(104));
    }

    /// The segment range must not overlap the marketplace's own pools, or a
    /// capture is ambiguous about which layer an address belongs to.
    #[test]
    fn the_segment_range_is_outside_the_marketplace_pools() {
        // 10.200.0.0/13 is project networks, 10.208.0.0/13 is overlay peers.
        for a in [segment_address(100), segment_address(3_999)] {
            let second: u32 = a.split('.').nth(1).unwrap().parse().unwrap();
            assert!(!(200..=215).contains(&second), "{a} overlaps a marketplace pool");
        }
    }

    /// Proxmox caps an SDN id at eight characters, and every id we mint has to
    /// fit — including the one that was shortened to `onat0` on the belief that
    /// it did not.
    #[test]
    fn every_sdn_id_fits_proxmoxs_eight_characters() {
        for id in [SDN_ZONE, SDN_ZONE_NAT, NAT_VNET, NAT_VNET_LEGACY, &vnet("c4d90fd2-be3d-4225-a4a6-265138a76e49")] {
            assert!(id.len() <= 8, "{id} is {} characters", id.len());
            assert!(
                id.chars().next().is_some_and(|c| c.is_ascii_alphabetic()),
                "{id} must start with a letter"
            );
            assert!(id.chars().all(|c| c.is_ascii_alphanumeric()), "{id} is not alphanumeric");
        }
        // And the current name says `onv`, which the shortened one did not.
        assert!(NAT_VNET.starts_with(PREFIX), "{NAT_VNET} does not say {PREFIX}");
        assert_ne!(NAT_VNET, NAT_VNET_LEGACY, "a rename needs both names to exist");
    }

    #[test]
    fn every_name_carries_the_prefix() {
        for n in [AGENT, EGRESS_UNIT, POOL, POOL_BUYERS, STORAGE_SNIPPETS,
                  SDN_ZONE, SDN_ZONE_NAT, TAG_INSTANCE, TAG_GATEWAY, TAG_WORKER] {
            assert!(n.starts_with(PREFIX), "{n} does not start with {PREFIX}");
        }
        for p in [ETC, VAR, LOG, RUN] {
            assert!(p.contains(PREFIX), "{p} does not contain {PREFIX}");
        }
        assert!(EGRESS_TABLE.starts_with(PREFIX));
        assert!(PVE_USER.starts_with(PREFIX));
    }

    #[test]
    fn the_old_names_are_still_recognised() {
        // A machine built before a rename must still be identifiable, or a
        // removal play walks past it.
        assert!(LEGACY_PREFIXES.contains(&"omnuv-"));
        assert!(LEGACY_PREFIXES.contains(&"omnu-"));
        assert!(!LEGACY_PREFIXES.iter().any(|p| p.starts_with(PREFIX)));
    }
}

#[cfg(test)]
mod snippet_grammar_tests {
    use super::*;

    /// Both generations are recognised, with their kind and their id. A rename
    /// that stopped matching the old name would leave every file written before
    /// it on the provider forever.
    #[test]
    fn both_worker_generations_are_recognised() {
        let id = "b3e77a10-5c44-4de9-8f02-91ab6e4c7d58";
        assert_eq!(snippet_owner(&snippet_worker(id)), Some((SnippetKind::Worker, id)));
        assert_eq!(
            snippet_owner(&snippet_worker_legacy(id)),
            Some((SnippetKind::WorkerLegacy, id))
        );
        assert_eq!(snippet_owner(&snippet_instance(id)), Some((SnippetKind::Instance, id)));
        assert_eq!(snippet_owner(&snippet_network(id)), Some((SnippetKind::Network, id)));
    }

    /// **A prefix is recognition, not authority.** Anything whose grammar we do
    /// not know returns `None`, so a caller cannot mistake it for a machine's
    /// file — and the sweep reports those rather than collecting them.
    #[test]
    fn a_prefix_alone_is_not_a_claim() {
        for name in [
            "onv-notes.yaml",            // ours by prefix, no id: not a machine's
            "onv-.yaml",                 // empty id
            "onv-worker-.yaml",          // empty id, with a kind
            "onv-snippets",              // the storage, not a snippet
            "user-data.yaml",            // somebody else's
            "onv-b3e77a10.yaml",         // short: not a uuid, so not the legacy name
            "onv-instance-x.yml",        // wrong extension
        ] {
            assert_eq!(snippet_owner(name), None, "{name} was claimed");
        }
    }
}

#[cfg(test)]
mod tag_grammar {
    use super::*;

    #[test]
    fn a_machine_carries_its_claim_its_key_and_its_environment() {
        let t = tags(TAG_INSTANCE, "3f2a1b4c-5d6e-7f80-9112-233445566778", Some("test"));
        assert_eq!(t, "onv-instance;onv-3f2a1b4c5d6e;onv-test");
        // Whole tokens, never a prefix: this is what a sweep matches on.
        let parts: Vec<_> = t.split(';').collect();
        assert!(parts.contains(&TAG_INSTANCE));
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn an_unstamped_agent_still_produces_what_everything_matches_on() {
        // An agent deployed before `environment` existed. Its machines carry
        // the claim and the key, which is what finds them.
        for absent in [None, Some(""), Some("   ")] {
            let t = tags(TAG_WORKER, "aaaa-bbbb", absent);
            assert_eq!(t, format!("{TAG_WORKER};{}", short_tag("aaaa-bbbb")), "{absent:?}");
        }
    }

    #[test]
    fn the_environment_is_not_a_claim() {
        // The 18 September rule, as a test: `onv-test` names where a machine
        // lives and authorizes nothing. Only the first token claims it.
        let t = tags(TAG_INSTANCE, "id", Some("test"));
        let claims: Vec<_> = t.split(';')
            .filter(|p| [TAG_INSTANCE, TAG_GATEWAY, TAG_WORKER].contains(p))
            .collect();
        assert_eq!(claims, vec![TAG_INSTANCE]);
        assert!(!["onv-test", "onv-prod", "onv-dev"]
            .iter()
            .any(|e| [TAG_INSTANCE, TAG_GATEWAY, TAG_WORKER].contains(e)));
    }
}
