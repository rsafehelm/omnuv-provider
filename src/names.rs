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
pub const NAT_VNET: &str = "onat0";

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

/// The cloud-init snippet a machine of each kind reads at first boot.
pub fn snippet_instance(id: &str) -> String {
    format!("{PREFIX}-instance-{id}.yaml")
}

pub fn snippet_worker(id: &str) -> String {
    format!("{PREFIX}-{id}.yaml")
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

#[cfg(test)]
mod tests {
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
        assert!(snippet_worker("x").starts_with("onv-"));
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
