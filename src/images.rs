//! Mirroring the marketplace's published images.
//!
//! **The provider fetches; nobody puts an image on a provider by hand.** That
//! is the whole point of the catalogue, and it is what makes an image id mean
//! one machine instead of "whatever each host happened to build".
//!
//! Before this, every provider ran the build itself: half an hour of driver
//! install per host, against a public mirror, producing bytes nobody could
//! compare. Three times in one week that mirror was mid-sync and the build
//! failed — once while a buyer watched. Worse, "which provider holds which id"
//! was a claim read out of the agent's own configuration file, where a
//! template that was never built and one that was deleted advertise exactly
//! the same thing.
//!
//! So Core publishes an artefact and its digest; the agent downloads it,
//! **verifies the digest before importing**, and reports back the digests it
//! actually holds. A provider may decline an image — disk and bandwidth are
//! its operational cost, and fewer images simply means fewer opportunities to
//! earn. It may never redefine one.
//!
//! ## Why the file goes into a Proxmox storage rather than any old path
//!
//! The agent's token deliberately lacks `Sys.Modify`, and PVE is explicit
//! about what that costs (`PVE::Storage::check_volume_access`):
//!
//! ```text
//! die "Only root can pass arbitrary filesystem paths." if $user ne 'root@pam';
//! ```
//!
//! So `import-from=/var/lib/onv/…` is refused, by design, and the right answer
//! is not to widen the role. A storage of content type `import` needs only
//! `Datastore.AllocateSpace` or `Datastore.Audit`, both of which the agent
//! already holds, so the artefact lands there and is referenced as a volume id.
//!
//! ## What the agent does not build
//!
//! An image importer. `CLAUDE.md` lists one among the things we never write our
//! own of, and Proxmox's `import-from` already is one. The agent downloads,
//! hashes, and asks Proxmox to do the import.

use omnuv_protocol::{HeldImage, ImageArtefact};

/// The line a template's description carries, naming the digest of the
/// artefact it was imported from.
///
/// **In the runtime object, not in a file beside it.** A sidecar drifts the
/// moment somebody destroys a template without deleting it, and then the agent
/// reports holding an image that is not there. Proxmox stores the description
/// with the VM, so the claim and the thing it describes are destroyed together.
const DIGEST_MARKER: &str = "onv-artefact-sha256:";

/// The description a mirrored template carries. The wording keeps
/// `destroy-templates.yml` working, which matches loosely on "marketplace base
/// image" precisely so a rename cannot make a removal play refuse to remove.
fn description(id: &str, sha256: &str) -> String {
    format!(
        "Onv marketplace base image - {id}. Mirrored by the provider agent from \
         the marketplace catalogue; do not edit.\n{DIGEST_MARKER} {sha256}"
    )
}

/// The digest a template says it was imported from, if it says.
///
/// A template without the marker was built locally by `build-template.yml`
/// rather than mirrored. That is not an error — it is every provider built
/// before the catalogue existed — and it is reported as *not held*, because
/// what it holds cannot be compared to what the marketplace published.
pub fn digest_in(description: &str) -> Option<String> {
    description.lines().find_map(|l| {
        let rest = l.trim().strip_prefix(DIGEST_MARKER)?;
        let hex = rest.trim();
        (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
            .then(|| hex.to_string())
    })
}

/// The file name an artefact takes inside the import storage.
///
/// `.qcow2` is not decoration: `PVE::Storage::Plugin::parse_volname` matches
/// `import/<name>$IMPORT_EXT_RE_1`, and that regex is
/// `\.(ova|ovf|qcow2|raw|vmdk)`. A file without one of those suffixes is not a
/// volume at all and the import is refused with a parse error.
pub fn artefact_file(id: &str) -> String {
    format!("{id}.qcow2")
}

/// The volume id Proxmox imports from, for an artefact already on disk.
pub fn artefact_volid(storage: &str, id: &str) -> String {
    format!("{storage}:import/{}", artefact_file(id))
}

/// Hashes a file, in blocks, without reading it into memory.
///
/// These are several gigabytes. The digest is checked twice — once as the
/// bytes arrive, and once here from disk before the import — because the two
/// answer different questions: the first says the download was not corrupted,
/// the second says the file that is about to be imported is still the file
/// that was downloaded.
pub fn digest_of_file(path: &std::path::Path) -> anyhow::Result<String> {
    use sha2::Digest as _;
    use std::io::Read as _;

    let mut f = std::fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Which catalogue entries this provider should be holding, and is not.
///
/// Only images the provider offers: the catalogue is what the marketplace
/// publishes, not an instruction. An entry the provider does not offer is
/// ignored, and one it offers at the right digest is left alone — re-importing
/// bytes that are already here would cost an hour and change nothing.
pub fn outstanding<'a>(
    catalogue: &'a [ImageArtefact],
    offered: &std::collections::BTreeMap<String, u32>,
    held: &[HeldImage],
) -> Vec<(&'a ImageArtefact, u32)> {
    catalogue
        .iter()
        .filter_map(|a| {
            let vmid = *offered.get(&a.id)?;
            let current = held.iter().find(|h| h.id == a.id).map(|h| h.sha256.as_str());
            (current != Some(a.sha256.as_str())).then_some((a, vmid))
        })
        .collect()
}

/// What this provider actually holds, read from the templates themselves.
///
/// **Observed, never inferred from having fetched.** The invariant is written
/// down: *observed state is written only from observation*. A mirror run that
/// succeeded is not evidence a template is there a week later — somebody may
/// have destroyed it — and reporting a cached success would make Core place
/// machines on an image that does not exist.
///
/// An id the provider offers but cannot be read, or that is not a template, or
/// whose description carries no marker, is simply absent from the result. That
/// is the honest answer: not held, as far as anything can tell.
pub async fn held(
    px: &crate::proxmox::Client,
    node: &str,
    offered: &std::collections::BTreeMap<String, u32>,
) -> Vec<HeldImage> {
    let mut out = Vec::new();
    for (id, vmid) in offered {
        let cfg: serde_json::Value =
            match px.get_json(&format!("/nodes/{node}/qemu/{vmid}/config")).await {
                Ok(c) => c,
                // No such VM on this node. Not an error to report upward: an
                // operator may have listed an image this host has not mirrored
                // yet, which is exactly the state this loop exists to fix.
                Err(_) => continue,
            };
        // A template, not a running machine. Importing over somebody's VM
        // because a vmid was mistyped is the one failure here that cannot be
        // undone, so it is checked before anything is written.
        if cfg.get("template").and_then(serde_json::Value::as_u64) != Some(1) {
            continue;
        }
        let desc = cfg.get("description").and_then(serde_json::Value::as_str).unwrap_or_default();
        if let Some(sha256) = digest_in(desc) {
            out.push(HeldImage { id: id.clone(), sha256 });
        }
    }
    out
}

/// Turns a verified artefact on disk into a template at `vmid`.
///
/// The shape matches what `build-template.yml` produces, because a buyer's
/// machine is cloned from either and must not be able to tell which: UEFI and
/// q35 (the 26.04 cloud image is UEFI-only and silently never boots under
/// SeaBIOS), a serial console, and a cloud-init drive.
///
/// **Proxmox's own guard is what protects linked clones.** An earlier draft
/// reimplemented `build-template.yml`'s ZFS origin check here; it does not
/// belong in the agent, and it would be a second implementation of a rule the
/// hypervisor already enforces — `qm destroy` refuses a base image that has
/// linked clones. If the destroy fails, so does the mirror, and the id is
/// reported as not held.
pub async fn import(
    px: &crate::proxmox::Client,
    node: &str,
    storage: &str,
    import_storage: &str,
    id: &str,
    vmid: u32,
    sha256: &str,
) -> anyhow::Result<()> {
    // **Everything that can be checked is checked before anything is
    // destroyed.** The window below cannot be closed — the vmid *is* the
    // image's identity here, so the replacement cannot be built beside the
    // original and swapped — but it can be made very unlikely to be entered
    // for a reason that was knowable in advance.
    //
    // On 12 September it was entered for exactly such a reason: the pool the
    // create names did not exist, so Titan's template was destroyed and
    // nothing replaced it. Proxmox reports that as "Permission check failed",
    // which is not a sentence anyone connects to a missing pool.
    anyhow::ensure!(
        px.get_json::<serde_json::Value>(&format!("/pools/{}", crate::names::POOL))
            .await
            .is_ok(),
        "pool '{}' does not exist on {node}; not destroying the existing template \
         for an import that would fail",
        crate::names::POOL
    );
    anyhow::ensure!(
        px.get_json::<serde_json::Value>(&format!("/nodes/{node}/storage/{storage}/status"))
            .await
            .is_ok(),
        "storage '{storage}' does not answer on {node}; not destroying the existing \
         template for an import that would fail"
    );

    // Retire whatever is there. Only ever a template: `held` refuses to look
    // at anything else, and this refuses to remove anything else.
    //
    // **This destroys before it can prove the replacement will build**, and on
    // 12 September that cost Titan its `ubuntu-26.04` template: the old one was
    // destroyed, the create failed on a misnamed pool, and the provider was
    // left holding nothing. There is no way around the window — the vmid is
    // the image's identity here, so the replacement cannot be built beside the
    // original and swapped.
    //
    // What makes it survivable is the reconciler, not cleverness: `held` reads
    // the templates rather than remembering them, so the provider immediately
    // and correctly reports that it no longer has the image, and the next pass
    // two minutes later tries again. A provider mid-mirror is a provider with
    // one fewer image, which is a state the marketplace already models.
    if let Ok(cfg) =
        px.get_json::<serde_json::Value>(&format!("/nodes/{node}/qemu/{vmid}/config")).await
    {
        anyhow::ensure!(
            cfg.get("template").and_then(serde_json::Value::as_u64) == Some(1),
            "vmid {vmid} on {node} is a machine, not a template — refusing to import over it"
        );
        let upid: String = px.delete_task(&format!("/nodes/{node}/qemu/{vmid}?purge=1")).await?;
        px.wait_task(node, &upid).await?;
    }

    let upid: String = px
        .post_form(
            &format!("/nodes/{node}/qemu"),
            &[
                ("vmid".to_string(), vmid.to_string()),
                ("name".to_string(), format!("{}-{}", crate::names::PREFIX, id)),
                ("memory".to_string(), "4096".to_string()),
                ("cores".to_string(), "2".to_string()),
                ("cpu".to_string(), "host".to_string()),
                ("machine".to_string(), "q35".to_string()),
                ("bios".to_string(), "ovmf".to_string()),
                ("scsihw".to_string(), "virtio-scsi-single".to_string()),
                ("ostype".to_string(), "l26".to_string()),
                ("agent".to_string(), "enabled=1".to_string()),
                ("net0".to_string(), "virtio,bridge=vmbr0".to_string()),
                ("pool".to_string(), crate::names::POOL.to_string()),
                ("description".to_string(), description(id, sha256)),
            ],
        )
        .await?;
    px.wait_task(node, &upid).await?;

    // The import itself, and the only step that moves gigabytes. Proxmox reads
    // the volume, converts it onto `storage`, and owns every part of that — we
    // do not write an image importer, we ask the one that exists.
    let _: serde_json::Value = px
        .put_form(
            &format!("/nodes/{node}/qemu/{vmid}/config"),
            &[(
                "scsi0".to_string(),
                format!(
                    "{storage}:0,import-from={},discard=on,ssd=1",
                    artefact_volid(import_storage, id)
                ),
            )],
        )
        .await?;

    let _: serde_json::Value = px
        .put_form(
            &format!("/nodes/{node}/qemu/{vmid}/config"),
            &[
                (
                    "efidisk0".to_string(),
                    format!("{storage}:0,efitype=4m,pre-enrolled-keys=0"),
                ),
                ("ide2".to_string(), format!("{storage}:cloudinit")),
                ("boot".to_string(), "order=scsi0".to_string()),
                ("serial0".to_string(), "socket".to_string()),
                ("vga".to_string(), "serial0".to_string()),
            ],
        )
        .await?;

    let _: serde_json::Value =
        px.post_form(&format!("/nodes/{node}/qemu/{vmid}/template"), &[] as &[(String, String)]).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artefact(id: &str, sha: &str) -> ImageArtefact {
        ImageArtefact {
            id: id.into(),
            sha256: sha.into(),
            bytes: 1,
            url: "https://example.invalid/x".into(),
        }
    }

    const A: &str = "4d3e9997536968ae6ec7f0cf51b953e4523b3ff319bdf558e2f16e5295525620";
    const B: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn a_template_reports_the_digest_it_was_imported_from() {
        assert_eq!(digest_in(&description("ubuntu-26.04", A)).as_deref(), Some(A));
    }

    #[test]
    fn a_locally_built_template_claims_nothing() {
        // What `build-template.yml` writes. Not an error: it predates the
        // catalogue, and the honest report is "I cannot compare this".
        assert_eq!(
            digest_in("Omnuv marketplace base image - Ubuntu 26.04 cloud-init. Managed by Ansible."),
            None
        );
    }

    #[test]
    fn a_malformed_marker_is_not_a_digest() {
        // Truncated, uppercase, and non-hex all have to fail closed. A bad
        // value here would be reported to Core as a digest we hold, and the
        // next comparison would silently never match.
        for bad in ["onv-artefact-sha256: deadbeef", &format!("{DIGEST_MARKER} {}", A.to_uppercase()), "onv-artefact-sha256: zz"] {
            assert_eq!(digest_in(bad), None, "accepted {bad}");
        }
    }

    #[test]
    fn only_offered_images_are_fetched() {
        let cat = vec![artefact("ubuntu-26.04", A), artefact("ubuntu-26.04-gaming", B)];
        let offered = std::collections::BTreeMap::from([("ubuntu-26.04".to_string(), 9000u32)]);
        let out = outstanding(&cat, &offered, &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.id, "ubuntu-26.04");
        assert_eq!(out[0].1, 9000);
    }

    #[test]
    fn an_image_already_held_at_that_digest_is_left_alone() {
        let cat = vec![artefact("ubuntu-26.04", A)];
        let offered = std::collections::BTreeMap::from([("ubuntu-26.04".to_string(), 9000u32)]);
        let held = vec![HeldImage { id: "ubuntu-26.04".into(), sha256: A.into() }];
        assert!(outstanding(&cat, &offered, &held).is_empty());
    }

    #[test]
    fn a_republished_image_is_fetched_again() {
        // The digest changed, so the bytes changed. Holding the old ones is
        // exactly the case the digest exists to detect.
        let cat = vec![artefact("ubuntu-26.04", B)];
        let offered = std::collections::BTreeMap::from([("ubuntu-26.04".to_string(), 9000u32)]);
        let held = vec![HeldImage { id: "ubuntu-26.04".into(), sha256: A.into() }];
        assert_eq!(outstanding(&cat, &offered, &held).len(), 1);
    }

    #[test]
    fn the_volume_id_is_one_proxmox_can_parse() {
        // `import/<name>\.(ova|ovf|qcow2|raw|vmdk)` — verified against
        // PVE::Storage::Plugin on the host, not from memory.
        let v = artefact_volid("onv-snippets", "ubuntu-26.04");
        assert_eq!(v, "onv-snippets:import/ubuntu-26.04.qcow2");
        assert!(v.ends_with(".qcow2"));
    }
}
