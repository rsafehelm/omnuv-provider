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

/// Whether a VM's configuration is a template the marketplace built, mirrored
/// or by `build-template.yml`, in either generation of wording ("Omnuv" or
/// "Onv" marketplace base image). Loose on the wording for the reason
/// `destroy-templates.yml` gives; strict on being a template at all.
pub fn is_marketplace_template(cfg: &serde_json::Value) -> bool {
    cfg.get("template").and_then(serde_json::Value::as_u64) == Some(1)
        && cfg
            .get("description")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|d| d.contains("marketplace base image"))
}

/// Whether a guest at this image's vmid is **this import's own unfinished
/// work** (PROVIDER-9): created with the name and description the mirror gives
/// this image, never made a template, carrying no claim. The import is five
/// calls and a template flag is the last of them; a failure anywhere in
/// between left a guest that `is_marketplace_template` rightly refuses to call
/// a template, and so every later retry refused with "is a machine, not a
/// template" — the mirror wedged on its own debris for ever.
///
/// Strict on purpose, because the answer licenses a destroy. Anything short of
/// all four — another image's name, an operator's wording, a claim tag, a
/// template — is somebody's machine and is left alone. That it is not running
/// is checked separately, live, by the caller.
pub fn is_unfinished_import(cfg: &serde_json::Value, id: &str) -> bool {
    let text = |k: &str| cfg.get(k).and_then(serde_json::Value::as_str).unwrap_or_default();
    let never_a_template = cfg.get("template").and_then(serde_json::Value::as_u64) != Some(1);
    let our_name = text("name") == format!("{}-{id}", crate::names::PREFIX);
    let our_words = text("description").starts_with(&format!("Onv marketplace base image - {id}."))
        && text("description").contains(DIGEST_MARKER);
    let claimed = text("tags").split(&[';', ','][..]).map(str::trim).any(|t| {
        [crate::names::TAG_INSTANCE, crate::names::TAG_WORKER, crate::names::TAG_GATEWAY].contains(&t)
    }) || crate::instance::is_legacy_marketplace_tag(text("tags"));
    never_a_template && our_name && our_words && !claimed
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

/// Remove partial downloads for artefacts nothing is fetching.
///
/// A partial is `<id>.part` beside a `<id>.part.sha256` sidecar, and the
/// download path only ever looks at the partial for the id it is fetching. So a
/// partial for an image this host already holds, or no longer offers, is never
/// read, never resumed and never removed: one from an interrupted transfer sat
/// in the import directory at 2.24 GB with its template long since built.
///
/// `keep` is the set of ids the current pass is still fetching. Only files
/// ending exactly in `.part` or `.part.sha256` are candidates, so a finished
/// `.qcow2` is never touched. Returns what was removed.
pub fn reap_stale_partials(dir: &std::path::Path, keep: &[&str]) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut removed = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let id = name
            .strip_suffix(".part.sha256")
            .or_else(|| name.strip_suffix(".part"));
        if let Some(id) = id
            && !keep.contains(&id)
            && std::fs::remove_file(entry.path()).is_ok()
        {
            removed.push(name);
        }
    }
    removed.sort();
    removed
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
        // Our own half-built import is cleared like a template of ours. It was
        // never started, and a live read proves it is not running now.
        let ours_unfinished = is_unfinished_import(&cfg, id) && {
            let status: serde_json::Value =
                px.get_json(&format!("/nodes/{node}/qemu/{vmid}/status/current")).await?;
            status.get("status").and_then(serde_json::Value::as_str) == Some("stopped")
        };
        anyhow::ensure!(
            ours_unfinished || cfg.get("template").and_then(serde_json::Value::as_u64) == Some(1),
            "vmid {vmid} on {node} is a machine, not a template — refusing to import over it"
        );
        // **A template, and ours.** Being a template was the only check, so an
        // operator's own template at a vmid the configuration names would have
        // been destroyed. Ours say so in their description, in the words the
        // mirror and `build-template.yml` both write, the same test
        // `destroy-templates.yml` applies before it destroys one.
        anyhow::ensure!(
            ours_unfinished || is_marketplace_template(&cfg),
            "vmid {vmid} on {node} is a template the marketplace did not build — refusing to import over it"
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

    /// **PROVIDER-9: this import's own debris, and nothing that resembles it.**
    #[test]
    fn only_this_imports_unfinished_guest_is_recognised() {
        let debris = |name: &str, desc: String, template: u64, tags: &str| {
            serde_json::json!({"name": name, "description": desc, "template": template, "tags": tags})
        };
        let ours = super::description("ubuntu-2604", "ab12");
        assert!(super::is_unfinished_import(&debris("onv-ubuntu-2604", ours.clone(), 0, ""), "ubuntu-2604"));
        for (why, cfg) in [
            ("a finished template", debris("onv-ubuntu-2604", ours.clone(), 1, "")),
            ("another image's", debris("onv-debian-13", super::description("debian-13", "ab12"), 0, "")),
            ("a different name", debris("my-vm", ours.clone(), 0, "")),
            ("a buyer's machine", debris("onv-ubuntu-2604", ours.clone(), 0, "onv-instance;onv-0a0b0c0d0e0f")),
            ("an older claim", debris("onv-ubuntu-2604", ours.clone(), 0, "omnuv-instance")),
            ("build-template's wording", debris("onv-ubuntu-2604", "Omnuv marketplace base image".into(), 0, "")),
            ("no description", serde_json::json!({"name": "onv-ubuntu-2604", "template": 0})),
        ] {
            assert!(!super::is_unfinished_import(&cfg, "ubuntu-2604"), "{why} was taken for this import's debris");
        }
    }

    /// Through `import`: its own stopped debris is cleared and the import goes
    /// on; the same debris *running* is refused; an operator's machine at the
    /// vmid is refused. The refusals are asserted by what was never deleted.
    #[tokio::test]
    async fn an_import_clears_its_own_debris_and_nothing_else() {
        use crate::pvemock::{task_ok, Mock};
        let run = |config: serde_json::Value, status: &'static str| async move {
            let mock = Mock::start(move |method, path, _| {
                if let Some(ok) = task_ok(path) {
                    return ok;
                }
                match (method, path) {
                    ("GET", "/nodes/n1/qemu/9001/config") => (200, config.clone()),
                    ("GET", "/nodes/n1/qemu/9001/status/current") => (200, serde_json::json!({"status": status})),
                    ("DELETE", _) => (200, serde_json::json!("UPID:n1:del")),
                    ("POST", _) => (200, serde_json::json!("UPID:n1:post")),
                    ("GET", _) | ("PUT", _) => (200, serde_json::json!({})),
                    _ => (404, serde_json::Value::Null),
                }
            })
            .await;
            let result = super::import(&mock.client(), "n1", "local-lvm", "local", "ubuntu-2604", 9001, "ab12").await;
            let deleted = mock.calls.lock().unwrap().iter().any(|c| c.method == "DELETE" && c.path.starts_with("/nodes/n1/qemu/9001"));
            (result, deleted)
        };
        let debris = serde_json::json!({"name": "onv-ubuntu-2604", "template": 0,
                                        "description": super::description("ubuntu-2604", "old")});

        let (result, deleted) = run(debris.clone(), "stopped").await;
        assert!(result.is_ok(), "its own debris wedged the import: {result:?}");
        assert!(deleted, "the debris was not cleared");

        let (result, deleted) = run(debris, "running").await;
        assert!(result.is_err() && !deleted, "a running guest was destroyed for an import");

        let operators = serde_json::json!({"name": "db-1", "template": 0, "description": "production database"});
        let (result, deleted) = run(operators, "stopped").await;
        assert!(result.is_err() && !deleted, "an operator's machine was destroyed for an import");
    }
    use super::is_marketplace_template;
    use serde_json::json;

    #[test]
    fn only_a_marketplace_template_is_replaced() {
        for ours in [
            "Onv marketplace base image - ubuntu-26.04. Mirrored by the provider agent",
            "Omnuv marketplace base image - Ubuntu 26.04 cloud-init. Managed by Ansible; do not edit.",
        ] {
            assert!(is_marketplace_template(&json!({"template": 1, "description": ours})), "{ours}");
        }
        // Negative: an operator's template, a template with no description, and
        // our wording on something that is not a template.
        assert!(!is_marketplace_template(&json!({"template": 1, "description": "my golden image"})));
        assert!(!is_marketplace_template(&json!({"template": 1})));
        assert!(!is_marketplace_template(
            &json!({"template": 0, "description": "Onv marketplace base image - x"})
        ));
    }

    /// A partial for an id still being fetched survives, a partial for any
    /// other id goes with its sidecar, and a finished artefact is never a
    /// candidate whatever its id.
    #[test]
    fn stale_partials_go_and_nothing_else_does() {
        let d = tempfile::tempdir().unwrap();
        for f in ["old.part", "old.part.sha256", "live.part", "live.part.sha256",
                  "old.qcow2", "notes.txt"] {
            std::fs::write(d.path().join(f), b"x").unwrap();
        }
        let removed = super::reap_stale_partials(d.path(), &["live"]);
        assert_eq!(removed, vec!["old.part", "old.part.sha256"]);
        for f in ["live.part", "live.part.sha256", "old.qcow2", "notes.txt"] {
            assert!(d.path().join(f).exists(), "{f} should have survived");
        }
        assert!(super::reap_stale_partials(&d.path().join("absent"), &[]).is_empty());
    }

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
