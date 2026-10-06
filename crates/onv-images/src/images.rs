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
pub const DIGEST_MARKER: &str = "onv-artefact-sha256:";

/// The description a mirrored template carries. The wording keeps
/// `destroy-templates.yml` working, which matches loosely on "marketplace base
/// image" precisely so a rename cannot make a removal play refuse to remove.
pub fn description(id: &str, sha256: &str) -> String {
    format!(
        "Onv marketplace base image - {id}. Mirrored by the provider agent from \
         the marketplace catalogue; do not edit.\n{DIGEST_MARKER} {sha256}"
    )
}

/// **The template an image is imported into**: the Linux cloud images' shape,
/// or the Windows image's, which is `build-template-windows.yml`'s.
///
/// Which one is the provider's configuration (`proxmox.windowsImages`), never
/// guessed from an id. What differs, and why it matters on a clone:
///
/// ```text
///                 Linux                  Windows
/// ostype          l26                    win11: Hyper-V enlightenments, the
///                                        clock Windows expects
/// efidisk0        no enrolled keys       Microsoft's keys: Secure Boot on, as
///                                        the build ran it
/// scsi0           discard, ssd           and iothread, as the build's disk
/// vga             serial0                std: the console a buyer opens
/// citype          (Proxmox's default)    nocloud: a Windows ostype otherwise
///                                        gets ConfigDrive v2, which
///                                        cloudbase-init's NoCloud never reads
/// tpmstate0       none                   none: each clone gets its own
/// ```
///
/// **The Windows shape is held to the build play's** by a fixture both
/// repositories read: `tests/windows/template.json` here, compared with
/// `build-template-windows.yml`'s `qm create` and `qm set` by omnuv's
/// `publish_image_windows_test.py`, and with what `import` asks Proxmox for
/// by `the_windows_import_is_the_build_plays_template` below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateShape {
    Linux,
    Windows,
}

impl TemplateShape {
    /// Whether a template's configuration is of this shape, by its `ostype`:
    /// what decides how Proxmox runs every clone. A Linux template is any
    /// that is not a Windows one, so a template built before `ostype` was
    /// written keeps being held.
    pub fn holds(self, cfg: &serde_json::Value) -> bool {
        let ostype = cfg.get("ostype").and_then(serde_json::Value::as_str).unwrap_or_default();
        match self {
            TemplateShape::Linux => !ostype.starts_with("win"),
            // **And its clock in UTC** (run fa56103c, 5 October 2026):
            // Proxmox puts a Windows guest's RTC on the host's local time
            // unless `localtime` says otherwise, the image's zone is UTC, so
            // on Pluto (WEST) a clone booted an hour ahead and Sunshine minted
            // its certificate then: "The certificate is not yet valid" to the
            // client. A template without it is imported again.
            TemplateShape::Windows => {
                ostype == "win11"
                    && cfg.get("localtime").map(|v| v.as_u64() == Some(0) || v.as_str() == Some("0")) == Some(true)
                    // And its sound card: a template without one streams
                    // silence, so it is imported again.
                    && cfg.get("audio0").and_then(serde_json::Value::as_str).is_some_and(|a| a.contains("device=ich9-intel-hda"))
            }
        }
    }
}

/// **Every value `import` gives the template**, in the three calls it makes:
/// the create, the disk's import, and the rest once the disk is there. A
/// function of its inputs alone, so a test reads the whole shape without a
/// hypervisor.
pub fn template_requests(
    shape: TemplateShape,
    id: &str,
    vmid: u32,
    sha256: &str,
    storage: &str,
    import_volid: &str,
    environment: Option<&str>,
) -> [Vec<(String, String)>; 3] {
    let kv = |k: &str, v: String| (k.to_string(), v);
    let create = vec![
        kv("vmid", vmid.to_string()),
        kv("name", format!("{}-{}", onv_agent_lib::names::PREFIX, id)),
        // Per clone, whatever the template says: the machine's own size.
        kv("memory", "4096".into()),
        kv("cores", "2".into()),
        kv("cpu", "host".into()),
        kv("machine", "q35".into()),
        kv("bios", "ovmf".into()),
        kv("scsihw", "virtio-scsi-single".into()),
        kv(
            "ostype",
            match shape {
                TemplateShape::Linux => "l26",
                TemplateShape::Windows => "win11",
            }
            .into(),
        ),
        kv("agent", "enabled=1".into()),
        kv("net0", "virtio,bridge=vmbr0".into()),
        kv("pool", onv_agent_lib::names::POOL.into()),
        kv("description", description(id, sha256)),
    ];
    let disk = vec![kv(
        "scsi0",
        match shape {
            TemplateShape::Linux => format!("{storage}:0,import-from={import_volid},discard=on,ssd=1"),
            TemplateShape::Windows => {
                format!("{storage}:0,import-from={import_volid},iothread=1,discard=on,ssd=1")
            }
        },
    )];
    let finish = match shape {
        TemplateShape::Linux => vec![
            kv("efidisk0", format!("{storage}:0,efitype=4m,pre-enrolled-keys=0")),
            kv("ide2", format!("{storage}:cloudinit")),
            kv("boot", "order=scsi0".into()),
            kv("serial0", "socket".into()),
            kv("vga", "serial0".into()),
        ],
        TemplateShape::Windows => vec![
            kv("efidisk0", format!("{storage}:1,efitype=4m,pre-enrolled-keys=1")),
            kv("ide2", format!("{storage}:cloudinit")),
            kv("citype", "nocloud".into()),
            kv("boot", "order=scsi0".into()),
            kv("serial0", "socket".into()),
            kv("vga", "std".into()),
            kv("localtime", "0".into()),
            // **A sound card**, so Sunshine has something to capture (5 Oct
            // 2026: "Couldn't get default audio endpoint [0x80070490] ...
            // The stream will not have audio"). Intel HD Audio, which Windows
            // drives with its own driver; no host backend (`none`), since the
            // sound leaves through the stream, never through the host.
            kv("audio0", "device=ich9-intel-hda,driver=none".into()),
        ],
    };
    // The deployment it belongs to, as every machine this agent makes says
    // it (`names::tags`); never a claim, so a template stays a template.
    //
    // **Set with the finish, never at create.** qemu-server 9.2.7 checks a
    // create's tags against `/vms/<vmid>` with no pool (`assert_tag_permissions`
    // in the create worker, `check_vm_perm(…, undef, ['VM.Config.Options'])`),
    // and this token's rights reach a VM only through the `onv` pool it is not
    // yet in. On Titan on 5 October 2026 every import was refused so, while
    // Pluto's 9.1.16, which checks no tags at create, imported. Once created
    // the VM is a pool member, and the finish's PUT is allowed.
    let mut finish = finish;
    if let Some(env) = environment.map(str::trim).filter(|e| !e.is_empty()) {
        finish.push(kv("tags", format!("{}-{env}", onv_agent_lib::names::PREFIX)));
    }
    [create, disk, finish]
}

/// Whether a VM's configuration is **this image's template and nothing else's**
/// (the assets-by-id audit of 3 October 2026): the only thing an import may
/// destroy to make room. The test it replaced answered "ours at all", and
/// an import used it, so the template of another image at a vmid the
/// configuration names for this one, or an operator's template described in
/// our words, was destroyed for an import. (That looser test, "a template
/// whose description says marketplace base image", is still the one
/// `destroy-templates.yml` applies, on purpose: a removal must not refuse.)
///
/// ```text
/// a template                      a machine is never retired for an image
/// no claim tag                    a buyer's or a worker's guest is not a template of ours
/// named onv-…                     everything the marketplace creates is; an operator's is not
/// first line names this whole id  "Onv marketplace base image - <id>.", which the
///                                 mirror and build-template.yml both write
/// ```
///
/// The name is checked by prefix, not as `onv-<id>`: `build-template.yml`
/// names its templates for people (`onv-ubuntu-2604-gaming` holds
/// `ubuntu-26.04-gaming`), so the description's whole id is the identity and
/// the name only says the marketplace made it. A template whose description
/// names no id — the first wording, "Omnuv marketplace base image - Ubuntu
/// 26.04 cloud-init." — cannot be proved to be this image and is refused.
pub fn is_this_images_template(cfg: &serde_json::Value, id: &str) -> bool {
    let text = |k: &str| cfg.get(k).and_then(serde_json::Value::as_str).unwrap_or_default();
    let a_template = cfg.get("template").and_then(serde_json::Value::as_u64) == Some(1);
    let our_name = text("name").starts_with(&format!("{}-", onv_agent_lib::names::PREFIX));
    let this_id = text("description")
        .lines()
        .next()
        .is_some_and(|l| l.trim_end().starts_with(&format!("Onv marketplace base image - {id}.")));
    let claimed = text("tags").split(&[';', ','][..]).map(str::trim).any(|t| {
        [onv_agent_lib::names::TAG_INSTANCE, onv_agent_lib::names::TAG_WORKER, onv_agent_lib::names::TAG_GATEWAY, onv_agent_lib::names::TAG_SCRUB]
            .contains(&t)
    }) || onv_agent_lib::names::is_legacy_marketplace_tag(text("tags"));
    a_template && our_name && this_id && !claimed
}

/// Whether a guest at this image's vmid is **this import's own unfinished
/// work** (PROVIDER-9): created with the name and description the mirror gives
/// this image, never made a template, carrying no claim. The import is five
/// calls and a template flag is the last of them; a failure anywhere in
/// between left a guest that is rightly refused as "not a template", and so every later retry refused with "is a machine, not a
/// template" — the mirror wedged on its own debris for ever.
///
/// Strict on purpose, because the answer licenses a destroy. Anything short of
/// all four — another image's name, an operator's wording, a claim tag, a
/// template — is somebody's machine and is left alone. That it is not running
/// is checked separately, live, by the caller.
pub fn is_unfinished_import(cfg: &serde_json::Value, id: &str) -> bool {
    let text = |k: &str| cfg.get(k).and_then(serde_json::Value::as_str).unwrap_or_default();
    let never_a_template = cfg.get("template").and_then(serde_json::Value::as_u64) != Some(1);
    let our_name = text("name") == format!("{}-{id}", onv_agent_lib::names::PREFIX);
    let our_words = text("description").starts_with(&format!("Onv marketplace base image - {id}."))
        && text("description").contains(DIGEST_MARKER);
    let claimed = text("tags").split(&[';', ','][..]).map(str::trim).any(|t| {
        [onv_agent_lib::names::TAG_INSTANCE, onv_agent_lib::names::TAG_WORKER, onv_agent_lib::names::TAG_GATEWAY].contains(&t)
    }) || onv_agent_lib::names::is_legacy_marketplace_tag(text("tags"));
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


    /// The guard alone, for what `import`'s own "a machine, not a template"
    /// check would otherwise hide: our words on a machine are not a template.
    #[test]
    fn this_images_template_is_a_template() {
        let cfg = |template: u64| {
            serde_json::json!({"name": "onv-ubuntu-2604", "template": template,
                               "description": super::description("ubuntu-2604", "ab12")})
        };
        assert!(super::is_this_images_template(&cfg(1), "ubuntu-2604"));
        assert!(!super::is_this_images_template(&cfg(0), "ubuntu-2604"), "a machine was taken for a template");
        assert!(!super::is_this_images_template(&cfg(1), "ubuntu-26"), "a prefix of the id was taken for it");
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
    use omnuv_protocol::ImageArtefact;

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

    /// Half of our words is not our words: the description's opening without
    /// the digest marker, or the marker under another opening, is somebody's
    /// machine. Added with A1b, for the two mutants of `is_unfinished_import`
    /// no earlier case could tell apart.
    #[test]
    fn our_opening_without_the_marker_is_not_an_import() {
        let cfg = |desc: &str| serde_json::json!({"name": "onv-ubuntu-2604", "template": 0, "description": desc});
        assert!(is_unfinished_import(&cfg(&description("ubuntu-2604", A)), "ubuntu-2604"));
        assert!(!is_unfinished_import(&cfg("Onv marketplace base image - ubuntu-2604. Hand-made."), "ubuntu-2604"),
                "our opening without the marker was taken for an import");
        assert!(!is_unfinished_import(&cfg(&format!("An operator's machine. {DIGEST_MARKER} {A}")), "ubuntu-2604"),
                "the marker under another opening was taken for an import");
    }

    /// The file's digest is SHA-256 in lowercase hex, read to the end: the
    /// standard vectors for "abc" and for nothing, and a file longer than one
    /// read. Added with A1b; the agent's own tests never read a file's digest.
    #[test]
    fn a_files_digest_is_its_sha256() {
        let d = tempfile::tempdir().unwrap();
        let file = |name: &str, bytes: &[u8]| {
            let p = d.path().join(name);
            std::fs::write(&p, bytes).unwrap();
            digest_of_file(&p).unwrap()
        };
        assert_eq!(file("abc", b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(file("empty", b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let long = vec![b'a'; 1024 * 1024 + 1];
        let whole = {
            use sha2::Digest as _;
            hex(&sha2::Sha256::digest(&long))
        };
        assert_eq!(file("long", &long), whole, "a file longer than one read was not read to the end");
        assert!(digest_of_file(&d.path().join("absent")).is_err());
        assert_eq!(hex(&[0x00, 0x0f, 0xab]), "000fab");
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
