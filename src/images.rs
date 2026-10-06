//! **Mirroring the marketplace's published images**, the half that speaks to
//! Proxmox: tagging, reading what is held, importing. The image store's rules
//! (an artefact's name, digest and template shape) moved to
//! `onv_images::images` with no behaviour change (omnuv's modular design, work
//! package A1b), and are imported here under the names they always had.

use omnuv_protocol::HeldImage;

pub use onv_images::images::*;

/// **Every template of ours says its environment, whenever it was made**
/// (the operator, 5 October 2026). The mirror tags what it imports, but only
/// since 6782fb8, and `build-template.yml` tagged nothing; a template whose
/// digest never moves is never imported again, so six templates on Pluto and
/// Titan stayed untagged. This adds `onv-<environment>` to each template that
/// is this image's (`is_this_images_template`), keeping every tag it carries.
/// A tag is metadata: nothing is rebuilt. Answers the vmids it tagged.
pub async fn ensure_environment_tags(
    px: &crate::proxmox::Client,
    node: &str,
    offered: &std::collections::BTreeMap<String, u32>,
) -> Vec<u32> {
    let Some(env) = px.environment.as_deref().map(str::trim).filter(|e| !e.is_empty()) else {
        return Vec::new();
    };
    let want = format!("{}-{env}", crate::names::PREFIX);
    let mut tagged = Vec::new();
    for (id, vmid) in offered {
        let Ok(cfg) = px.get_json::<serde_json::Value>(&format!("/nodes/{node}/qemu/{vmid}/config")).await else {
            continue;
        };
        if !is_this_images_template(&cfg, id) {
            continue;
        }
        let tags = cfg.get("tags").and_then(serde_json::Value::as_str).unwrap_or_default();
        let mut tokens: Vec<&str> =
            tags.split(&[';', ','][..]).map(str::trim).filter(|t| !t.is_empty()).collect();
        if tokens.contains(&want.as_str()) {
            continue;
        }
        tokens.push(&want);
        match px
            .put_form::<Option<serde_json::Value>>(&format!("/nodes/{node}/qemu/{vmid}/config"), &[("tags", tokens.join(";"))])
            .await
        {
            Ok(_) => tagged.push(*vmid),
            Err(e) => eprintln!("image {id}: template {vmid} could not be tagged {want}: {e:#}"),
        }
    }
    tagged
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
        // **Of the shape this provider configures for the id.** A template
        // imported in the other shape boots every clone wrong (a Windows guest
        // as `l26`, without Secure Boot's keys), so it is not held, and the
        // next pass imports it again in the right one.
        if !px.template_shape(id).holds(&cfg) {
            continue;
        }
        let desc = cfg.get("description").and_then(serde_json::Value::as_str).unwrap_or_default();
        if let Some(sha256) = digest_in(desc) {
            out.push(HeldImage { id: id.clone(), sha256, node: Some(node.to_string()) });
        }
    }
    out
}

/// How long an import may take: about an hour of one-second looks. Not timed;
/// Pluto's Windows import (9.0 GB onto 64 G) was in its config by 01:02 after
/// starting at 00:59:55 on 5 October 2026, so the hour is wide on purpose.
const IMPORT_POLLS: u32 = 3600;

/// Turns a verified artefact on disk into a template at `vmid`.
///
/// The shape matches what the build plays produce, because a buyer's machine
/// is cloned from either and must not be able to tell which: UEFI and q35 (the
/// 26.04 cloud image is UEFI-only and silently never boots under SeaBIOS), a
/// serial console, and a cloud-init drive; for a Windows image, the template
/// `build-template-windows.yml` makes (`TemplateShape`, `template_requests`).
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
    //
    // **What Proxmox said is kept.** These two checks once read any failure as
    // "does not exist": on Pluto on 5 October 2026 the pool was there and the
    // token could read it, and every retry still said it was missing, for a
    // reason the message threw away.
    if let Err(e) = px.get_json::<serde_json::Value>(&format!("/pools/{}", crate::names::POOL)).await {
        anyhow::bail!(
            "pool '{}' could not be read on {node} ({e:#}); not destroying the existing template \
             for an import that would fail",
            crate::names::POOL
        );
    }
    if let Err(e) = px.get_json::<serde_json::Value>(&format!("/nodes/{node}/storage/{storage}/status")).await {
        anyhow::bail!(
            "storage '{storage}' does not answer on {node} ({e:#}); not destroying the existing \
             template for an import that would fail"
        );
    }

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
        // **A template, and this image's.** Being a template was once the only
        // check, so an operator's own template at a vmid the configuration
        // names would have been destroyed; then "the marketplace's", so
        // another image's template was. Now the whole catalogue id its
        // description names, on a template named by the marketplace and
        // carrying no claim (`is_this_images_template`).
        anyhow::ensure!(
            ours_unfinished || is_this_images_template(&cfg, id),
            "vmid {vmid} on {node} is not this image's template ({id}): its name, description or tags say \
             another image's, an operator's or a claimed guest's — refusing to import over it"
        );
        let upid: String = px.delete_task(&format!("/nodes/{node}/qemu/{vmid}?purge=1")).await?;
        px.wait_task(node, &upid).await?;
    }

    let [create, disk, finish] = template_requests(
        px.template_shape(id),
        id,
        vmid,
        sha256,
        storage,
        &artefact_volid(import_storage, id),
        px.environment.as_deref(),
    );
    let upid: String = px.post_form(&format!("/nodes/{node}/qemu"), &create).await?;
    px.wait_task(node, &upid).await?;

    // The import itself, and the only step that moves gigabytes. Proxmox reads
    // the volume, converts it onto `storage`, and owns every part of that — we
    // do not write an image importer, we ask the one that exists.
    //
    // **Asked as a task (POST), never PUT.** PUT converts inside the request,
    // and every request this client makes gives up after 20 s (`tls::client`).
    // On Pluto on 5 October 2026 windows-11-gaming's 9.0 GB qcow2, onto a 64 G
    // volume, outlasted it: Proxmox finished the import, and the steps after it
    // never ran. Proxmox's own description of PUT says to use POST for storage
    // allocation (PVE 9.2, `update_vm`).
    let upid: String = px.post_form(&format!("/nodes/{node}/qemu/{vmid}/config"), &disk).await?;
    px.wait_task_within(node, &upid, IMPORT_POLLS).await?;

    let _: serde_json::Value = px.put_form(&format!("/nodes/{node}/qemu/{vmid}/config"), &finish).await?;

    let _: serde_json::Value =
        px.post_form(&format!("/nodes/{node}/qemu/{vmid}/template"), &[] as &[(String, String)]).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest the import tests carry. The same value pins
    /// `onv_images::images`' own tests, which moved there with A1b.
    const A: &str = "4d3e9997536968ae6ec7f0cf51b953e4523b3ff319bdf558e2f16e5295525620";

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

        // **Only this image's template is retired** (the assets-by-id audit):
        // a template of another image at this vmid, or one in our words that
        // the marketplace did not name or that carries a claim, is refused.
        let template = |name: &str, description: String, tags: &str| {
            serde_json::json!({"name": name, "template": 1, "description": description, "tags": tags})
        };
        for (why, cfg) in [
            ("another image's", template("onv-ubuntu-2604-gaming", super::description("ubuntu-26.04-gaming", "old"), "")),
            ("an id this one prefixes", template("onv-ubuntu-2604", super::description("ubuntu-2604-nvidia", "old"), "")),
            ("an operator's in our words", template("golden", super::description("ubuntu-2604", "old"), "")),
            ("a claimed guest's", template("onv-ubuntu-2604", super::description("ubuntu-2604", "old"), "onv-instance;onv-0a0b0c0d0e0f")),
            ("the first wording, naming no id", template("onv-ubuntu-2604",
                "Omnuv marketplace base image - Ubuntu 26.04 cloud-init. Managed by Ansible; do not edit.".into(), "")),
            ("an operator's", template("golden", "my golden image".into(), "")),
        ] {
            let (result, deleted) = run(cfg, "stopped").await;
            assert!(result.is_err() && !deleted, "{why} template was destroyed for this import: {result:?}");
        }
        for (why, cfg) in [
            ("mirrored", template("onv-ubuntu-2604", super::description("ubuntu-2604", "old"), "")),
            ("built by build-template.yml", template("onv-ubuntu-2604-built",
                "Onv marketplace base image - ubuntu-2604.\nBuilt on this host by build-template.yml; do not edit.\n\nonv-artefact-sha256: old".into(), "onv-prod")),
        ] {
            let (result, deleted) = run(cfg, "stopped").await;
            assert!(result.is_ok() && deleted, "this image's own {why} template was not replaced: {result:?}");
        }
    }
    /// **A held template gains its environment tag and keeps the rest**; one
    /// already tagged, an operator's template, our unfinished import and a
    /// client with no environment are all left alone.
    #[tokio::test]
    async fn held_templates_are_tagged_with_their_environment() {
        use crate::pvemock::Mock;
        let ours = |vmid: u32, id: &str, tags: &str| {
            serde_json::json!({"name": format!("onv-{id}"), "template": 1,
                               "description": super::description(id, "ab12"), "tags": tags, "vmid": vmid})
        };
        let configs = std::sync::Arc::new(std::collections::BTreeMap::from([
            ("/nodes/n1/qemu/9000/config".to_string(), ours(9000, "ubuntu-2604", "")),
            ("/nodes/n1/qemu/9001/config".to_string(), ours(9001, "ubuntu-2604-nvidia", "keep;onv-test")),
            ("/nodes/n1/qemu/9002/config".to_string(), ours(9002, "ubuntu-2604-gaming", "keep")),
            ("/nodes/n1/qemu/9003/config".to_string(),
             serde_json::json!({"name": "golden", "template": 1, "description": "my golden image"})),
            ("/nodes/n1/qemu/9004/config".to_string(),
             serde_json::json!({"name": "onv-ubuntu-2604-ollama", "template": 0,
                                "description": super::description("ubuntu-2604-ollama", "ab12")})),
        ]));
        let offered = std::collections::BTreeMap::from([
            ("ubuntu-2604".to_string(), 9000),
            ("ubuntu-2604-nvidia".to_string(), 9001),
            ("ubuntu-2604-gaming".to_string(), 9002),
            ("golden".to_string(), 9003),
            ("ubuntu-2604-ollama".to_string(), 9004),
        ]);
        let routes = configs.clone();
        let mock = Mock::start(move |method, path, _| match (method, routes.get(path)) {
            ("GET", Some(cfg)) => (200, cfg.clone()),
            ("PUT", Some(_)) => (200, serde_json::Value::Null),
            _ => (404, serde_json::Value::Null),
        })
        .await;

        let px = mock.client().with_environment(Some("test".into()));
        let tagged = super::ensure_environment_tags(&px, "n1", &offered).await;
        assert_eq!(tagged, vec![9000, 9002]);
        let puts: Vec<(String, String)> = mock.calls.lock().unwrap().iter()
            .filter(|c| c.method == "PUT").map(|c| (c.path.clone(), c.body.clone())).collect();
        assert_eq!(puts, vec![
            ("/nodes/n1/qemu/9000/config".to_string(), "tags=onv-test".to_string()),
            ("/nodes/n1/qemu/9002/config".to_string(), "tags=keep%3Bonv-test".to_string()),
        ]);

        let none = super::ensure_environment_tags(&mock.client(), "n1", &offered).await;
        assert!(none.is_empty(), "a client with no environment tagged {none:?}");
    }

    /// Every call an import makes against a hypervisor with nothing at the
    /// vmid, for a client of the given Windows ids and environment: the
    /// merged form values, and whether the template flag was set.
    async fn imported(
        windows: &[&str],
        environment: Option<&str>,
        id: &str,
    ) -> (std::collections::BTreeMap<String, String>, bool) {
        use crate::pvemock::{task_ok, Mock};
        let mock = Mock::start(move |method, path, _| {
            if let Some(ok) = task_ok(path) {
                return ok;
            }
            match (method, path) {
                ("GET", "/nodes/n1/qemu/9005/config") => (404, serde_json::Value::Null),
                ("POST", _) => (200, serde_json::json!("UPID:n1:post")),
                ("GET", _) | ("PUT", _) => (200, serde_json::json!({})),
                _ => (404, serde_json::Value::Null),
            }
        })
        .await;
        let px = mock
            .client()
            .with_windows_images(windows.iter().map(|s| s.to_string()).collect())
            .with_environment(environment.map(str::to_string));
        super::import(&px, "n1", "local-zfs", "onv-snippets", id, 9005, A).await.expect("the import");
        let calls = mock.calls.lock().unwrap().clone();
        let mut merged = std::collections::BTreeMap::new();
        // **The disk is imported as a task**: POSTed and waited on, never PUT,
        // which converts inside a request the client abandons after 20 s.
        let imports = |m: &str| {
            calls.iter().filter(|c| c.method == m && c.path == "/nodes/n1/qemu/9005/config" && c.body.contains("import-from")).count()
        };
        assert_eq!((imports("POST"), imports("PUT")), (1, 0), "the disk was not imported as one task");
        // **No tags at create**: qemu-server 9.2.7 checks them against a VM
        // not yet in the pool that grants this token anything.
        assert!(
            calls.iter().filter(|c| c.method == "POST" && c.path == "/nodes/n1/qemu").all(|c| !c.body.contains("tags=")),
            "the create carries tags"
        );
        // Two tasks are waited on: the create's, and the import's.
        let waits = calls.iter().filter(|c| c.method == "GET" && c.path.starts_with("/nodes/n1/tasks/") && c.path.ends_with("/status")).count();
        assert_eq!(waits, 2, "the import's task was not waited on");
        for c in calls.iter().filter(|c| {
            (c.method == "POST" && c.path == "/nodes/n1/qemu")
                || (matches!(c.method.as_str(), "POST" | "PUT") && c.path == "/nodes/n1/qemu/9005/config")
        }) {
            let pairs: Vec<(String, String)> =
                reqwest::Url::parse(&format!("http://x/?{}", c.body)).unwrap().query_pairs().into_owned().collect();
            for (k, v) in pairs {
                assert!(merged.insert(k.clone(), v).is_none(), "{k} was set twice");
            }
        }
        let templated = calls.iter().any(|c| c.method == "POST" && c.path == "/nodes/n1/qemu/9005/template");
        (merged, templated)
    }

    /// **The Windows template the mirror makes is the one the build play
    /// makes** (omnuv's build-template-windows.yml, through the fixture both
    /// repositories read): every key the fixture names, at its value, and no
    /// key it does not, beyond the vmid and the per-clone size.
    #[tokio::test]
    async fn the_windows_import_is_the_build_plays_template() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/windows/template.json")).expect("the fixture parses");
        let id = "windows-11-gaming";
        let (got, templated) = imported(&[id], Some("prod"), id).await;
        assert!(templated, "never made a template");
        let fill = |v: &str| {
            v.replace("{id}", id)
                .replace("{storage}", "local-zfs")
                .replace("{import}", &artefact_volid("onv-snippets", id))
                .replace("{environment}", "prod")
        };
        let want = fixture["template"].as_object().expect("a template");
        for (k, v) in want {
            let v = fill(v.as_str().expect("a string"));
            let have = got.get(k).unwrap_or_else(|| panic!("{k} is not set; the build play sets it to {v}"));
            if k == "description" {
                // What `is_this_images_template` reads: the first line opens
                // with the whole id, whatever follows it.
                assert!(have.lines().next().is_some_and(|l| l.starts_with(&v)), "the description's first line: {have}");
            } else {
                assert_eq!(have, &v, "{k}");
            }
        }
        let per_clone: Vec<&str> = fixture["per_clone"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        for k in got.keys() {
            assert!(
                want.contains_key(k) || per_clone.contains(&k.as_str()) || k == "vmid",
                "{k} is set by the mirror and not by the build play"
            );
        }
        for k in fixture["absent"].as_array().unwrap().iter().filter_map(|v| v.as_str()) {
            assert!(!got.contains_key(k), "{k} is on the template: no clone may share it");
        }
        // The digest the mirror is held to, on the template itself.
        assert_eq!(digest_in(&got["description"]).as_deref(), Some(A));
    }

    /// The Linux shape is unchanged by Windows existing, and an environment
    /// is a tag on either, never a claim.
    #[tokio::test]
    async fn a_linux_import_keeps_the_linux_shape() {
        let (got, templated) = imported(&["windows-11-gaming"], None, "ubuntu-26.04").await;
        assert!(templated);
        assert_eq!(got["ostype"], "l26");
        assert_eq!(got["efidisk0"], "local-zfs:0,efitype=4m,pre-enrolled-keys=0");
        assert_eq!(got["vga"], "serial0");
        assert_eq!(got["scsi0"], "local-zfs:0,import-from=onv-snippets:import/ubuntu-26.04.qcow2,discard=on,ssd=1");
        assert!(!got.contains_key("citype") && !got.contains_key("tags"), "{got:?}");
        let (got, _) = imported(&[], Some("test"), "ubuntu-26.04").await;
        assert_eq!(got["tags"], "onv-test");
        assert!(super::is_this_images_template(
            &serde_json::json!({"name": got["name"], "template": 1, "description": got["description"], "tags": got["tags"]}),
            "ubuntu-26.04"
        ), "the environment's tag made the mirror's own template unrecognisable");
    }

    /// **A template is held only in the shape configured for its id**: a
    /// Windows image imported as Linux (a provider whose `windowsImages`
    /// missed it) is not held, so the next pass imports it again; and the
    /// reverse.
    #[tokio::test]
    async fn a_template_is_held_only_in_its_shape() {
        use crate::pvemock::Mock;
        let held_shape = |ostype: &'static str, windows: &'static [&'static str], localtime: serde_json::Value, audio: bool| async move {
            let mock = Mock::start(move |method, path, _| match (method, path) {
                ("GET", "/nodes/n1/qemu/9005/config") => {
                    let mut cfg = serde_json::json!({
                        "template": 1, "ostype": ostype, "name": "onv-windows-11-gaming",
                        "description": super::description("windows-11-gaming", A)});
                    if !localtime.is_null() {
                        cfg["localtime"] = localtime.clone();
                    }
                    if audio {
                        cfg["audio0"] = serde_json::json!("device=ich9-intel-hda,driver=none");
                    }
                    (200, cfg)
                }
                _ => (404, serde_json::Value::Null),
            })
            .await;
            let px = mock.client().with_windows_images(windows.iter().map(|s| s.to_string()).collect());
            let offered = std::collections::BTreeMap::from([("windows-11-gaming".to_string(), 9005u32)]);
            super::held(&px, "n1", &offered).await
        };
        let held_clock = |ostype: &'static str, windows: &'static [&'static str], localtime: serde_json::Value| held_shape(ostype, windows, localtime, true);
        let held_with = |ostype: &'static str, windows: &'static [&'static str]| held_clock(ostype, windows, serde_json::json!(0));
        // Its sound card (5 Oct 2026): without one the stream is silent.
        assert!(held_shape("win11", &["windows-11-gaming"], serde_json::json!(0), false).await.is_empty(),
                "a Windows template with no sound card was held");
        assert_eq!(held_with("win11", &["windows-11-gaming"]).await.len(), 1, "the right shape was not held");
        // Its clock in UTC (run fa56103c): Proxmox's default for a Windows
        // guest, unset, is the host's local time, and so is an explicit 1.
        for clock in [serde_json::Value::Null, serde_json::json!(1)] {
            assert!(held_clock("win11", &["windows-11-gaming"], clock.clone()).await.is_empty(),
                    "a Windows template with localtime {clock} was held");
        }
        assert!(held_with("l26", &["windows-11-gaming"]).await.is_empty(), "a Linux-shaped Windows template was held");
        assert!(held_with("win11", &[]).await.is_empty(), "a Windows-shaped template held for a Linux id");
        assert_eq!(held_with("l26", &[]).await.len(), 1, "a Linux template stopped being held");
    }

}
