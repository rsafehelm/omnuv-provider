//! **A Windows machine's first boot**: rendered by `onv_generators::windows`
//! (the agent workspace, omnuv's modular design A1), which holds the module
//! documentation and every item this file held. Re-exported whole, so every
//! caller reads them by the names it always did; the tests that drive a
//! create through the Proxmox stand-in stay here, beside the driver.

#[allow(unused_imports)]
pub(crate) use onv_generators::windows::*;
#[cfg(test)]
use omnuv_protocol::{FirstBoot, ImageSpec, InstanceSpec, OsFamily, OverlayEnrolment};

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0E38B183-B8B6-45CE-B93B-2EF63F3D14E4";
    const ID: &str = "3f2a9c1b-04de-4a6f-9b1e-7c5d2e8f9a10";

    fn windows_spec() -> InstanceSpec {
        let desired: serde_json::Value =
            serde_json::from_str(include_str!("../tests/from-core/desired-state.json")).unwrap();
        let mut spec: InstanceSpec = serde_json::from_value(desired["instances"][0].clone()).unwrap();
        spec.id = ID.into();
        spec.name = "rig".into();
        spec.image = ImageSpec {
            id: "windows-11-gaming".into(),
            os_family: OsFamily::Windows,
            first_boot: FirstBoot::CloudbaseInit,
            default_user: "omnuv".into(),
            auth_mode: omnuv_protocol::AuthMode::SshKey,
        };
        spec.ssh_keys = vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyOnlyForTheGoldenFile buyer@example".into()];
        spec.gpu_local_ids = vec!["0000:01:00.0".into()];
        spec.overlay = Some(OverlayEnrolment {
            setup_key: KEY.into(),
            management_url: "https://api.omnuv.com:8443".into(),
            hostname: None,
        });
        spec.recipe = Some(omnuv_protocol::RecipeSpec {
            id: "steam-gaming-windows".into(),
            compose: "services: {}\n".into(),
            gpu: true,
            post_up: vec!["Write-Output 'a recipe step'".into()],
        });
        spec
    }

    fn files_of(user_data: &str) -> Vec<(String, Vec<u8>)> {
        use base64::Engine as _;
        let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(user_data).expect("user-data is YAML");
        doc["write_files"]
            .as_sequence()
            .expect("write_files is a list")
            .iter()
            .map(|f| {
                assert_eq!(f["encoding"].as_str(), Some("b64"), "every file is base64");
                (
                    f["path"].as_str().unwrap().to_string(),
                    base64::engine::general_purpose::STANDARD.decode(f["content"].as_str().unwrap()).unwrap(),
                )
            })
            .collect()
    }

    /// Compares against `tests/windows/<name>`; `ONV_GOLDEN=write` rewrites it.
    fn golden(name: &str, actual: &str) {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/windows").join(name);
        if std::env::var("ONV_GOLDEN").as_deref() == Ok("write") {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, actual).unwrap();
        }
        let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(actual, expected, "{name} differs from its golden file (ONV_GOLDEN=write to accept)");
    }

    /// **The golden files**: the user-data, its meta-data, and what the drive
    /// writes, decoded, so a change to any of them is a diff a person reads.
    #[test]
    fn a_windows_machine_s_drive_is_its_golden_file() {
        let spec = windows_spec();
        let ud = user_data(&spec).unwrap();
        golden("user-data.yaml", &ud);
        golden("meta-data.yaml", &meta_data(&spec));
        for (path, bytes) in files_of(&ud) {
            let leaf = path.rsplit('\\').next().unwrap().to_string();
            golden(&format!("drive/{leaf}"), &String::from_utf8(bytes).unwrap());
        }
    }

    /// The image's family chooses the kind, and a mismatch is refused.
    #[test]
    fn the_os_family_chooses_the_guest_kind_and_a_mismatch_is_refused() {
        let mut image = ImageSpec::default();
        assert_eq!(guest_kind(&image).unwrap(), GuestKind::Linux);
        image.os_family = OsFamily::Windows;
        assert!(guest_kind(&image).is_err(), "Windows with cloud-init was built");
        image.first_boot = FirstBoot::CloudbaseInit;
        assert_eq!(guest_kind(&image).unwrap(), GuestKind::Windows);
        image.os_family = OsFamily::Linux;
        assert!(guest_kind(&image).is_err(), "Linux with cloudbase-init was built");
    }

    /// **The key's own bytes reach the join file, and nowhere else in the
    /// clear.** The document carries it only inside the join file's base64;
    /// the script cloudbase-init logs the output of never holds it.
    #[test]
    fn the_key_reaches_the_join_file_and_only_the_join_file() {
        let spec = windows_spec();
        let ud = user_data(&spec).unwrap();
        assert!(!ud.contains(KEY), "the key is in the user-data in the clear");
        let files = files_of(&ud);
        let holding: Vec<&str> = files
            .iter()
            .filter(|(_, b)| String::from_utf8_lossy(b).contains(KEY))
            .map(|(p, _)| p.as_str())
            .collect();
        assert_eq!(holding, vec![JOIN], "the key is in {holding:?}");
        let join: serde_json::Value = serde_json::from_slice(&files[0].1).unwrap();
        assert_eq!(join["setup_key"], KEY);
        assert_eq!(join["machine_id"], ID);
        assert_eq!(join["hostname"], format!("onv-m-{ID}"));
        // Nor in anything the agent prints of the machine.
        assert!(!format!("{spec:?}").contains(KEY));
        assert!(!meta_data(&spec).contains(KEY));
    }

    /// **The redacted placeholder can never be written**: a key that is not a
    /// setup key's shape refuses the build, with a reason that quotes nothing.
    #[test]
    fn a_key_without_a_setup_key_s_shape_refuses_the_build() {
        for bad in ["<redacted>", "", "0E38B183B8B645CEB93B2EF63F3D14E4"] {
            let mut spec = windows_spec();
            spec.overlay.as_mut().unwrap().setup_key = bad.into();
            let err = user_data(&spec).expect_err(&format!("{bad:?} was written")).to_string();
            assert!(err.contains("setup key's shape"), "{err}");
            assert!(bad.is_empty() || !err.contains(bad), "the refusal quotes the key: {err}");
        }
    }

    /// The join file passes the tunnel's rules, and each rule refuses the
    /// nearest thing it must (the port's negative cases).
    #[test]
    fn the_join_file_passes_the_tunnel_s_rules_and_each_rule_refuses() {
        let spec = windows_spec();
        let good = join_file(spec.overlay.as_ref().unwrap(), &spec.id).unwrap();
        assert_eq!(tunnel_rules::accepts(&good), Ok(()));
        let v: serde_json::Value = serde_json::from_str(&good).unwrap();
        let with = |field: &str, value: serde_json::Value| {
            let mut v = v.clone();
            v[field] = value;
            v.to_string()
        };
        let refused = [
            (with("version", 2.into()), "version 2"),
            (with("machine_id", "rig".into()), "machine_id"),
            (with("management_url", "http://api.omnuv.com".into()), "https origin"),
            (with("management_url", "https://api.omnuv.com/api".into()), "https origin"),
            (with("management_url", "https://u@api.omnuv.com".into()), "https origin"),
            (with("management_url", "https://:p@api.omnuv.com".into()), "https origin"),
            (with("management_url", "https://api.omnuv.com?x=1".into()), "https origin"),
            (with("management_url", "https://api.omnuv.com#f".into()), "https origin"),
            (with("management_url", "https://".into()), "https origin"),
            (with("setup_key", "<redacted>".into()), "setup key's shape"),
            (with("hostname", "rig.example".into()), "DNS label"),
            (with("hostname", "-rig".into()), "DNS label"),
            (with("extra", 1.into()), "not a join file"),
            (format!("{good}{good}"), "more than one"),
            ("{".to_string(), "not JSON"),
            ("x".repeat(16385), "larger"),
        ];
        for (text, why) in refused {
            let got = tunnel_rules::accepts(&text);
            assert!(got.as_ref().is_err_and(|e| e.contains(why)), "{why}: {got:?}");
        }
        // And what it accepts besides: a BOM, no hostname (the default peer),
        // a port, a trailing slash, http to loopback.
        assert_eq!(tunnel_rules::accepts(&format!("\u{feff}{good}")), Ok(()));
        // The size limit is the tunnel's: 16384 bytes pass, one more does not.
        let padded = format!("{good}{}", " ".repeat(16384 - good.len()));
        assert_eq!(tunnel_rules::accepts(&padded), Ok(()));
        assert!(tunnel_rules::accepts(&format!("{padded} ")).is_err());
        let mut v2 = v.clone();
        v2.as_object_mut().unwrap().remove("hostname");
        assert_eq!(tunnel_rules::accepts(&v2.to_string()), Ok(()));
        assert_eq!(tunnel_rules::accepts(&with("management_url", "https://api.omnuv.com/".into())), Ok(()));
        assert_eq!(tunnel_rules::accepts(&with("management_url", "http://127.0.0.1:33073".into())), Ok(()));
    }

    /// The NetBIOS name: fifteen characters at most, from the id alone,
    /// deterministic, and never all digits.
    #[test]
    fn the_netbios_name_is_fifteen_characters_from_the_id() {
        assert_eq!(netbios_name(ID), "onv-3f2a9c1b04d");
        assert_eq!(netbios_name(&ID.to_uppercase()), "onv-3f2a9c1b04d");
        assert_eq!(netbios_name(ID).len(), 15);
        let other = "3f2a9c1b-04de-4a6f-9b1e-000000000000";
        assert_eq!(netbios_name(other), netbios_name(ID), "eleven digits are a display name, not an id");
        let meta: serde_yaml_ng::Value = serde_yaml_ng::from_str(&meta_data(&windows_spec())).unwrap();
        assert_eq!(meta["instance-id"].as_str(), Some(ID));
        assert_eq!(meta["local-hostname"].as_str(), Some("onv-3f2a9c1b04d"));
    }

    /// Steps: numbered out of one total, never a stream login (the
    /// recipe's alone), the recipe's own steps last, the join only with an
    /// enrolment; containers refused.
    #[test]
    fn the_steps_follow_what_the_machine_was_given() {
        let spec = windows_spec();
        let labels: Vec<&str> = steps(&spec).unwrap().iter().map(|(l, _)| *l).collect();
        assert_eq!(labels, ["Starting the machine", "Joining your private network", "Finishing setup"]);
        let script = first_boot_script(&spec).unwrap();
        assert!(script.contains("$STEP = '3/3'") && !script.contains("$STEP = '4/"), "{script}");
        // One writer of the stream login: the recipe. Nothing here mints it,
        // writes its file or tells Sunshine a login.
        for needle in ["--creds", "recipe-stream-credential", "sunshine.exe", "SunshineService"] {
            assert!(!script.contains(needle), "the first-boot script holds {needle}");
        }
        assert!(!script.contains(STEPS_MARK));
        // The steps are indented into the template, which a here-string's
        // closing `'@` at column 0 would not survive.
        for step in [STEP_MACHINE, STEP_JOIN] {
            assert!(!step.contains("@'") && !step.contains("@\""), "a here-string in a step");
        }

        let mut bare = windows_spec();
        bare.overlay = None;
        bare.recipe = None;
        let labels: Vec<&str> = steps(&bare).unwrap().iter().map(|(l, _)| *l).collect();
        assert_eq!(labels, ["Starting the machine"]);
        let ud = user_data(&bare).unwrap();
        assert!(files_of(&ud).iter().all(|(p, _)| p != JOIN), "a join file without an enrolment");

        let mut docker = windows_spec();
        docker.recipe.as_mut().unwrap().compose = "services:\n  web:\n    image: nginx\n".into();
        assert!(user_data(&docker).is_err(), "a recipe with containers was written for Windows");
    }

    /// The document is what cloudbase-init reads: one cloud-config, its
    /// plugins only (write_files, users, runcmd), and nothing that would
    /// rename the machine a second time.
    #[test]
    fn the_user_data_is_one_cloud_config_of_three_plugins() {
        let ud = user_data(&windows_spec()).unwrap();
        assert!(ud.starts_with("#cloud-config\n"));
        assert!(!ud.contains("Content-Type"), "multipart is logged whole at debug");
        let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(&ud).unwrap();
        let keys: Vec<&str> = doc.as_mapping().unwrap().keys().filter_map(|k| k.as_str()).collect();
        assert_eq!(keys, ["write_files", "users", "runcmd"]);
        assert_eq!(doc["users"][0]["name"].as_str(), Some("omnuv"));
        assert!(doc["users"][0].get("passwd").is_none(), "W2: no password on the drive");
        let run = doc["runcmd"][0].as_str().unwrap();
        assert!(run.contains(FIRST_BOOT), "{run}");
        // The keys, CRLF, one a line.
        let keys = files_of(&ud).into_iter().find(|(p, _)| p == ADMIN_KEYS).unwrap().1;
        assert!(String::from_utf8(keys).unwrap().ends_with("buyer@example\r\n"));
    }

    /// **The create, through the real client**: the drive's three files are
    /// written (0600, the meta-data among them), and the clone is configured
    /// with the meta-data in `cicustom`, NoCloud said per clone, and a TPM of
    /// its own, all after the claim tag. The resize then fails, so the clone
    /// is rolled back, which is the rest of the create test's job.
    #[tokio::test]
    async fn a_windows_create_writes_its_drive_and_configures_the_clone() {
        use crate::pvemock::{task_ok, Mock};
        use std::os::unix::fs::PermissionsExt as _;
        let mut spec = windows_spec();
        spec.gpu_local_ids.clear();
        spec.network = None;
        let stamp = crate::names::description(crate::instance::TAG, &spec.id);
        let mock = Mock::start(move |method, path, _| {
            if let Some(r) = task_ok(path) {
                return r;
            }
            match (method, path) {
                ("GET", "/cluster/resources?type=vm") => (200, serde_json::json!([])),
                ("GET", "/nodes") => (200, serde_json::json!([{"node": "n1", "status": "online"}])),
                ("GET", "/nodes/n1/qemu") => (200, serde_json::json!([])),
                ("GET", "/cluster/nextid") => (200, serde_json::json!("123")),
                ("POST", p) if p.ends_with("/clone") => (200, serde_json::json!("UPID:n1:clone")),
                ("POST", "/nodes/n1/qemu/123/config") => (200, serde_json::Value::Null),
                ("GET", "/nodes/n1/qemu/123/config") => (200, serde_json::json!({"description": stamp.clone()})),
                ("PUT", "/nodes/n1/qemu/123/resize") => (500, serde_json::Value::Null),
                ("POST", "/nodes/n1/qemu/123/status/stop") => (200, serde_json::json!("UPID:n1:stop")),
                ("DELETE", "/nodes/n1/qemu/123") => (200, serde_json::json!("UPID:n1:del")),
                _ => (404, serde_json::Value::Null),
            }
        })
        .await;
        let root = std::env::temp_dir().join(format!("onv-win-create-{}", std::process::id()));
        let dir = root.join("snippets");
        std::fs::create_dir_all(&dir).unwrap();
        let result = mock.client().ensure_instance("n1", 9005, "local", dir.to_str().unwrap(), &spec).await;
        assert!(result.is_err(), "the resize failed and the create reported success");

        for (name, expected) in [
            (crate::names::snippet_instance(&spec.id), user_data(&spec).unwrap()),
            (crate::names::snippet_meta(&spec.id), meta_data(&spec)),
        ] {
            let path = dir.join(&name);
            assert_eq!(std::fs::read_to_string(&path).unwrap(), expected, "{name}");
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600, "{name}");
        }
        let calls = mock.calls.lock().unwrap();
        let configs: Vec<std::collections::HashMap<String, String>> = calls
            .iter()
            .filter(|c| c.method == "POST" && c.path == "/nodes/n1/qemu/123/config")
            .map(|c| reqwest::Url::parse(&format!("http://x/?{}", c.body)).unwrap().query_pairs().into_owned().collect())
            .collect();
        assert_eq!(configs.len(), 2, "the tag, then the configuration");
        assert_eq!(configs[0].keys().collect::<Vec<_>>(), ["tags"], "the claim first, alone");
        let c = &configs[1];
        assert_eq!(c["cicustom"], format!(
            "user=onv-snippets:snippets/{},network=onv-snippets:snippets/{},meta=onv-snippets:snippets/{}",
            crate::names::snippet_instance(&spec.id), crate::names::snippet_network(&spec.id), crate::names::snippet_meta(&spec.id)
        ));
        assert_eq!(c["citype"], "nocloud");
        assert_eq!(c["tpmstate0"], "local:1,version=v2.0");
        assert_eq!(c["vga"], "std", "no card, so the emulated display stays");
        // The clone's volumes read again after the TPM was made.
        let config_reads = calls.iter().filter(|c| c.method == "GET" && c.path == "/nodes/n1/qemu/123/config").count();
        assert!(config_reads >= 2, "the TPM's volume was not journalled ({config_reads} reads)");
        // Nothing the agent asked of Proxmox carries the key.
        assert!(calls.iter().all(|c| !c.body.contains(KEY) && !c.path.contains(KEY)), "the key reached Proxmox's API");
        drop(calls);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// And a Linux machine's configuration is what it was: no meta-data, no
    /// citype, no TPM.
    #[tokio::test]
    async fn a_linux_create_is_configured_as_before() {
        use crate::pvemock::{task_ok, Mock};
        let mut spec = windows_spec();
        spec.image = ImageSpec::default();
        spec.gpu_local_ids.clear();
        spec.network = None;
        spec.recipe = None;
        let stamp = crate::names::description(crate::instance::TAG, &spec.id);
        let mock = Mock::start(move |method, path, _| {
            if let Some(r) = task_ok(path) {
                return r;
            }
            match (method, path) {
                ("GET", "/cluster/resources?type=vm") => (200, serde_json::json!([])),
                ("GET", "/nodes") => (200, serde_json::json!([{"node": "n1", "status": "online"}])),
                ("GET", "/nodes/n1/qemu") => (200, serde_json::json!([])),
                ("GET", "/cluster/nextid") => (200, serde_json::json!("123")),
                ("POST", p) if p.ends_with("/clone") => (200, serde_json::json!("UPID:n1:clone")),
                ("POST", "/nodes/n1/qemu/123/config") => (200, serde_json::Value::Null),
                ("GET", "/nodes/n1/qemu/123/config") => (200, serde_json::json!({"description": stamp.clone()})),
                ("PUT", "/nodes/n1/qemu/123/resize") => (500, serde_json::Value::Null),
                ("POST", "/nodes/n1/qemu/123/status/stop") => (200, serde_json::json!("UPID:n1:stop")),
                ("DELETE", "/nodes/n1/qemu/123") => (200, serde_json::json!("UPID:n1:del")),
                _ => (404, serde_json::Value::Null),
            }
        })
        .await;
        let root = std::env::temp_dir().join(format!("onv-linux-create-{}", std::process::id()));
        let dir = root.join("snippets");
        std::fs::create_dir_all(&dir).unwrap();
        let _ = mock.client().ensure_instance("n1", 9000, "local", dir.to_str().unwrap(), &spec).await;
        assert!(!dir.join(crate::names::snippet_meta(&spec.id)).exists(), "a Linux machine was given meta-data");
        let body = mock.calls.lock().unwrap().iter()
            .filter(|c| c.method == "POST" && c.path == "/nodes/n1/qemu/123/config").nth(1).unwrap().body.clone();
        let c: std::collections::HashMap<String, String> =
            reqwest::Url::parse(&format!("http://x/?{body}")).unwrap().query_pairs().into_owned().collect();
        assert!(!c["cicustom"].contains("meta="));
        assert!(!c.contains_key("citype") && !c.contains_key("tpmstate0"));
        assert_eq!(c["vga"], "std");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// **The install's status and the stream login are read from a Windows
    /// machine's own paths**, encoded into the query, and never from Linux's.
    #[tokio::test]
    async fn a_windows_machine_s_progress_and_login_are_read_from_its_paths() {
        use crate::pvemock::Mock;
        let status_q = format!("/nodes/n1/qemu/700/agent/file-read?file={}", crate::proxmox::urlencode(STATUS));
        let cred_q = format!("/nodes/n1/qemu/700/agent/file-read?file={}", crate::proxmox::urlencode(STREAM_CREDENTIAL));
        assert!(status_q.ends_with("C%3A%5CProgramData%5Conv%5Crecipe-status"), "{status_q}");
        for (status, want) in [("step=finished\nlabel=Finishing setup\nrc=0\n", "done"), ("step=3/3\nlabel=Finishing setup\nrc=1\n", "error")] {
            let (sq, cq) = (status_q.clone(), cred_q.clone());
            let mock = Mock::start(move |_, path, _| {
                if path == sq {
                    (200, serde_json::json!({"content": status}))
                } else if path == cq {
                    (200, serde_json::json!({"content": "user=onv-abcdefgh\npassword=ABCDEFGHIJ0123456789\n"}))
                } else {
                    (404, serde_json::Value::Null)
                }
            })
            .await;
            let progress = mock.client().recipe_progress("n1", 700, &windows_spec().image).await.expect("read");
            assert_eq!(progress.status, want);
            if want == "done" {
                let login = progress.stream_credentials.expect("the login");
                assert_eq!((login.user.as_str(), login.password.expose()), ("onv-abcdefgh", "ABCDEFGHIJ0123456789"));
            } else {
                let detail = progress.detail.expect("a detail");
                assert!(detail.contains(FIRST_BOOT_LOG) && !detail.contains("/var/log"), "{detail}");
                assert!(progress.stream_credentials.is_none());
            }
            assert!(mock.calls.lock().unwrap().iter().all(|c| !c.path.contains("file=/etc/")), "a Linux path was asked of Windows");
        }
        // And a Linux machine's read is the request it always was.
        let mock = Mock::start(|_, _, _| (404, serde_json::Value::Null)).await;
        assert!(mock.client().recipe_progress("n1", 700, &ImageSpec::default()).await.is_none());
        let asked: Vec<String> = mock.calls.lock().unwrap().iter().map(|c| c.path.clone()).collect();
        assert_eq!(asked, ["/nodes/n1/qemu/700/agent/file-read?file=/etc/onv/recipe-status"]);
    }

    /// W1: no emulated display beside a card.
    #[test]
    fn a_machine_with_a_card_has_no_emulated_display() {
        let mut spec = windows_spec();
        assert_eq!(vga(&spec), "none");
        spec.gpu_local_ids.clear();
        assert_eq!(vga(&spec), "std");
    }
}
