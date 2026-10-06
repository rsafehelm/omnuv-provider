//! **A Linux machine's first boot, pinned byte for byte.** The user-data and
//! network config every case below renders are compared with the files in
//! `tests/linux/`; `ONV_GOLDEN=write` rewrites them. A machine's drive is a
//! contract with every machine already built from it: a byte that moves is a
//! drive refreshed, so a change here is a diff a person reads, never a
//! side effect of moving code.
//!
//! The fixtures are invented, not taken from a machine: the setup key and the
//! certificate bootstrap are the shapes the agent writes, and neither was ever
//! issued by anything.

use super::*;

const KEY: &str = "0E38B183-B8B6-45CE-B93B-2EF63F3D14E4";

/// Core's own fixture (`tests/from-core`): a machine with nothing but its size.
fn bare() -> InstanceSpec {
    let desired: serde_json::Value =
        serde_json::from_str(include_str!("../tests/from-core/desired-state.json")).unwrap();
    serde_json::from_value(desired["instances"][0].clone()).unwrap()
}

/// Everything a Linux first boot can carry: two keys (one with a stray
/// newline), a console password, a private network, an overlay that names no
/// peer, a recipe with containers on a card, and a certificate fetch.
fn full() -> InstanceSpec {
    let mut spec = bare();
    spec.id = "3f2a9c1b-04de-4a6f-9b1e-7c5d2e8f9a10".into();
    spec.name = "web-1".into();
    spec.ssh_keys = vec![
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyOnlyForTheGoldenFile buyer@example".into(),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISecondFixture\nkey@example ".into(),
    ];
    spec.console_password_hash = Some("$6$rounds=10000$saltsaltsaltsalt$hashhashhashhash".into());
    spec.network = Some(NetworkAttachment {
        network_id: "c4d90fd2-be3d-4225-a4a6-265138a76e49".into(),
        dns_name: Some("web-1.internal".into()),
        mac: "02:09:a4:76:f8:ee".into(),
    });
    spec.overlay = Some(omnuv_protocol::OverlayEnrolment {
        setup_key: KEY.into(),
        management_url: "https://api.omnuv.com:8443".into(),
        hostname: None,
    });
    spec.recipe = Some(omnuv_protocol::RecipeSpec {
        id: "ollama-openwebui".into(),
        compose: "services:\n  app:\n    image: x\n    command: [\"sh\", \"-c\", \"echo '$HOME' \\\"q\\\"\"]\n".into(),
        gpu: true,
        post_up: vec!["docker compose exec -T app true".into(), "printf '%s\\n' \"$(id -u)\" >/tmp/x".into()],
    });
    spec.certificate = Some(omnuv_protocol::CertificatePull {
        core_url: "https://api.omnuv.com/".into(),
        bootstrap_token: "cbt_golden_fixture_never_issued".into(),
    });
    spec
}

/// A gaming recipe: no containers, an overlay whose peer Core named, no
/// password, no certificate.
fn gaming() -> InstanceSpec {
    let mut spec = full();
    spec.name = "rig".into();
    spec.console_password_hash = None;
    spec.certificate = None;
    spec.overlay.as_mut().unwrap().hostname = Some("onv-rig-01509af7".into());
    spec.recipe = Some(omnuv_protocol::RecipeSpec {
        id: "steam-gaming".into(),
        compose: "services: {}\n".into(),
        gpu: true,
        post_up: vec!["bash ./steam-gaming.sh".into()],
    });
    spec
}

/// Every case: its file name and the bytes the agent writes.
fn cases() -> Vec<(String, String)> {
    let opened = crate::opening::Opened { port: 31845, public: std::net::Ipv4Addr::new(203, 0, 113, 7) };
    let mirror = Some(" http://mirror.example/ubuntu ");
    let mut out = Vec::new();
    for (name, spec, apt, open) in [
        ("bare", bare(), None, None),
        ("full", full(), mirror, None),
        ("full-opened", full(), mirror, Some(opened)),
        ("gaming", gaming(), None, None),
        ("gaming-opened", gaming(), None, Some(opened)),
    ] {
        out.push((format!("{name}.user-data.yaml"), first_boot_user_data(&spec, apt, 103, open).unwrap()));
        out.push((format!("{name}.network.yaml"), network_config(&spec, 103)));
    }
    // A VMID past the first /24 of the segment range.
    out.push(("full-vmid-9301.user-data.yaml".into(), first_boot_user_data(&full(), None, 9301, None).unwrap()));
    out
}

fn dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/linux")
}

#[test]
fn a_linux_machine_s_first_boot_is_its_golden_file() {
    let write = std::env::var("ONV_GOLDEN").as_deref() == Ok("write");
    let cases = cases();
    for (name, actual) in &cases {
        let path = dir().join(name);
        if write {
            std::fs::create_dir_all(dir()).unwrap();
            std::fs::write(&path, actual).unwrap();
        }
        let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(actual, &expected, "{name} differs from its golden file (ONV_GOLDEN=write to accept)");
    }
    // No golden file is left that no case renders: a case dropped from the
    // list would otherwise leave its file pinning nothing.
    let mut on_disk: Vec<String> =
        std::fs::read_dir(dir()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    let mut rendered: Vec<String> = cases.iter().map(|(n, _)| n.clone()).collect();
    on_disk.sort();
    rendered.sort();
    assert_eq!(on_disk, rendered, "tests/linux holds exactly the rendered cases");
}
