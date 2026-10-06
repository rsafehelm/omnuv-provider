//! **`onv-lease-expire`, as built, refuses to start without its token**
//! (omnuv's modular design, A3): the binary run with an emptied environment,
//! a configuration it can read, and a machine past its lease beside it. No
//! `$CREDENTIALS_DIRECTORY`, or one without the timer's credential: exit 1,
//! the refusal in its own file naming where the token comes from, and the
//! lease file untouched.

use std::process::Command;

fn run(dir: &std::path::Path, credentials: Option<&std::path::Path>) -> (Option<i32>, String) {
    let config = dir.join("agent.yaml");
    std::fs::write(
        &config,
        format!(
            "proxmox:\n  apiUrl: https://127.0.0.1:1\n  tlsFingerprintSha256: \"{}\"\n  snippetDir: {}\n",
            "AB".repeat(32),
            dir.join("snippets").display()
        ),
    )
    .unwrap();
    let log = dir.join("run-lease-expire.log");
    let _ = std::fs::remove_file(&log);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_onv-lease-expire"));
    cmd.env_clear()
        .env("OMNUV_LEASE_TIMER_LOG", &log)
        .env("OMNUV_AUDIT_LOG", dir.join("audit.log"))
        .args(["--config", config.to_str().unwrap()]);
    if let Some(c) = credentials {
        cmd.env("CREDENTIALS_DIRECTORY", c);
    }
    let out = cmd.output().expect("onv-lease-expire runs");
    (out.status.code(), std::fs::read_to_string(&log).unwrap_or_default())
}

#[test]
fn the_binary_refuses_to_start_without_its_token() {
    let dir = tempfile::tempdir().unwrap();
    let lease = dir.path().join("run-lease.json");
    let body = r#"{"leases": [{"id": "0b1f7a2e-1111-4222-8333-944455556666", "until_unix": 1}]}"#;
    std::fs::write(&lease, body).unwrap();
    let empty = tempfile::tempdir().unwrap();
    for creds in [None, Some(empty.path())] {
        let (code, said) = run(dir.path(), creds);
        assert_eq!(code, Some(1), "{creds:?}: {said}");
        assert!(said.contains("lease refused: no credential"), "{creds:?}: {said}");
        assert!(said.contains("LoadCredential=lease:/etc/onv/lease-secrets.yaml"), "{said}");
    }
    assert_eq!(std::fs::read_to_string(&lease).unwrap(), body, "the lease file was touched");
    assert!(!dir.path().join("run-lease.lock").exists(), "a lock was taken before the token was read");
}

#[test]
fn its_usage_names_its_one_credential() {
    let out = Command::new(env!("CARGO_BIN_EXE_onv-lease-expire")).env_clear().arg("--help").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(said.contains("onv@pve!lease") && said.contains("LoadCredential="), "{said}");
    let bad = Command::new(env!("CARGO_BIN_EXE_onv-lease-expire")).env_clear().arg("--frobnicate").output().unwrap();
    assert_eq!(bad.status.code(), Some(2));
}
