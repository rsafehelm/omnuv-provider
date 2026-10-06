//! **`onv-opening` starts with no Core or Proxmox credential** (omnuv's
//! modular design, A3): the applier is a binary of its own, run here as
//! built, with an environment emptied and a configuration that names no
//! credential and has no credentials file beside it. It renders its rules
//! and exits 0, where the agent refuses the very same file.

use std::path::Path;
use std::process::Command;

/// agent.yaml with the opening on and nothing of Core or Proxmox but the
/// address and the snippet directory: no `coreToken`, no `tokenSecret`, and
/// no agent-secrets.yaml beside it.
fn config(dir: &Path) -> std::path::PathBuf {
    let snippets = dir.join("snippets");
    std::fs::create_dir_all(&snippets).unwrap();
    std::fs::write(
        dir.join("opening.json"),
        r#"{"machines": {"m-guest": {"port": 31820, "address": "10.201.0.105"}}}"#,
    )
    .unwrap();
    let path = dir.join("agent.yaml");
    std::fs::write(
        &path,
        format!(
            "core:\n  url: https://core.invalid\nproxmox:\n  apiUrl: https://127.0.0.1:8006\n  tokenId: onv@pve!agent\n  \
             snippetDir: {}\nopening:\n  enabled: true\n  reach: forwarded\n  publicAddress: 203.0.113.7\n  \
             interface: vmbr0\n  ports: \"31820-31822\"\n",
            snippets.display()
        ),
    )
    .unwrap();
    path
}

#[test]
fn onv_opening_starts_with_no_core_or_proxmox_credential() {
    let dir = tempfile::tempdir().unwrap();
    let path = config(dir.path());
    assert!(!dir.path().join("agent-secrets.yaml").exists() && !dir.path().join("lease-secrets.yaml").exists());

    let out = Command::new(env!("CARGO_BIN_EXE_onv-opening"))
        .env_clear()
        .args(["--config", path.to_str().unwrap(), "--print"])
        .output()
        .expect("onv-opening runs");
    let said = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "onv-opening did not start: {said} {}", String::from_utf8_lossy(&out.stderr));
    assert!(said.contains("dnat ip to 10.201.0.105:31820"), "the rules were not rendered: {said}");

    // The same file, to the agent: refused, for want of the credentials the
    // applier never needed. So the pass above is the applier's own.
    let agent = Command::new(env!("CARGO_BIN_EXE_onv-provider"))
        .env_clear()
        .args(["check-config", "--config", path.to_str().unwrap()])
        .output()
        .expect("onv-provider runs");
    assert_eq!(agent.status.code(), Some(2), "the agent loaded a file with no credential");
    assert!(String::from_utf8_lossy(&agent.stderr).contains("neither credential"), "{}", String::from_utf8_lossy(&agent.stderr));
}

/// **The agent's binary no longer runs either part**: each old command says
/// where it went and does nothing.
#[test]
fn the_agent_names_where_the_two_commands_went() {
    for (old, new) in [("apply-opening", "/usr/bin/onv-opening"), ("run-lease-expire", "/usr/bin/onv-lease-expire")] {
        let out = Command::new(env!("CARGO_BIN_EXE_onv-provider")).env_clear().arg(old).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{old}");
        assert!(String::from_utf8_lossy(&out.stderr).contains(&format!("moved to {new}")), "{old}");
    }
}
