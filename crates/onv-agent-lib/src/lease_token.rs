//! **The host timer's token** (omnuv's modular design, A3): what it is
//! called, where it is kept, what it may do, and how the timer reads it.
//! Here, beside the parser it uses, because two parts name it: `join`, which
//! mints it and writes it, and `onv-lease-expire`, which refuses to start
//! without it.

/// **The name systemd gives the timer's token** (omnuv's modular design, A3):
/// `LoadCredential=lease:/etc/onv/lease-secrets.yaml` in
/// onv-lease-expire.service puts a copy readable by the service alone at
/// `$CREDENTIALS_DIRECTORY/lease`. The file itself is root's, mode 0600, so
/// neither the agent nor a person running as onv can read it.
pub const CREDENTIAL: &str = "lease";

/// Where deploy-agent.yml and `join` write the token, for the unit to load.
pub const CREDENTIAL_SOURCE: &str = "/etc/onv/lease-secrets.yaml";

/// The two keys the credential holds: the token's id beside its secret, so
/// one cannot be paired with another token's. Never `coreToken`: the timer
/// holds no Core credential, and a file that names one is refused.
pub const CREDENTIAL_KEYS: [&str; 2] = ["proxmoxTokenId", "proxmoxTokenSecret"];

/// The token's own name, after the `!`: `onv@pve!lease`, a privilege-separated
/// token holding `OnvLease` (VM.Audit, VM.PowerMgmt) on the buyers' pool and
/// nothing else. A credential naming another token (the agent's `!agent`,
/// which can build and destroy) is refused rather than used.
pub const TOKEN_NAME: &str = "lease";

/// The two privileges the token holds, and the pool it holds them on: what
/// `--probe` asks Proxmox the token has, and refuses anything beyond.
/// VM.PowerMgmt is the stop; VM.Audit is the three reads before it (the
/// cluster's listing, a guest's config for its stamp, its live status), each
/// of which Proxmox answers only to a holder of VM.Audit.
pub const PRIVILEGES: [&str; 2] = ["VM.Audit", "VM.PowerMgmt"];

/// The role that carries [`PRIVILEGES`], granted to the token alone on the
/// buyers' pool by deploy-agent.yml and `join`.
pub const ROLE: &str = "OnvLease";

/// The timer's token, as its credential holds it.
pub struct Token {
    pub id: String,
    pub secret: omnuv_protocol::Redacted,
}

/// **The token, from the directory systemd gave the unit, or a refusal in
/// words.** `None` is a run with no `$CREDENTIALS_DIRECTORY`: not started by
/// its unit. Nothing in a refusal quotes a value.
pub fn read_token(dir: Option<&std::path::Path>) -> Result<Token, String> {
    let Some(dir) = dir else {
        return Err(format!(
            "no credential: $CREDENTIALS_DIRECTORY is not set. The timer's Proxmox token reaches it only through \
             onv-lease-expire.service's LoadCredential={CREDENTIAL}:{CREDENTIAL_SOURCE}; run it by hand with \
             systemd-run -p User=onv -p LoadCredential={CREDENTIAL}:{CREDENTIAL_SOURCE} --pipe --wait \
             /usr/bin/onv-lease-expire --dry-run"
        ));
    };
    let path = dir.join(CREDENTIAL);
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) => {
            return Err(format!(
                "no credential: {} could not be read ({e}); the unit gives it with \
                 LoadCredential={CREDENTIAL}:{CREDENTIAL_SOURCE}, which deploy-agent.yml or join writes",
                path.display()
            ));
        }
    };
    let mut found = crate::secrets::parse_partial(&raw, &CREDENTIAL_KEYS)
        .map_err(|bad| format!("the credential {} refused: {}", path.display(), bad.join("; ")))?;
    let missing: Vec<&str> = CREDENTIAL_KEYS.iter().copied().filter(|k| !found.contains_key(k)).collect();
    if !missing.is_empty() {
        return Err(format!("the credential {} refused: {} missing", path.display(), missing.join(" and ")));
    }
    let id = found.remove("proxmoxTokenId").map(|r| r.expose().trim().to_string()).unwrap_or_default();
    let secret = found.remove("proxmoxTokenSecret").unwrap_or_else(|| "".into());
    // A token id is `user@realm!name`: a username, not a secret, so it is said.
    match id.split_once('!') {
        Some((user, name)) if user.contains('@') && name == TOKEN_NAME => Ok(Token { id, secret }),
        _ => Err(format!(
            "the credential {} refused: proxmoxTokenId is {id:?}, not a `<user>@<realm>!{TOKEN_NAME}` token; \
             the timer stops machines with its own token and never with the agent's",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_with(body: Option<&str>) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "onv-lease-token-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(body) = body {
            std::fs::write(dir.join(CREDENTIAL), body).unwrap();
        }
        dir
    }

    /// **The timer's own token is read**: its id and its secret, as `join`
    /// and deploy-agent.yml write them.
    #[test]
    fn the_timers_own_token_is_read() {
        let dir = dir_with(Some("proxmoxTokenId: onv@pve!lease\nproxmoxTokenSecret: \"SEKRET-LEASE\"\n"));
        let t = read_token(Some(&dir)).expect("the timer's own token was refused");
        assert_eq!((t.id.as_str(), t.secret.expose()), ("onv@pve!lease", "SEKRET-LEASE"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **No credential, or one that is not the timer's own, is refused**:
    /// none at all, one naming Core's token, one naming the agent's Proxmox
    /// token, one with a part missing, empty or not a string. No refusal
    /// quotes a secret.
    #[test]
    fn no_token_or_another_ones_is_refused() {
        let said = read_token(None).err().unwrap_or_default();
        assert!(said.contains("no credential") && said.contains("LoadCredential=lease:/etc/onv/lease-secrets.yaml"), "{said}");
        let empty = dir_with(None);
        assert!(read_token(Some(&empty)).err().unwrap_or_default().contains("no credential"));
        for (body, why) in [
            ("proxmoxTokenId: onv@pve!lease\nproxmoxTokenSecret: SEKRET-A\ncoreToken: SEKRET-B\n", "`coreToken` is not a credential"),
            ("proxmoxTokenId: onv@pve!agent\nproxmoxTokenSecret: SEKRET-A\n", "never with the agent's"),
            ("proxmoxTokenId: lease\nproxmoxTokenSecret: SEKRET-A\n", "not a `<user>@<realm>!lease` token"),
            ("proxmoxTokenSecret: SEKRET-A\n", "proxmoxTokenId missing"),
            ("proxmoxTokenId: onv@pve!lease\n", "proxmoxTokenSecret missing"),
            ("proxmoxTokenId: onv@pve!lease\nproxmoxTokenSecret: ''\n", "proxmoxTokenSecret is empty"),
            ("proxmoxTokenId: onv@pve!lease\nproxmoxTokenSecret: [SEKRET-A]\n", "proxmoxTokenSecret must be a string"),
            ("proxmoxTokenSecret: \"SEKRET-A\n", "not a map of names to values"),
        ] {
            let dir = dir_with(Some(body));
            let said = read_token(Some(&dir)).err().unwrap_or_default();
            assert!(said.contains(why), "{body:?}: said {said:?}");
            assert!(!said.contains("SEKRET"), "{body:?}: a secret was quoted: {said}");
            let _ = std::fs::remove_dir_all(&dir);
        }
        let _ = std::fs::remove_dir_all(&empty);
    }
}
