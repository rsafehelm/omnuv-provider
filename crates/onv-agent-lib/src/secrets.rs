//! **A credentials file, read as far as it goes** (omnuv's modular design,
//! A3). One parser for every credentials file on a provider: the agent's
//! `agent-secrets.yaml`, which must hold both of its names, and the host
//! timer's credential, which holds its own token and never Core's. Each
//! caller names the keys it knows, and asks for the ones it needs.

/// **A credentials file read as far as it goes** (omnuv's modular design,
/// A3): each of `known` it holds, and nothing else. A key it lacks is not a
/// refusal here; the part that needs it says so. A key outside `known` is,
/// and so is a value that is empty or not a string. Each part of the agent
/// asks for only the credentials it uses: the agent both of
/// `agent-secrets.yaml`, the host timer its own token's and never Core's.
///
/// **A refusal names the key, never the value**: a YAML library's own
/// messages quote what they could not read, so this reads a map of names to
/// values itself and says what is wrong in its own words.
pub fn parse_partial(
    yaml: &str,
    known: &[&'static str],
) -> Result<std::collections::BTreeMap<&'static str, omnuv_protocol::Redacted>, Vec<String>> {
    let (found, bad) = read_partial(yaml, known);
    if bad.is_empty() { Ok(found) } else { Err(bad) }
}

/// What [`parse_partial`] found, beside what it refused: the agent's whole
/// file names a missing key only when nothing was said of it already
/// (`AgentSecrets::parse` in the agent's config.rs).
pub fn read_partial(
    yaml: &str,
    known: &[&'static str],
) -> (std::collections::BTreeMap<&'static str, omnuv_protocol::Redacted>, Vec<String>) {
    let map: std::collections::BTreeMap<String, serde_yaml_ng::Value> = if yaml.trim().is_empty() {
        Default::default()
    } else {
        match serde_yaml_ng::from_str(yaml) {
            Ok(m) => m,
            Err(_) => {
                return (
                    Default::default(),
                    vec!["it is not a map of names to values; the line is not quoted here, because it may hold a \
                          credential"
                        .to_string()],
                );
            }
        }
    };
    let mut found = std::collections::BTreeMap::new();
    let mut bad = Vec::new();
    for (key, value) in map {
        let Some(name) = known.iter().copied().find(|k| *k == key) else {
            bad.push(format!("`{key}` is not a credential this agent knows: it knows {}", known.join(" and ")));
            continue;
        };
        match value {
            serde_yaml_ng::Value::String(v) if !v.trim().is_empty() => {
                found.insert(name, omnuv_protocol::Redacted::from(v));
            }
            serde_yaml_ng::Value::String(_) | serde_yaml_ng::Value::Null => bad.push(format!("{key} is empty")),
            _ => bad.push(format!("{key} must be a string")),
        }
    }
    (found, bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN: [&str; 2] = ["proxmoxTokenId", "proxmoxTokenSecret"];

    /// **A partial file is a file**: what it holds is returned, and a known
    /// key it lacks is no refusal here, so each part asks for its own.
    #[test]
    fn a_partial_file_is_read_as_far_as_it_goes() {
        let found = parse_partial("proxmoxTokenSecret: SEKRET\n", &KNOWN).expect("a partial file was refused");
        assert_eq!(found.keys().copied().collect::<Vec<_>>(), ["proxmoxTokenSecret"]);
        assert_eq!(found["proxmoxTokenSecret"].expose(), "SEKRET");
        assert!(parse_partial("", &KNOWN).expect("an empty file").is_empty());
    }

    /// **A key it does not know, or a value that is not one, is refused**,
    /// in words that name the key and never quote the value.
    #[test]
    fn an_unknown_key_or_a_bad_value_is_refused_without_its_value() {
        for (body, why) in [
            ("coreToken: SEKRET\n", "`coreToken` is not a credential this agent knows: it knows proxmoxTokenId and proxmoxTokenSecret"),
            ("proxmoxTokenSecret: ''\n", "proxmoxTokenSecret is empty"),
            ("proxmoxTokenSecret: [SEKRET]\n", "proxmoxTokenSecret must be a string"),
            ("proxmoxTokenSecret: \"SEKRET\n", "not a map of names to values"),
        ] {
            let said = parse_partial(body, &KNOWN).err().unwrap_or_default().join("; ");
            assert!(said.contains(why), "{body:?}: {said}");
            assert!(!said.contains("SEKRET"), "{body:?}: the value was quoted: {said}");
        }
        // What was read beside a refusal is still there, for a caller that
        // names only what is missing.
        let (found, bad) = read_partial("proxmoxTokenId: onv@pve!lease\nsessionKey: x\n", &KNOWN);
        assert!(found.contains_key("proxmoxTokenId") && bad.len() == 1, "{bad:?}");
    }
}
