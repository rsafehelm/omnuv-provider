//! **The package's supervision and log bounds, as files** (omnuv's modular
//! design, A4): the agent's unit carries the directives that make a panic a
//! restart and "stop for good" final, the journal is capped, logrotate covers
//! /var/log/onv by rename, and dpkg treats the two /etc files as conffiles.
//! `tests/logs/rotate_test.sh` runs the same files under systemd and logrotate.

use std::collections::BTreeMap;
use std::path::Path;

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The `key=value` lines of one `[section]` of a systemd-style file, comments
/// and blank lines skipped. A key given twice keeps every value, as systemd
/// reads most of them; the tests below ask for exactly one.
fn section(text: &str, name: &str) -> BTreeMap<String, Vec<String>> {
    let mut keys: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut inside = false;
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            inside = line == format!("[{name}]");
            continue;
        }
        if inside && let Some((k, v)) = line.split_once('=') {
            keys.entry(k.trim().to_string()).or_default().push(v.trim().to_string());
        }
    }
    keys
}

fn one<'a>(keys: &'a BTreeMap<String, Vec<String>>, key: &str) -> &'a str {
    match keys.get(key).map(Vec::as_slice) {
        Some([v]) => v,
        other => panic!("{key}: expected exactly one value, found {other:?}"),
    }
}

/// The parser itself, against the nearest thing it must ignore: a key in a
/// comment, and the same key in another section.
#[test]
fn the_reader_takes_only_live_keys_of_its_section() {
    let text = "[Unit]\nMemoryMax=9G\n[Service]\n# MemoryMax=8G\nMemoryMax=1G\n[Install]\nMemoryMax=7G\n";
    let keys = section(text, "Service");
    assert_eq!(one(&keys, "MemoryMax"), "1G");
    assert!(section("[Service]\n#RestartPreventExitStatus=3\n", "Service").is_empty());
}

#[test]
fn the_agent_unit_restarts_a_panic_and_not_stop_for_good() {
    let unit = read("packaging/deb/lib/systemd/system/onv-provider.service");
    let service = section(&unit, "Service");
    assert_eq!(one(&service, "Restart"), "always");
    // 3 is agent.rs's `stop_for_good`; 70 is supervise's panic, restarted.
    assert_eq!(one(&service, "RestartPreventExitStatus"), "3");
    assert_eq!(onv_core_link::supervise::PANIC_EXIT, 70);
    assert_eq!(one(&service, "TimeoutStopSec"), "660");
    let memory = one(&service, "MemoryMax");
    let digits = memory.trim_end_matches(['K', 'M', 'G']);
    assert!(
        memory != "infinity" && !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()),
        "MemoryMax is {memory}, not a bound"
    );
}

#[test]
fn the_journal_is_capped() {
    let conf = read("packaging/deb/etc/systemd/journald.conf.d/60-onv-provider.conf");
    let journal = section(&conf, "Journal");
    assert_eq!(one(&journal, "SystemMaxUse"), "1G");
}

#[test]
fn logrotate_covers_the_log_directory_by_rename() {
    let conf = read("packaging/deb/etc/logrotate.d/onv-provider");
    let live: Vec<&str> =
        conf.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    assert_eq!(live.first(), Some(&"/var/log/onv/*.log {"), "{live:?}");
    assert_eq!(live.last(), Some(&"}"));
    for directive in ["su onv onv", "create 0640 onv onv", "maxsize 100M", "rotate 12", "compress", "missingok"] {
        assert!(live.contains(&directive), "no `{directive}` in {live:?}");
    }
    // The audit sink reopens on a rename; a truncate in place would race it.
    assert!(!live.contains(&"copytruncate"));
}

/// Every file the package installs under /etc is a conffile, so an upgrade
/// never silently replaces a provider's edit, and nothing else is.
#[test]
fn every_file_under_etc_is_a_conffile() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/deb");
    let mut found = Vec::new();
    let mut dirs = vec![root.join("etc")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else {
                found.push(format!("/{}", path.strip_prefix(&root).unwrap().display()));
            }
        }
    }
    found.sort();
    let mut listed: Vec<String> = read("packaging/deb/DEBIAN/conffiles").lines().map(str::to_string).collect();
    listed.sort();
    assert_eq!(listed, found);
}
