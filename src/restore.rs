//! **A restore of Core's ledger, noticed from this side** (lifecycle phase 8,
//! TD11; the model's G_restoreGen and G_restoreMode).
//!
//! A restore of Core's database by hand calls nothing: no generation moves,
//! no session is revoked, and Core itself cannot tell. What can tell is what
//! this agent holds and the ledger no longer does:
//!
//! ```text
//! the head       the highest view revision this agent acted on. A revision
//!                only increases, so a full view below it is a history that
//!                went back
//! a tombstone    an attempt this agent tore down (phase 7). Absent is final,
//!                so a view that wants it again is a history that went back
//! Core's word    `onv-restore` on the view: Core holds this provider
//! ```
//!
//! **In restore mode this agent lists and reports, and does nothing else**:
//! no destroy, no start, no create, no recovery of a clone, no restart of a
//! crashed machine. It says so on every call ([`DETECTED_HEADER`]) until Core
//! names a restore back, and it leaves the mode only when Core, having named
//! one, stops naming it — a person ended the hold. The head is then re-based
//! on the view Core sends.
//!
//! **Armed only against a Core that says it holds restores** (its handshake
//! answer's `restore_mode`). Only such a Core can end the mode; against an
//! older one, or one with the switch off, this agent behaves as it always did.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

/// Core's answer header naming the restore that holds this provider.
pub const HEADER: &str = "onv-restore";

/// This agent's report that its head is not extended, with the evidence.
pub const DETECTED_HEADER: &str = "onv-restore-detected";

/// The capability this agent advertises, and Core's answer names.
pub const CAPABILITY: &str = "restore-mode";

/// What is persisted: survives a restart of this agent, never a restore of
/// Core's ledger, which is the point.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Head {
    /// The provider this head was kept for: a re-enrolled provider starts again.
    #[serde(default)]
    pub provider: String,
    /// The highest view revision this agent acted on.
    #[serde(default)]
    pub revision: u64,
    /// Restore mode, while in it.
    #[serde(default)]
    pub mode: Option<Mode>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Mode {
    /// Why this agent believes the ledger went back.
    pub evidence: String,
    /// The restore Core named, once it named one. None: this agent detected
    /// it and Core has not answered yet.
    #[serde(default)]
    pub core: Option<String>,
}

#[derive(Debug, Default)]
pub struct State {
    path: Option<PathBuf>,
    armed: bool,
    head: Head,
}

/// Shared by every clone of the Core client, so the header rides every call.
pub type Shared = Arc<Mutex<State>>;

fn lock(s: &Shared) -> std::sync::MutexGuard<'_, State> {
    s.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Where the head is kept: beside the tombstones, under the agent's own
/// directory (`/var/lib/onv`).
pub fn head_file(snippet_dir: &str) -> PathBuf {
    Path::new(snippet_dir).parent().unwrap_or(Path::new("/var/lib/onv")).join("restore-head.json")
}

/// The head this agent kept, or none. An unreadable file is kept as restore
/// mode, never read as an empty head: an empty head detects nothing.
pub fn load(path: PathBuf) -> Shared {
    let head = match std::fs::read(&path) {
        Ok(raw) => serde_json::from_slice(&raw).unwrap_or_else(|e| {
            eprintln!("restore head {} unreadable, held as a restore: {e}", path.display());
            Head {
                mode: Some(Mode { evidence: format!("this agent's restore head was unreadable: {e}"), core: None }),
                ..Head::default()
            }
        }),
        Err(_) => Head::default(),
    };
    Arc::new(Mutex::new(State { path: Some(path), armed: false, head }))
}

fn save(s: &State) {
    let Some(path) = &s.path else { return };
    let tmp = path.with_extension("json.tmp");
    let written = serde_json::to_vec(&s.head)
        .map_err(std::io::Error::other)
        .and_then(|b| std::fs::write(&tmp, b))
        .and_then(|()| std::fs::rename(&tmp, path));
    if let Err(e) = written {
        eprintln!("restore head not saved to {}: {e}", path.display());
    }
}

/// What the handshake's answer said: whether Core holds restores, and for
/// which provider. A head kept for another provider is dropped.
pub fn arm(s: &Shared, answer: &serde_json::Value) {
    let mut st = lock(s);
    st.armed = answer.get("restore_mode").and_then(serde_json::Value::as_bool).unwrap_or(false);
    let provider = answer.get("provider_id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    if st.armed && !provider.is_empty() && st.head.provider != provider {
        if !st.head.provider.is_empty() {
            println!("restore head kept for provider {} dropped: this agent now holds {provider}", st.head.provider);
        }
        st.head = Head { provider, ..Head::default() };
        save(&st);
    }
    if !st.armed {
        println!("Core holds no restores (no restore_mode in its handshake answer): restore detection is not armed");
    }
}

/// The evidence to send Core on this call: while in a restore this agent
/// detected and Core has not named back.
pub fn to_tell(s: &Shared) -> Option<String> {
    let st = lock(s);
    match &st.head.mode {
        Some(m) if st.armed && m.core.is_none() => Some(m.evidence.chars().take(400).collect()),
        _ => None,
    }
}

/// Whether this agent is in restore mode now: it lists, reports and acts on
/// nothing.
pub fn active(s: &Shared) -> bool {
    let st = lock(s);
    st.armed && st.head.mode.is_some()
}

/// **One view, read against the head.** `named` is Core's `onv-restore`;
/// `unchanged` answers carry no body and change nothing but the mode; `torn`
/// says whether an id is one this agent tore down. True when this agent must
/// act on nothing.
pub fn observe(
    s: &Shared,
    view: &omnuv_protocol::DesiredState,
    named: Option<&str>,
    torn: impl Fn(&str) -> bool,
) -> bool {
    let mut st = lock(s);
    if !st.armed {
        return false;
    }
    let before = st.head.clone();
    match (named, &mut st.head.mode) {
        (Some(id), Some(m)) => m.core = Some(id.to_string()),
        (Some(id), None) => {
            st.head.mode = Some(Mode { evidence: format!("Core holds this provider in restore {id}"), core: Some(id.to_string()) });
        }
        // Core named a restore before and names none now: a person ended it.
        // The head is re-based on what Core sends from here on.
        (None, Some(m)) if m.core.is_some() => {
            println!("restore {} ended by Core; this agent acts again", m.core.as_deref().unwrap_or("?"));
            st.head.mode = None;
            if !view.unchanged {
                st.head.revision = view.version;
            }
        }
        _ => {}
    }
    if st.head.mode.is_none() && !view.unchanged {
        let wanted_again = view
            .instances
            .iter()
            .filter(|i| i.intent != omnuv_protocol::Lifecycle::Absent)
            .map(|i| i.id.as_str())
            .chain(
                view.inference_workers
                    .iter()
                    .filter(|w| w.intent != omnuv_protocol::Lifecycle::Absent)
                    .map(|w| w.id.as_str()),
            )
            .find(|id| torn(id))
            .map(str::to_string);
        if view.version != 0 && view.version < st.head.revision {
            st.head.mode = Some(Mode {
                evidence: format!(
                    "Core sent view revision {}, below revision {} this agent acted on: the ledger went back",
                    view.version, st.head.revision
                ),
                core: None,
            });
        } else if let Some(id) = wanted_again {
            st.head.mode = Some(Mode {
                evidence: format!("attempt {id} is wanted again, and this agent tore it down: the ledger went back"),
                core: None,
            });
        } else {
            st.head.revision = st.head.revision.max(view.version);
        }
        if let Some(m) = &st.head.mode {
            eprintln!("RESTORE DETECTED: {}; this agent lists and acts on nothing until Core ends it", m.evidence);
        }
    }
    if st.head != before {
        save(&st);
    }
    st.head.mode.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnuv_protocol::{DesiredState, Lifecycle};

    fn view(version: u64, ids: &[(&str, Lifecycle)]) -> DesiredState {
        let mut d: DesiredState =
            serde_json::from_str(include_str!("../tests/from-core/desired-state.json")).expect("the fixture");
        let template = d.instances[0].clone();
        d.inference_workers.clear();
        d.unchanged = false;
        d.version = version;
        d.instances = ids
            .iter()
            .map(|(id, intent)| {
                let mut spec = template.clone();
                spec.id = id.to_string();
                spec.intent = *intent;
                spec
            })
            .collect();
        d
    }

    fn armed(dir: &Path) -> Shared {
        let s = load(dir.join("restore-head.json"));
        arm(&s, &serde_json::json!({"provider_id": "p-1", "restore_mode": true}));
        s
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("onv-restore-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// **A view below the head is a restore** (G_restoreGen): a revision only
    /// increases, so Core sending one below what this agent acted on went
    /// back in time. The head survives this agent's restart.
    #[test]
    fn a_view_behind_the_head_is_a_restore() {
        let d = scratch("behind");
        let s = armed(&d);
        assert!(!observe(&s, &view(7, &[]), None, |_| false));
        assert!(!observe(&s, &view(9, &[]), None, |_| false));
        // Restarted: the head is read back.
        let s = load(d.join("restore-head.json"));
        arm(&s, &serde_json::json!({"provider_id": "p-1", "restore_mode": true}));
        assert!(observe(&s, &view(4, &[]), None, |_| false), "a view below the head was acted on");
        assert!(to_tell(&s).is_some_and(|e| e.contains("below revision 9")), "{:?}", to_tell(&s));
    }

    /// **A torn-down attempt wanted again is a restore** (Absent is final):
    /// the evidence the revision cannot give when the restored ledger has
    /// climbed back past the number this agent holds.
    #[test]
    fn a_torn_down_attempt_wanted_again_is_a_restore() {
        let d = scratch("torn");
        let s = armed(&d);
        assert!(!observe(&s, &view(3, &[("k-old", Lifecycle::Absent)]), None, |id| id == "k-old"),
            "an Absent this agent tore down read as a restore");
        assert!(observe(&s, &view(5, &[("k-old", Lifecycle::Running)]), None, |id| id == "k-old"));
        assert!(to_tell(&s).is_some_and(|e| e.contains("k-old")));
    }

    /// **The mode ends only when Core ends it**: detected here, told to Core
    /// until Core names the restore, and left when Core, having named one,
    /// stops naming it. The head is re-based then, so the view that follows a
    /// restore is not itself read as one.
    #[test]
    fn the_mode_ends_only_when_core_ends_it() {
        let d = scratch("ends");
        let s = armed(&d);
        observe(&s, &view(9, &[]), None, |_| false);
        assert!(observe(&s, &view(4, &[]), None, |_| false));
        // Core has not named it yet: still in the mode, still telling.
        assert!(observe(&s, &view(4, &[]), None, |_| false), "left the mode before Core named a restore");
        assert!(to_tell(&s).is_some());
        // Core names it: still in the mode, no longer telling.
        assert!(observe(&s, &view(4, &[]), Some("r-1"), |_| false));
        assert!(to_tell(&s).is_none(), "told Core again after it named the restore");
        // A person ended it: acts again, on a head re-based to what Core sends.
        assert!(!observe(&s, &view(5, &[]), None, |_| false), "Core ended the restore and the agent stayed in it");
        assert!(!observe(&s, &view(6, &[]), None, |_| false));
        let kept: Head = serde_json::from_slice(&std::fs::read(d.join("restore-head.json")).unwrap()).unwrap();
        assert_eq!((kept.revision, kept.mode), (6, None));
    }

    /// **Core's word alone holds this agent** (a restore through the
    /// boundary, which Core knows of and the agent's head may not show).
    #[test]
    fn core_naming_a_restore_holds_the_agent() {
        let d = scratch("named");
        let s = armed(&d);
        assert!(observe(&s, &view(1, &[]), Some("r-2"), |_| false));
        assert!(to_tell(&s).is_none(), "an agent told Core what Core had told it");
        assert!(!observe(&s, &view(1, &[]), None, |_| false));
    }

    /// **Against a Core that holds no restores, nothing changes**: no
    /// detection, no header, no file.
    #[test]
    fn against_a_core_without_restore_mode_nothing_changes() {
        let d = scratch("old-core");
        let s = load(d.join("restore-head.json"));
        arm(&s, &serde_json::json!({"provider_id": "p-1"}));
        observe(&s, &view(9, &[]), None, |_| false);
        assert!(!observe(&s, &view(4, &[("k", Lifecycle::Running)]), Some("r"), |_| true));
        assert!(to_tell(&s).is_none() && !active(&s));
        assert!(!d.join("restore-head.json").exists(), "an unarmed agent wrote a head");
    }
}
