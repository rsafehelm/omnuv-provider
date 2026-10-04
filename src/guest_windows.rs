//! **A Windows machine's first boot** (omnuv's `docs/plans/windows-gaming-image.md`,
//! phase 4, the agent's half; the operator's decisions W1-W5 of 4 October 2026).
//!
//! The image's OS family (the catalogue's `os_family`, sent in `ImageSpec`)
//! chooses the guest kind, and the kind chooses what the NoCloud drive holds.
//! A Linux machine's drive is a cloud-config for cloud-init and is unchanged
//! by anything here. A Windows machine's is read by cloudbase-init 1.1.8's
//! `NoCloudConfigDriveService` (the template says `citype nocloud`), and holds:
//!
//! ```text
//! meta-data     instance-id: the machine's id; local-hostname: its NetBIOS name
//! user-data     #cloud-config: write_files (the tunnel's join file, the buyer's
//!               SSH keys, the first-boot script), users (the buyer's account),
//!               runcmd (the script, once, as LocalSystem)
//! network       the Linux machine's own v2 file, which cloudbase-init's v2
//!               parser reads as written (match: macaddress, a static address
//!               with no gateway on the segment, DHCP on the egress NIC)
//! ```
//!
//! Every external name here was read at its source, 4 October 2026:
//! cloudbase-init tag 1.1.8 (`cloudconfigplugins/factory.py`: the plugins and
//! their order, write_files, set_hostname, users, runcmd; `write_files.py`:
//! `encoding: b64`; `userdata.py`: a non-multipart cloud-config is never logged
//! whole, a multipart one is, at debug, so this is never multipart;
//! `userdatautils.py`: a runcmd's stdout and stderr are logged at debug;
//! `execcmd.py`: exit codes 1001-1003 ask for a reboot); omnuv-client
//! `tunnel/machine.go` at 7ca3633f (the join file's grammar); Sunshine
//! v2026.906.222525 `src/entry_handler.cpp` (`--creds <user> <password>`).

use omnuv_protocol::{FirstBoot, ImageSpec, InstanceSpec, OsFamily, OverlayEnrolment};

/// Which first boot a machine gets: the image's OS family decides, and the
/// first-boot mechanism it names has to agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuestKind {
    Linux,
    Windows,
}

/// The guest kind an image asks for. **A disagreement is refused**, never
/// guessed at: a Linux image naming cloudbase-init, or a Windows one naming
/// cloud-init, is a catalogue row that would build a machine whose drive its
/// first boot cannot read.
pub(crate) fn guest_kind(image: &ImageSpec) -> anyhow::Result<GuestKind> {
    match (image.os_family, image.first_boot) {
        (OsFamily::Linux, FirstBoot::CloudInit) => Ok(GuestKind::Linux),
        (OsFamily::Windows, FirstBoot::CloudbaseInit) => Ok(GuestKind::Windows),
        (family, boot) => anyhow::bail!(
            "image {}: os family {family:?} with first boot {boot:?} is not a combination this agent builds",
            image.id
        ),
    }
}

/// Where a Windows machine's install says how it went: the twin of Linux's
/// `/etc/onv/recipe-status`, the same `step=`/`label=`/`rc=` lines.
pub(crate) const STATUS: &str = r"C:\ProgramData\onv\recipe-status";
/// Where it leaves the stream login it minted: Linux's
/// `/etc/onv/recipe-stream-credential`, the same `user=`/`password=` lines.
pub(crate) const STREAM_CREDENTIAL: &str = r"C:\ProgramData\onv\recipe-stream-credential";
/// The tunnel's join file (W3; omnuv-client `tunnel/machine.go`, plan §5a).
pub(crate) const JOIN: &str = r"C:\ProgramData\onv\tunnel\machine-join.json";
/// OpenSSH's file for an administrator's keys (W2).
pub(crate) const ADMIN_KEYS: &str = r"C:\ProgramData\ssh\administrators_authorized_keys";
/// The first-boot script, written by the drive and run by runcmd.
pub(crate) const FIRST_BOOT: &str = r"C:\ProgramData\onv\first-boot.ps1";
/// Where its output lands: cloudbase-init's own log (the image's
/// `onv-cloudbase-init.conf`, `log_dir` and `log_file`), at debug.
pub(crate) const FIRST_BOOT_LOG: &str = r"C:\Program Files\Cloudbase Solutions\Cloudbase-Init\log\cloudbase-init.log";

const SCRIPT: &str = include_str!("guest/windows-first-boot.ps1");
const STEP_MACHINE: &str = include_str!("guest/windows-step-machine.ps1");
const STEP_JOIN: &str = include_str!("guest/windows-step-join.ps1");
const STEP_STREAM: &str = include_str!("guest/windows-step-stream.ps1");
const STEPS_MARK: &str = "# @STEPS@\n";

/// **The machine's NetBIOS name**: `onv-` and the first eleven hex digits of
/// its id, lower case, dashes dropped; fifteen characters, Windows' limit,
/// which cloudbase-init would otherwise cut to (`netbios_host_name_compatibility`).
///
/// **A display name, and it decides nothing** (the operator's rule of 3
/// October 2026: assets by id, never by name). Eleven digits are not an id,
/// and nothing looks the machine up by this: the overlay peer is named by the
/// join file (Core's name, else `onv-m-<the whole id>`), and Core's private
/// DNS answers by the machine's id. Derived from the id rather than the
/// buyer's name, so a machine made again under a deleted one's name is not
/// that machine's namesake on its own network either.
pub(crate) fn netbios_name(id: &str) -> String {
    let digits: String = id.chars().filter(char::is_ascii_hexdigit).take(11).collect();
    format!("onv-{}", digits.to_ascii_lowercase())
}

/// The drive's `meta-data`. **The instance-id is the machine's id**, never
/// Proxmox's default (a hash of the user-data and network-config): that
/// changes whenever the agent refreshes the drive, and cloudbase-init then
/// runs every per-instance plugin again, the user-data included, on a machine
/// already in use. `local-hostname` is what sysprep's specialize pass names the
/// machine from (the image's `onv-cloudbase-init-unattend.conf`).
pub(crate) fn meta_data(spec: &InstanceSpec) -> String {
    format!("instance-id: '{}'\nlocal-hostname: '{}'\n", spec.id, netbios_name(&spec.id))
}

/// What the tunnel's machine mode reads, version 1. Field order is the
/// contract's; the tunnel refuses an unknown field, so nothing is added here
/// without a new version there.
#[derive(serde::Serialize)]
struct MachineJoin<'a> {
    version: u32,
    machine_id: &'a str,
    management_url: &'a str,
    setup_key: &'a str,
    hostname: String,
}

/// **The join file, or a refusal.** Every rule the tunnel holds the file to
/// (`readMachineJoin`, `validate`) is held here first, so a file the tunnel
/// would refuse, and remove, is never written: the machine would boot, answer
/// its console and never join. In particular the key must have a setup key's
/// shape, so `<redacted>` (what the key's `Display` prints) cannot be written.
pub(crate) fn join_file(o: &OverlayEnrolment, machine_id: &str) -> anyhow::Result<String> {
    let join = MachineJoin {
        version: 1,
        machine_id,
        management_url: o.management_url.trim(),
        // `.expose()`, for the reason overlay_runcmd gives: `{}` would be
        // `<redacted>`, which the check below refuses.
        setup_key: o.setup_key.expose(),
        hostname: crate::instance::peer_name(o, machine_id),
    };
    let text = serde_json::to_string(&join)?;
    // Never the value in the message: the key is one of the fields.
    tunnel_rules::accepts(&text).map_err(|why| anyhow::anyhow!("machine {machine_id}: the join file would be refused: {why}"))?;
    Ok(text)
}

/// The tunnel's rules for the join file, ported from omnuv-client
/// `tunnel/machine.go` (`readMachineJoin`, `machineJoin.validate`) and
/// `tunnel/membership.go` (`uuidText`, `origin`) at 7ca3633f. A port, so its
/// own tests run every rule against the file and against the nearest thing it
/// must refuse.
pub(crate) mod tunnel_rules {
    const MAX_BYTES: usize = 16384;

    fn uuid(s: &str) -> bool {
        let b = s.as_bytes();
        b.len() == 36
            && b.iter().enumerate().all(|(i, c)| match i {
                8 | 13 | 18 | 23 => *c == b'-',
                _ => c.is_ascii_hexdigit(),
            })
    }

    /// `^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`
    fn dns_label(s: &str) -> bool {
        let b = s.as_bytes();
        !b.is_empty()
            && b.len() <= 63
            && b[0].is_ascii_alphanumeric()
            && b[b.len() - 1].is_ascii_alphanumeric()
            && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
    }

    /// `origin()`: https (or http to a loopback address), a host, and no
    /// user, query, fragment or path but `/`.
    fn origin(raw: &str) -> bool {
        let Ok(u) = reqwest::Url::parse(raw) else { return false };
        let host = match u.host_str() {
            Some(h) if !h.is_empty() => h,
            _ => return false,
        };
        if !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some() {
            return false;
        }
        if !(u.path().is_empty() || u.path() == "/") {
            return false;
        }
        match u.scheme() {
            "https" => true,
            "http" => host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()),
            _ => false,
        }
    }

    /// Whether the tunnel would accept `text` as its join file. The reason,
    /// never a value.
    pub(crate) fn accepts(text: &str) -> Result<(), String> {
        if text.len() > MAX_BYTES {
            return Err("larger than a join file can be".into());
        }
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Join {
            #[serde(default)]
            version: i64,
            #[serde(default)]
            machine_id: String,
            #[serde(default)]
            management_url: String,
            #[serde(default)]
            setup_key: String,
            #[serde(default)]
            hostname: String,
        }
        let mut stream = serde_json::Deserializer::from_str(text).into_iter::<Join>();
        let join = match stream.next() {
            Some(Ok(j)) => j,
            Some(Err(e)) if e.is_syntax() || e.is_eof() => return Err(format!("not JSON (at column {})", e.column())),
            Some(Err(_)) => return Err("not a join file".into()),
            None => return Err("not JSON".into()),
        };
        if stream.next().is_some() {
            return Err("more than one JSON object".into());
        }
        let peer = if join.hostname.trim().is_empty() {
            format!("onv-m-{}", join.machine_id.to_ascii_lowercase())
        } else {
            join.hostname.trim().to_string()
        };
        match () {
            _ if join.version != 1 => Err(format!("version {} is not one this daemon reads (1)", join.version)),
            _ if !uuid(&join.machine_id) => Err("machine_id is not a uuid".into()),
            _ if !origin(&join.management_url) => Err("management_url is not an https origin".into()),
            _ if !uuid(&join.setup_key) => Err("setup_key does not have a setup key's shape".into()),
            _ if !dns_label(&peer) => Err("hostname is not a DNS label".into()),
            _ => Ok(()),
        }
    }
}

/// A single-quoted YAML scalar: nothing in it is special but `'`, doubled.
fn yaml_quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// A single-quoted PowerShell string: nothing in it is special but `'`, doubled.
fn ps_quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// One `write_files` entry, base64 so nothing in it can break the document,
/// and so cloudbase-init's plugin, which logs no content, is the only reader.
fn write_file(path: &str, content: &[u8]) -> String {
    format!(
        "  - path: {}\n    permissions: '0600'\n    encoding: b64\n    content: {}\n",
        yaml_quoted(path),
        b64(content)
    )
}

/// The steps of a Windows first boot, labelled as a buyer reads them while
/// they run (the Linux machine's words, where the step is the same).
fn steps(spec: &InstanceSpec) -> anyhow::Result<Vec<(&'static str, String)>> {
    let mut steps: Vec<(&'static str, String)> = vec![("Starting the machine", STEP_MACHINE.to_string())];
    if spec.overlay.is_some() {
        steps.push(("Joining your private network", STEP_JOIN.to_string()));
    }
    if let Some(recipe) = &spec.recipe {
        // **No containers on Windows.** A recipe that runs any is refused
        // here, with the reason, rather than written for a Docker this image
        // does not have.
        if crate::instance::has_containers(&recipe.compose) {
            anyhow::bail!("recipe {}: a Windows machine runs no containers, and this recipe's compose file has services", recipe.id);
        }
        // A Windows recipe's finishing commands are PowerShell, each run in
        // its own process from a file, so its exit code is its own and its
        // size is not a command line's. UTF-8 with a BOM: Windows PowerShell
        // reads a file without one as the ANSI code page.
        for (n, cmd) in recipe.post_up.iter().enumerate() {
            let mut bytes = "\u{feff}".as_bytes().to_vec();
            bytes.extend_from_slice(cmd.as_bytes());
            steps.push((
                "Finishing setup",
                format!(
                    "$file = Join-Path $onv {file}\n\
                     [System.IO.File]::WriteAllBytes($file, [Convert]::FromBase64String({content}))\n\
                     & powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $file\n\
                     if ($LASTEXITCODE -ne 0) {{ throw \"the recipe's step exited $LASTEXITCODE\" }}\n",
                    file = ps_quoted(&format!("recipe-step-{}.ps1", n + 1)),
                    content = ps_quoted(&b64(&bytes)),
                ),
            ));
        }
        // The stream's login, only for a machine with a recipe: Core keeps
        // it on the recipe's deployment, and a machine without one has
        // nowhere for it to go.
        steps.push(("Preparing your stream", STEP_STREAM.to_string()));
    }
    Ok(steps)
}

/// The first-boot script: the template with its steps, each announced in the
/// status file before it runs, then run in its own scope (`& { }`) so a
/// `return` ends the step and a throw ends the install.
pub(crate) fn first_boot_script(spec: &InstanceSpec) -> anyhow::Result<String> {
    let steps = steps(spec)?;
    let total = steps.len();
    let body: String = steps
        .iter()
        .enumerate()
        .map(|(i, (label, code))| {
            let indented: String =
                code.lines().map(|l| if l.is_empty() { "\n".to_string() } else { format!("        {l}\n") }).collect();
            [
                format!("    $STEP = '{}/{total}'\n", i + 1),
                format!("    $LABEL = {}\n", ps_quoted(label)),
                "    Write-OnvStatus (\"step={0}`nlabel={1}`n\" -f $STEP, $LABEL)\n".to_string(),
                "    Write-Output \"omnuv: step $STEP\"\n".to_string(),
                format!("    & {{\n{indented}    }}\n\n"),
            ]
            .concat()
        })
        .collect();
    anyhow::ensure!(SCRIPT.contains(STEPS_MARK), "the first-boot template has lost its steps' place");
    Ok(SCRIPT.replacen(STEPS_MARK, &body, 1))
}

/// **The user-data of a Windows machine**, for cloudbase-init. A plain
/// `#cloud-config`, never multipart: cloudbase-init logs a multipart
/// document whole at debug, and this one carries the overlay's key.
///
/// - `write_files` first (cloudbase-init's own order): the join file, when the
///   machine joins its network; the buyer's keys, when there are any; the
///   script.
/// - `users`: the image's account, an administrator, with no password given
///   (W2: no console password). cloudbase-init sets a random one nobody knows;
///   the buyer signs in with a key or reaches the desktop through the stream.
/// - `runcmd`: the script, once (cloudbase-init runs user-data once per
///   instance-id, which `meta_data` holds to the machine's id).
///
/// No hostname here: the meta-data names the machine in specialize, before
/// anyone signs in, and a `hostname:` here would rename it again and ask for
/// a reboot. No certificate pull either (`spec.certificate`): it is a
/// systemd timer and a shell script, Linux's alone for now.
pub(crate) fn user_data(spec: &InstanceSpec) -> anyhow::Result<String> {
    let mut files = String::new();
    if let Some(o) = &spec.overlay {
        files.push_str(&write_file(JOIN, join_file(o, &spec.id)?.as_bytes()));
    }
    if !spec.ssh_keys.is_empty() {
        // CRLF, Windows' own; one key a line, a key's own newlines folded.
        let keys: String = spec.ssh_keys.iter().map(|k| format!("{}\r\n", k.trim().replace(['\r', '\n'], " "))).collect();
        files.push_str(&write_file(ADMIN_KEYS, keys.as_bytes()));
    }
    // A BOM, so Windows PowerShell reads it as UTF-8 and not the ANSI code
    // page; LF line ends, which it parses as it does CRLF.
    let mut script = "\u{feff}".as_bytes().to_vec();
    script.extend_from_slice(first_boot_script(spec)?.as_bytes());
    files.push_str(&write_file(FIRST_BOOT, &script));

    Ok(format!(
        "#cloud-config\n\
         # Omnuv, a Windows machine's first boot (cloudbase-init 1.1.8, NoCloud).\n\
         # Written by the provider agent; read by nothing but cloudbase-init.\n\
         write_files:\n{files}\
         users:\n  - name: {user}\n    groups: [Administrators]\n\
         runcmd:\n  - {run}\n",
        user = yaml_quoted(&spec.image.default_user),
        run = yaml_quoted(&format!(
            "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{FIRST_BOOT}\""
        )),
    ))
}

/// **The display a Windows machine is given** (W1). With a card passed
/// through: `none`. The virtual display driver's monitor, rendered on the
/// card, is then the only display the machine has, so it is the primary and
/// the one Sunshine captures, and the emulated adapter (Microsoft Basic
/// Display Adapter, composed on the CPU) can be neither: Sunshine #844 is
/// "encoders not found when the emulated VGA is the primary". Keeping `std`
/// and making the virtual one primary would need a display change inside a
/// signed-in session, which first boot does not have, and Sunshine's
/// `ensure_only_display` would hold it only while a stream runs.
///
/// Without a card, `std`: it is then the machine's only screen, there is no
/// encoder to protect, and the console stays something to look at.
///
/// **What this costs**: the provider's console of a Windows machine with a
/// card shows no picture. Its desktop is reached through the stream, and its
/// shell through SSH, which W2 already says.
pub(crate) fn vga(spec: &InstanceSpec) -> &'static str {
    if spec.gpu_local_ids.is_empty() { "std" } else { "none" }
}

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

    /// Steps: numbered out of one total, the stream last and only with a
    /// recipe, the join only with an enrolment; containers refused.
    #[test]
    fn the_steps_follow_what_the_machine_was_given() {
        let spec = windows_spec();
        let labels: Vec<&str> = steps(&spec).unwrap().iter().map(|(l, _)| *l).collect();
        assert_eq!(labels, ["Starting the machine", "Joining your private network", "Finishing setup", "Preparing your stream"]);
        let script = first_boot_script(&spec).unwrap();
        assert!(script.contains("$STEP = '4/4'") && !script.contains("$STEP = '5/"), "{script}");
        assert!(!script.contains(STEPS_MARK));
        // The steps are indented into the template, which a here-string's
        // closing `'@` at column 0 would not survive.
        for step in [STEP_MACHINE, STEP_JOIN, STEP_STREAM] {
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
        for (status, want) in [("step=finished\nlabel=Preparing your stream\nrc=0\n", "done"), ("step=3/4\nlabel=Finishing setup\nrc=1\n", "error")] {
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
