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
pub enum GuestKind {
    Linux,
    Windows,
}

/// The guest kind an image asks for. **A disagreement is refused**, never
/// guessed at: a Linux image naming cloudbase-init, or a Windows one naming
/// cloud-init, is a catalogue row that would build a machine whose drive its
/// first boot cannot read.
pub fn guest_kind(image: &ImageSpec) -> anyhow::Result<GuestKind> {
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
pub const STATUS: &str = r"C:\ProgramData\onv\recipe-status";
/// Where the recipe leaves the stream login it minted: Linux's
/// `/etc/onv/recipe-stream-credential`, the same `user=`/`password=` lines.
/// **The recipe is its only writer** (omnuv's `steam-gaming-windows.ps1`, as
/// `steam-gaming.sh` on Linux); the agent reads and reports it, and its
/// first-boot script never touches it.
pub const STREAM_CREDENTIAL: &str = r"C:\ProgramData\onv\recipe-stream-credential";
/// The tunnel's join file (W3; omnuv-client `tunnel/machine.go`, plan §5a).
pub const JOIN: &str = r"C:\ProgramData\onv\tunnel\machine-join.json";
/// OpenSSH's file for an administrator's keys (W2).
pub const ADMIN_KEYS: &str = r"C:\ProgramData\ssh\administrators_authorized_keys";
/// The first-boot script, written by the drive and run by runcmd.
pub const FIRST_BOOT: &str = r"C:\ProgramData\onv\first-boot.ps1";
/// Where its output lands: cloudbase-init's own log (the image's
/// `onv-cloudbase-init.conf`, `log_dir` and `log_file`), at debug.
pub const FIRST_BOOT_LOG: &str = r"C:\Program Files\Cloudbase Solutions\Cloudbase-Init\log\cloudbase-init.log";

pub const SCRIPT: &str = include_str!("../guest/windows-first-boot.ps1");
pub const STEP_MACHINE: &str = include_str!("../guest/windows-step-machine.ps1");
pub const STEP_JOIN: &str = include_str!("../guest/windows-step-join.ps1");
pub const STEPS_MARK: &str = "# @STEPS@\n";

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
pub fn netbios_name(id: &str) -> String {
    let digits: String = id.chars().filter(char::is_ascii_hexdigit).take(11).collect();
    format!("onv-{}", digits.to_ascii_lowercase())
}

/// The drive's `meta-data`. **The instance-id is the machine's id**, never
/// Proxmox's default (a hash of the user-data and network-config): that
/// changes whenever the agent refreshes the drive, and cloudbase-init then
/// runs every per-instance plugin again, the user-data included, on a machine
/// already in use. `local-hostname` is what sysprep's specialize pass names the
/// machine from (the image's `onv-cloudbase-init-unattend.conf`).
pub fn meta_data(spec: &InstanceSpec) -> String {
    format!("instance-id: '{}'\nlocal-hostname: '{}'\n", spec.id, netbios_name(&spec.id))
}

/// What the tunnel's machine mode reads, version 1. Field order is the
/// contract's; the tunnel refuses an unknown field, so nothing is added here
/// without a new version there.
#[derive(serde::Serialize)]
pub struct MachineJoin<'a> {
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
pub fn join_file(o: &OverlayEnrolment, machine_id: &str) -> anyhow::Result<String> {
    let join = MachineJoin {
        version: 1,
        machine_id,
        management_url: o.management_url.trim(),
        // `.expose()`, for the reason overlay_runcmd gives: `{}` would be
        // `<redacted>`, which the check below refuses.
        setup_key: o.setup_key.expose(),
        hostname: crate::linux::peer_name(o, machine_id),
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
pub mod tunnel_rules {
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
        let Ok(u) = url::Url::parse(raw) else { return false };
        // Go's `u.Host == ""`. The WHATWG parser refuses an http(s) URL with
        // no host, so an empty one never reaches here.
        let Some(host) = u.host_str() else { return false };
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
    pub fn accepts(text: &str) -> Result<(), String> {
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
pub fn yaml_quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// A single-quoted PowerShell string: nothing in it is special but `'`, doubled.
pub fn ps_quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

pub fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// One `write_files` entry, base64 so nothing in it can break the document,
/// and so cloudbase-init's plugin, which logs no content, is the only reader.
pub fn write_file(path: &str, content: &[u8]) -> String {
    format!(
        "  - path: {}\n    permissions: '0600'\n    encoding: b64\n    content: {}\n",
        yaml_quoted(path),
        b64(content)
    )
}

/// The steps of a Windows first boot, labelled as a buyer reads them while
/// they run (the Linux machine's words, where the step is the same).
pub fn steps(spec: &InstanceSpec) -> anyhow::Result<Vec<(&'static str, String)>> {
    let mut steps: Vec<(&'static str, String)> = vec![("Starting the machine", STEP_MACHINE.to_string())];
    if spec.overlay.is_some() {
        steps.push(("Joining your private network", STEP_JOIN.to_string()));
    }
    if let Some(recipe) = &spec.recipe {
        // **No containers on Windows.** A recipe that runs any is refused
        // here, with the reason, rather than written for a Docker this image
        // does not have.
        if crate::linux::has_containers(&recipe.compose) {
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
        // **No stream login here.** The recipe mints it and writes
        // `STREAM_CREDENTIAL`, as steam-gaming.sh does on Linux: one writer.
        // A second mint after it would hand Sunshine one login while Core,
        // which takes only the first delivery, kept the other. A machine
        // with no recipe has no stream to sign in to (W2: no console
        // password either), so nothing mints one at all.
    }
    Ok(steps)
}

/// The first-boot script: the template with its steps, each announced in the
/// status file before it runs, then run in its own scope (`& { }`) so a
/// `return` ends the step and a throw ends the install.
pub fn first_boot_script(spec: &InstanceSpec) -> anyhow::Result<String> {
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
pub fn user_data(spec: &InstanceSpec) -> anyhow::Result<String> {
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
pub fn vga(spec: &InstanceSpec) -> &'static str {
    if spec.gpu_local_ids.is_empty() { "std" } else { "none" }
}
