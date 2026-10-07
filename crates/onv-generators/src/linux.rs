//! **A Linux machine's first boot**, as cloud-init reads it: the MACs its two
//! interfaces are matched by, the cloud-config, the network config, and the
//! status file its install writes. Moved whole from the agent's
//! `src/instance.rs` (omnuv's modular design, A1); the bytes are pinned by
//! `tests/linux/` at the workspace root.

use omnuv_protocol::{InstanceSpec, NetworkAttachment};

use crate::windows::GuestKind;

/// A stable, locally-administered MAC for a machine's marketplace interface.
///
/// The interface cannot be found by name: the distro picks that (`ens19`,
/// `enp6s19`, …) and it differs by image and by slot. Deriving the address from
/// the machine's own id gives cloud-init something deterministic to match on,
/// and keeps it stable across a rebuild.
///
/// **The protocol's derivation** since v0.28.0 (contract change 13): Core
/// sends the same address as `NetworkAttachment::mac`, and the two were
/// separate copies of this function until then. The copy this was is kept in
/// the tests, which hold every MAC it derived to the protocol's.
pub fn marketplace_mac(id: &str) -> String {
    omnuv_protocol::marketplace_mac(id)
}

/// The egress interface's MAC, derived the same way and from the same id.
///
/// **Derived rather than left to Proxmox**, because the network config names
/// both NICs and is written before the VM exists. Matching the egress NIC by
/// name instead (`en*`) would match the segment NIC too, and reading a MAC back
/// after the clone would mean writing the snippet twice.
///
/// One more round over a fixed salt, so the two NICs of one machine can never
/// collide — which they would if the same hash were reused for both.
///
/// The protocol's derivation too (v0.28.0).
pub fn egress_mac(id: &str) -> String {
    omnuv_protocol::egress_mac(id)
}

/// Shell that resolves the marketplace interface by MAC and exports `$DEV`.
///
/// One line, and the caller must place it inside a YAML **block** scalar (`- |`),
/// never a `[ sh, -c, "..." ]` flow scalar: the `"$DEV"` test would close the
/// flow string early and cloud-init would reject the whole config.
pub fn resolve_dev(mac: &str) -> String {
    format!(
        r#"DEV=$(ip -o link | awk -F'[ :]+' '/{mac_lower}/ {{print $2; exit}}'); [ -n "$DEV" ] || DEV=$(ip -o link | awk -F'[ :]+' '/{mac_upper}/ {{print $2; exit}}')"#,
        mac_lower = mac.to_lowercase(),
        mac_upper = mac,
    )
}


/// Where a recipe's compose file lives in the machine.
pub const RECIPE_DIR: &str = "/opt/onv/recipe";

/// Where a recipe records how its own install went. One file, one known path,
/// read with `VM.GuestAgent.FileRead` and nothing wider — see `recipe_progress`.
pub const RECIPE_STATUS: &str = "/etc/onv/recipe-status";

/// Where a recipe leaves the stream login it minted for itself.
///
/// **A second path, and it cannot be avoided by folding it into the first.**
/// The recipe runs under a trap that does `printf … > RECIPE_STATUS` on every
/// exit, which truncates — so anything the recipe wrote into that file would be
/// gone before this ever looked at it, and the body runs as a child shell that
/// cannot re-arm its parent's trap. Two files, one extra read.
pub const RECIPE_STREAM_CREDENTIAL: &str = "/etc/onv/recipe-stream-credential";

/// The login out of that file, or None when it is not there yet or not whole.
///
/// `user=…\npassword=…` — the same `key=value` shape the status file uses, and
/// unknown keys are ignored, so the recipe can add one without an agent that
/// predates it refusing to parse.
///
/// **Both halves or neither.** A blank user with a blank password is a login
/// nobody can use, handed up as one that works — the failure `CLAUDE.md` calls
/// worse than an absent credential, because a non-empty string passes every
/// `length > 0` check on the way and then refuses every sign-in at the end.
pub fn parse_stream_credentials(content: &str) -> Option<omnuv_protocol::StreamCredentials> {
    let (mut user, mut password) = (None, None);
    for line in content.lines() {
        match line.split_once('=') {
            Some(("user", v)) => user = Some(v.trim().to_string()),
            Some(("password", v)) => password = Some(v.trim().to_string()),
            _ => {}
        }
    }
    let (user, password) = (user?, password?);
    (!user.is_empty() && !password.is_empty())
        .then_some(omnuv_protocol::StreamCredentials { user, password: password.into() })
}

/// The recipe's compose file, written before any package runs. Base64: a
/// compose file is YAML inside YAML, and escaping it would be a bug farm.
pub fn recipe_files(recipe: &omnuv_protocol::RecipeSpec) -> String {
    write_file(&format!("{RECIPE_DIR}/compose.yaml"), "0644", &recipe.compose)
}

/// One `write_files` entry, its content as base64 so nothing in it can break
/// the cloud-config it rides in.
pub fn write_file(path: &str, permissions: &str, content: &str) -> String {
    use base64::Engine as _;
    format!(
        "  - path: {path}\n    permissions: \"{permissions}\"\n    encoding: b64\n    content: {}\n",
        base64::engine::general_purpose::STANDARD.encode(content)
    )
}

/// Where the machine's certificate fetch reads Core's origin and its bootstrap.
pub const CERT_PULL_ENV: &str = "/etc/onv/certificate/pull.env";
pub const CERT_SCRIPT: &str = include_str!("../guest/onv-certificate.sh");
pub const CERT_SERVICE: &str = include_str!("../guest/onv-certificate.service");
pub const CERT_TIMER: &str = include_str!("../guest/onv-certificate.timer");
pub const CERT_FIRST: &str = include_str!("../guest/onv-certificate-first.service");

/// **A web machine's certificate fetch** (omnuv-protocol v0.26.0; omnuv's
/// private names a browser trusts, D-2: pulled by the machine). The fetch
/// itself, its unit and its timer, and the file it reads: Core's origin and
/// the bootstrap, root's alone. The bootstrap is worth one trade at Core for a
/// token the machine keeps, and Core stops accepting it once that token has
/// fetched, so this file on a disk the provider can read is spent within
/// minutes of first boot, as the overlay's setup key is. The certificate's key
/// never passes through here: the machine fetches it over TLS.
pub fn certificate_files(pull: &omnuv_protocol::CertificatePull) -> String {
    let env = format!(
        "ONV_CORE_URL={}\nONV_BOOTSTRAP={}\n",
        pull.core_url.trim().trim_end_matches('/'),
        // `.expose()`: `Display` would write `<redacted>` here and the fetch
        // would be refused at every run, behind a machine that looks fine.
        pull.bootstrap_token.expose()
    );
    [
        write_file(CERT_PULL_ENV, "0600", &env),
        write_file("/usr/local/sbin/onv-certificate", "0755", CERT_SCRIPT),
        write_file("/etc/systemd/system/onv-certificate.service", "0644", CERT_SERVICE),
        write_file("/etc/systemd/system/onv-certificate.timer", "0644", CERT_TIMER),
        write_file("/etc/systemd/system/onv-certificate-first.service", "0644", CERT_FIRST),
    ]
    .concat()
}

/// Every file first boot writes, under one `write_files` key: YAML keeps the
/// last of two, so a second key would drop the first's files.
pub fn first_boot_files(spec: &InstanceSpec) -> String {
    let files = [
        spec.recipe.as_ref().map(recipe_files),
        spec.certificate.as_ref().map(certificate_files),
    ]
    .into_iter()
    .flatten()
    .collect::<String>();
    if files.is_empty() { String::new() } else { format!("write_files:\n{files}") }
}

/// The timer that keeps the certificate current, and first boot's wait for
/// the first one, asked every few seconds rather than a quarter hour apart.
/// `|| true`: a machine whose timer cannot start still boots and serves its
/// page over plain HTTP, as before.
pub fn certificate_runcmd(_: &omnuv_protocol::CertificatePull) -> String {
    "  - [ sh, -c, \"systemctl daemon-reload && systemctl enable --now onv-certificate.timer \
     && systemctl start --no-block onv-certificate-first.service || true\" ]\n"
        .to_string()
}

/// Whether a recipe actually runs containers.
///
/// `services: {}` is a real recipe shape — the gaming ones install packages and
/// configure a desktop session, and run nothing in Docker. Parsed rather than
/// pattern-matched, because "does this compose file have any services" is a
/// question about YAML and guessing at it with string matching is how a recipe
/// that works becomes one that mysteriously does not.
pub fn has_containers(compose: &str) -> bool {
    let Ok(doc) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(compose) else {
        // Unparseable: assume it means something and let compose say why.
        return true;
    };
    doc.get("services").and_then(|s| s.as_mapping()).is_some_and(|m| !m.is_empty())
}

/// Waits until this machine can actually fetch something, or gives up after
/// five minutes. DNS and a route are what every later step needs, and asking
/// for both at once is the only test that means anything.
///
/// Bounded rather than infinite: a machine whose internet never arrives should
/// fail with a recipe that did not install, not sit in a loop forever looking
/// like it is still working.
pub const WAIT_FOR_INTERNET: &str = r#"for i in $(seq 1 60); do
  if getent hosts get.docker.com >/dev/null 2>&1 && curl -fsS -m 10 -o /dev/null https://get.docker.com; then
    echo "omnuv: internet reachable after ${i} attempt(s)"
    exit 0
  fi
  sleep 5
done
echo "omnuv: no internet after five minutes; the recipe cannot install" >&2
exit 1"#;

/// Joins the machine to its buyer's overlay, at first boot.
///
/// **Topology v2.** The client runs here, in the machine, so WireGuard
/// terminates where the traffic actually ends. Under v1 it ran only on a
/// per-provider gateway and the last hop — gateway to machine, across a bridge
/// on the provider's hardware — was clear text.
///
/// The key is single-use and Core revokes it when the machine goes. It is
/// written into this file, which lives on a disk the provider can read, so its
/// one use is the whole of its value: by the time anyone else could read it,
/// it has been spent by the boot it was made for.
///
/// The client is in the image, not fetched here. An image is cloned; a machine
/// that apt-installs its own networking at first boot is one that fails when a
/// mirror is mid-sync, which is not a hypothetical — it cost a gaming rig on
/// 11 September and a smoke run the day after.
///
/// Failure is not fatal. `|| true` on the enrolment: a machine that cannot
/// reach the overlay still boots, still holds its provider-local address, and
/// still answers its console. Refusing to start would turn a network problem
/// into a dead machine, and the buyer can already see that it is unreachable.
/// **Every runcmd fragment ends with a newline and none begins with one.**
///
/// This one led with `\n` and ended without, which is the same shape as the
/// other convention and composes with nothing. On its own it looked right —
/// the guest-agent entry above it already ends a line — and the moment a
/// second fragment followed it, that fragment landed on this one's line:
///
///     - [ sh, -c, "netbird up … || true" ]  - |
///
/// and cloud-init rejected **the whole document**: *"sequence entries are not
/// allowed here"*, then *"Unexpected failure parsing userdata"*, then
/// `modules:final` finishing in 0.06 s having run nothing. The machine booted,
/// answered its console, reported RUNNING, and had no networking and no
/// enrolment — which is the first entry in `fixed.md`, met again from the
/// other direction.
/// **What the machine's overlay peer is called: never the buyer's name** (the
/// assets-by-id audit of 3 October 2026). Core's name when it sends one;
/// otherwise `onv-m-<instance id>`, the whole id, in the form the overlay's
/// own names take. Left unset, NetBird named the peer after the guest's
/// hostname, which is the buyer's name: a machine made again under a deleted
/// one's name enrolled as a namesake peer, and anything finding peers by name
/// found the wrong one.
pub fn peer_name(o: &omnuv_protocol::OverlayEnrolment, instance_id: &str) -> String {
    o.hostname.clone().filter(|h| !h.trim().is_empty()).unwrap_or_else(|| format!("onv-m-{instance_id}"))
}

/// The guest's hostname. The buyer's name is a display name inside the guest
/// (its prompt, `/etc/hosts`), and stays so where it identifies nothing: no
/// overlay, or a peer Core named. When Core enrols the machine and names no
/// peer, the guest takes the peer's id-based name, so the two agree and the
/// buyer's name is nowhere an identity is read from.
pub fn guest_hostname(spec: &InstanceSpec) -> String {
    match &spec.overlay {
        Some(o) if o.hostname.as_deref().is_none_or(|h| h.trim().is_empty()) => peer_name(o, &spec.id),
        _ => spec.name.clone(),
    }
}

/// The machine's enrolment. **Opened** (`crate::opening`), its WireGuard
/// listens on the port this host forwards to it and announces the public
/// address; otherwise it is the line it always was, byte for byte, so a
/// provider that never turns the opening on refreshes no machine's drive.
pub fn overlay_runcmd(
    o: &omnuv_protocol::OverlayEnrolment,
    instance_id: &str,
    opened: Option<&crate::opening::Opened>,
) -> String {
    let host_arg = format!(" --hostname {}", peer_name(o, instance_id));
    if let Some(opened) = opened {
        return crate::opening::netbird_up(
            &format!(
                "netbird up --management-url {url} --setup-key {key}{host_arg}",
                url = o.management_url,
                key = o.setup_key.expose()
            ),
            opened,
            &egress_mac(instance_id),
        );
    }
    format!(
        "  - [ sh, -c, \"netbird up --management-url {url} --setup-key {key}{host_arg} \
         >/var/log/onv-overlay.log 2>&1 || true\" ]\n",
        url = o.management_url,
        // `.expose()`, and the reason is that the compiler does not object to
        // its absence. `Redacted`'s `Display` prints `<redacted>`, so
        // `{key}` alone yields a cloud-config that is valid YAML, embeds a
        // syntactically fine `netbird up --setup-key <redacted>`, and enrols
        // nothing — behind `|| true`, on a machine that then boots, answers its
        // console and reports RUNNING. This is the one place in the agent where
        // the redaction could have shipped as a silent outage rather than as a
        // build error, which is why the test below asserts the key's own bytes
        // reach the guest rather than that this file compiles.
        key = o.setup_key.expose(),
    )
}

/// Brings the recipe up in runcmd: Docker from its own installer, the NVIDIA
/// container toolkit when the containers reserve a GPU (the image already
/// carries the driver), then `compose up` and the recipe's finishing steps.
/// Each command is a base64 script so nothing the recipe contains can break
/// the cloud-config it rides in.
pub fn recipe_steps(recipe: &omnuv_protocol::RecipeSpec) -> Vec<(&'static str, String)> {
    // Each step with the words a buyer reads while it runs (the Instances
    // redesign, 3 October 2026; omnuv-protocol v0.25.0 `label`).
    let mut steps: Vec<(&'static str, String)> = vec![
        // Nothing below works without the internet, and runcmd does not
        // reliably have it. A buyer machine has two interfaces, and
        // `systemd-networkd-wait-online` waits for *every* managed link: the
        // project one gets its address from the provider's gateway, which is
        // not always there first. When that wait fails cloud-init carries on
        // anyway and the first curl pays for it.
        //
        // So wait for the thing actually needed rather than for networkd's
        // opinion of the interfaces.
        ("Waiting for the network", WAIT_FOR_INTERNET.into()),
    ];

    // A recipe with no containers needs no container runtime. The gaming
    // recipes install packages and configure a session; `docker compose up -d`
    // on `services: {}` fails, and with the steps now chained under `set -e`
    // that failure took the rest of the recipe with it — which is how a rig
    // came up with no display manager and no streaming host.
    //
    // Skipping Docker for these also saves minutes on every gaming machine
    // that was previously spent installing something nothing would use.
    //
    // Each is skipped where the image already carries it (a recipe's own
    // image, as `ubuntu-26.04-ollama` does since 2 October 2026): Docker's
    // installer, finding Docker, pauses twenty seconds and reinstalls it, and
    // the toolkit's costs an apt update. Configuring the runtime is not
    // skipped; it is idempotent and is what makes the GPU visible.
    if has_containers(&recipe.compose) {
        steps.push((
            "Installing Docker",
            "command -v docker >/dev/null 2>&1 || curl -fsSL https://get.docker.com | sh".into(),
        ));
    }
    if recipe.gpu && has_containers(&recipe.compose) {
        steps.push((
            "Preparing the GPU",
            "if ! command -v nvidia-ctk >/dev/null 2>&1; then \
             curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg && \
             curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' > /etc/apt/sources.list.d/nvidia-container-toolkit.list && \
             apt-get update && apt-get install -y nvidia-container-toolkit; fi && \
             nvidia-ctk runtime configure --runtime=docker && systemctl restart docker"
                .into(),
        ));
    }
    if has_containers(&recipe.compose) {
        steps.push(("Starting the application", format!("cd {RECIPE_DIR} && docker compose up -d")));
    }
    for cmd in &recipe.post_up {
        steps.push(("Finishing setup", format!("cd {RECIPE_DIR} && {cmd}")));
    }
    // One runcmd entry, not one per step, and this is the whole point.
    //
    // cloud-init writes runcmd as `#!/bin/sh` with **no `set -e`**, so a
    // failing entry is skipped and every later one runs anyway. A gaming rig
    // came up with Steam and a streaming host but no display manager, because
    // the step that installs the session hit one package that no longer exists
    // on this release and was quietly stepped over. Worse, cloud-init's own
    // status reflects only the *last* command, so the machine reported success.
    //
    // Collapsing the recipe into one script under `set -e` makes a failing step
    // stop the recipe and makes the failure visible in `cloud-init status`,
    // which is the only thing outside the guest that can see any of this.
    //
    // **And it says which step it is on before running it**, in the same
    // file the EXIT trap writes at the end, so the install's progress can be
    // read while it runs and not only once it has stopped. No `rc=` line until
    // the trap: that is how a reader tells running from finished.
    steps
}

/// The recipe's install, as one runcmd entry: `steps` numbered from `first`
/// out of `total`, the steps before them being the machine's own (see
/// [`early_steps`]).
pub fn recipe_runcmd(steps: &[(&'static str, String)], first: usize, total: usize) -> String {
    let script = install_script(steps, RECIPE_STATUS, first, total);
    format!("  - [ bash, -c, \"echo {} | base64 -d | bash\" ]\n", b64(&script))
}

pub fn b64(script: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(script)
}

/// **The machine's own steps, before the recipe's** (the operator's choice of
/// 3 October 2026, "option 1"). On a recipe's baked image the install script
/// runs about ten seconds and starts late: before it, the machine boots,
/// installs its first packages and joins its network, and the status file did
/// not exist, so the card said "Installing" with no step for most of the
/// wait. These are written where they happen: the first from bootcmd, the
/// second at the start of runcmd, before the network is joined.
pub fn early_steps(spec: &InstanceSpec) -> Vec<&'static str> {
    if spec.recipe.is_none() {
        return Vec::new();
    }
    let mut early = vec!["Starting the machine"];
    if spec.overlay.is_some() {
        early.push("Joining your private network");
    }
    early
}

/// One status line, `step=n/total` and its label, as a cloud-init list entry.
/// `only_if_absent` for bootcmd, which runs on every boot: a later boot must
/// never overwrite what a finished or failed install wrote.
pub fn status_line(n: usize, total: usize, label: &str, only_if_absent: bool) -> String {
    let guard = if only_if_absent { format!("[ -e {RECIPE_STATUS} ] && exit 0\n") } else { String::new() };
    let script = format!(
        "mkdir -p \"$(dirname {RECIPE_STATUS})\"\n{guard}printf 'step=%s\\nlabel=%s\\n' '{n}/{total}' '{label}' > {RECIPE_STATUS}\n"
    );
    format!("  - [ bash, -c, \"echo {} | base64 -d | bash\" ]\n", b64(&script))
}

/// The whole install as one bash script: each step labelled and run in turn
/// under `set -e`, its step and label written to `status` before it runs, and
/// the EXIT trap writing the step, label and exit code at the end. Pure, so a
/// test can run it with harmless steps and a status file of its own.
/// What the install's status file says: `step=3/6\nlabel=…` written before
/// each step, and `rc=` added by the EXIT trap at the end. `None` when it says
/// nothing yet. Pure; `recipe_progress` adds the stream login after it.
pub fn progress_from(status: &str) -> Option<omnuv_protocol::RecipeProgress> {
    let mut step = None;
    let mut label = None;
    let mut rc = None;
    for line in status.lines() {
        match line.split_once('=') {
            Some(("step", v)) => step = Some(v.trim().to_string()),
            Some(("label", v)) if !v.trim().is_empty() => label = Some(v.trim().to_string()),
            Some(("rc", v)) => rc = v.trim().parse::<i32>().ok(),
            _ => {}
        }
    }
    // "finished" and "starting" are not steps anyone needs to see.
    let step = step.filter(|s| s != "finished" && s != "starting");
    // **A step and no exit code is an install under way**: the line written
    // before each step, not yet overwritten by the trap.
    let Some(rc) = rc else {
        return step.map(|step| omnuv_protocol::RecipeProgress {
            status: "running".to_string(),
            step: Some(step),
            label,
            detail: None,
            stream_credentials: None,
            stream_identity: None,
        });
    };
    Some(omnuv_protocol::RecipeProgress {
        status: if rc == 0 { "done" } else { "error" }.to_string(),
        label: step.as_ref().and(label),
        step,
        detail: (rc != 0).then(|| {
            format!("The recipe stopped with exit code {rc}. Its output is in the machine's own /var/log/cloud-init-output.log.")
        }),
        stream_credentials: None,
        stream_identity: None,
    })
}

/// **A step is a file bash runs, never bash's standard input** (5 October
/// 2026). Piped in, a step's first command that reads standard input reads the
/// rest of the step instead: Ollama's `docker compose exec -T` did, and every
/// line after it, the HTTPS front among them, never ran, while bash, at the end
/// of its input, exited 0 and the console said done. Standard input is
/// `/dev/null`, as it is for a step nobody types into.
pub fn install_script(steps: &[(&'static str, String)], status: &str, first: usize, total: usize) -> String {
    let body: String = steps
        .iter()
        .enumerate()
        .map(|(i, (label, script))| {
            format!(
                "STEP={}/{}\nLABEL='{label}'\n\
                 printf 'step=%s\\nlabel=%s\\n' \"$STEP\" \"$LABEL\" > {status}\n\
                 echo \"omnuv: recipe step $STEP\"\necho {} | base64 -d > {status}.step\n\
                 bash {status}.step </dev/null\n",
                first + i,
                total,
                b64(script)
            )
        })
        .collect();

    // The recipe says how it went, in one file, written whatever happens.
    //
    // This is the only thing outside the machine that can tell a finished
    // install from an abandoned one, and it is written *by the recipe* rather
    // than inferred from outside. The provider reads this one path and nothing
    // else: reading a known file needs `VM.GuestAgent.FileRead`, while asking
    // the guest to run `cloud-init status` would need
    // `VM.GuestAgent.Unrestricted` — arbitrary command execution inside a
    // buyer's machine. The agent holds that on the buyer pool for one call,
    // `set-user-password` (BUYER-18), and uses it for nothing else: a status
    // read is never a reason to run something in the buyer's guest.
    let script = format!(
        "set -e\n\
         mkdir -p \"$(dirname {status})\"\n\
         STEP=starting\n\
         LABEL=\n\
         trap 'rc=$?; printf \"step=%s\\nlabel=%s\\nrc=%s\\n\" \"$STEP\" \"$LABEL\" \"$rc\" > {status}' EXIT\n\
         {body}\
         STEP=finished\n\
         echo \"omnuv: recipe finished\"\n"
    );
    script
}

/// cloud-init for a buyer VM. Only public keys go in; Omnuv never has a private
/// key to inject even if it wanted to.
/// The machine's network, rendered before `systemd-networkd` starts.
///
/// **This exists because of *when* cloud-init reads things.** Network config is
/// rendered in `init-local`; `bootcmd` in the user data runs later, in `init`,
/// and cloud-init runs its own `systemd-networkd-wait-online` between the two.
/// So a machine whose segment was configured only from `bootcmd` had an
/// unconfigured link at wait time, and every first boot carried
///
///     Failed to wait for network: ... systemd-networkd-wait-online.service
///     failed because the control process exited with error code
///
/// twice — once in `init`, once in `modules-config` — which delayed the config
/// stage by about two minutes and therefore delayed enrolment by the same.
/// `RequiredForOnline=degraded` in the `.network` file cannot help: networkd
/// has not read that file yet when the wait happens.
///
/// Both NICs are named, matched by MAC rather than by kernel name, because the
/// distro chooses the name and it differs by image and by slot. The egress NIC
/// takes DHCP from the host; the segment NIC is on-link across the project
/// prefix with no gateway and no resolver, for the reasons in
/// `private_network` — which still writes the same address in `bootcmd`, so it
/// converges on every later boot even if the drive is refreshed.
pub fn network_config(spec: &InstanceSpec, vmid: u32) -> String {
    let egress = egress_mac(&spec.id);
    let Some(net) = &spec.network else {
        // No private network: the egress NIC alone, and nothing said about a
        // link the machine does not have.
        return format!(
            "version: 2\nethernets:\n  onv0:\n    match:\n      macaddress: \"{egress}\"\n    dhcp4: true\n"
        );
    };
    format!(
        "version: 2\n\
         ethernets:\n  \
         onv0:\n    \
         match:\n      \
         macaddress: \"{egress}\"\n    \
         dhcp4: true\n  \
         onv1:\n    \
         match:\n      \
         macaddress: \"{mac}\"\n    \
         dhcp4: false\n    \
         addresses: [{address}/{prefix}]\n",
        mac = net.mac,
        address = crate::segment::segment_address(vmid),
        prefix = SEGMENT_PREFIX,
    )
}

/// **The user-data a machine's first boot reads, by its guest kind**: the
/// image's OS family chooses (`guest_windows::guest_kind`). Linux's is the
/// cloud-config below, byte for byte what it was; Windows' is cloudbase-init's
/// (`guest_windows::user_data`), and `opened` is not given to it.
pub fn first_boot_user_data(
    spec: &InstanceSpec,
    apt_mirror: Option<&str>,
    vmid: u32,
    opened: Option<crate::opening::Opened>,
) -> anyhow::Result<String> {
    Ok(match crate::windows::guest_kind(&spec.image)? {
        GuestKind::Linux => cloud_init_opened(spec, apt_mirror, vmid, opened),
        GuestKind::Windows => crate::windows::user_data(spec)?,
    })
}

pub fn cloud_init_opened(
    spec: &InstanceSpec,
    apt_mirror: Option<&str>,
    vmid: u32,
    opened: Option<crate::opening::Opened>,
) -> String {
    // Written before anything installs, so cloud-init rewrites sources.list
    // first: the guest agent's fallback install and a recipe's use it.
    // Empty when the provider has not named one, which leaves the image's own
    // default — correct for a provider who has not been asked yet, and slow
    // where the default pool is slow.
    let apt = match apt_mirror {
        Some(m) if !m.trim().is_empty() => format!(
            "apt:\n  primary:\n    - arches: [default]\n      uri: {}\n",
            m.trim()
        ),
        _ => String::new(),
    };
    // Two indent levels, because the same list appears at two depths. Getting
    // this wrong parses the keys as a sibling of the users list instead of the
    // user's keys, and cloud-init then silently creates an account nobody can
    // log into.
    let render = |indent: &str| {
        if spec.ssh_keys.is_empty() {
            format!("{indent}[]")
        } else {
            spec.ssh_keys
                .iter()
                .map(|k| format!("{indent}- {}", k.trim().replace('\n', " ")))
                .collect::<Vec<_>>()
                .join("\n")
        }
    };

    // The machine's own steps, then the recipe's, out of one total.
    let early = early_steps(spec);
    let steps = spec.recipe.as_ref().map(recipe_steps);
    let total = early.len() + steps.as_ref().map_or(0, |s| s.len());

    format!(
        r#"#cloud-config
hostname: {name}
manage_etc_hosts: true
users:
  # `default` keeps the image's own user (ubuntu), which most tooling assumes.
  - default
  - name: {user}
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: {lock}
{hashed}    ssh_authorized_keys:
{nested}
# Applies to the default user.
ssh_authorized_keys:
{top}
{password}{apt}{recipe_files}# The marketplace network is configured in bootcmd, which cloud-init runs in
# the init stage on EVERY boot — before the config stage where apt runs, and
# unlike runcmd, which runs only once. A slow first-boot apt used to leave the
# private network unconfigured forever; here it comes up regardless.
bootcmd:
  # --no-block: in the init stage a start job for a unit ordered after
  # basic.target cannot complete until this very stage finishes; waiting on
  # it is a deadlock that looks like a boot stuck at cloud-init-network.
  - [ sh, -c, "systemctl enable --now --no-block qemu-guest-agent 2>/dev/null || true" ]
{recipe_boot}{network}
# The guest agent is baked into every template (build-template.yml), so apt
# runs only for an image that lacks it. It was `packages: [qemu-guest-agent]`,
# which makes cloud-init run `apt-get update` first even when the package is
# already there: 8.0 s of every first boot, measured on an Ollama install on
# production on 4 October 2026, for a no-op install. Networking already ran
# in bootcmd, so an apt here, on an older image, delays nothing else.
runcmd:
  - [ sh, -c, "command -v qemu-ga >/dev/null 2>&1 || {{ apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y qemu-guest-agent; }}; systemctl enable --now qemu-guest-agent || true" ]
{recipe_join}{overlay}{network_final}{certificate}{recipe_final}"#,
        apt = apt,
        name = guest_hostname(spec),
        overlay = spec.overlay.as_ref().map(|o| overlay_runcmd(o, &spec.id, opened.as_ref())).unwrap_or_default(),
        recipe_files = first_boot_files(spec),
        certificate = spec.certificate.as_ref().map(certificate_runcmd).unwrap_or_default(),
        recipe_boot = early.first().map(|l| status_line(1, total, l, true)).unwrap_or_default(),
        recipe_join = early.get(1).map(|l| status_line(2, total, l, false)).unwrap_or_default(),
        recipe_final = steps.as_ref().map(|st| recipe_runcmd(st, early.len() + 1, total)).unwrap_or_default(),
        user = spec.image.default_user,
        // A password is only usable when the account is not locked; without
        // one, the account stays key-only as before.
        lock = if spec.console_password_hash.is_some() { "false" } else { "true" },
        // **The hash goes on the user entry, not in a `chpasswd` block.**
        //
        // It was in `chpasswd`, and cloud-init said so on every machine:
        //
        //     Not unlocking password for user omnuv. 'lock_passwd: false'
        //     present in user-data but no 'passwd'/'plain_text_passwd'/
        //     'hashed_passwd' provided in user-data
        //
        // `cc_users_groups` creates the account in the *init* stage and will
        // not unlock it without a hash it can see there; `chpasswd` runs later,
        // in `modules:config`. So the account was created locked, and whether
        // the console password worked afterwards depended on a second module
        // undoing the first — which is not a thing to leave a buyer's only
        // out-of-band access resting on.
        //
        // `hashed_passwd` on the user entry is what the warning asks for, and
        // it does not expire the password the way `chpasswd` defaults to.
        hashed = spec
            .console_password_hash
            .as_deref()
            .map(|hash| format!("    hashed_passwd: \"{hash}\"\n"))
            .unwrap_or_default(),
        // SSH stays key-only regardless. The console password is for the
        // console, and a machine that accepted it over SSH would be a machine
        // whose one-time password is an internet-facing credential.
        password = if spec.console_password_hash.is_some() { "ssh_pwauth: false\n" } else { "" },
        nested = render("      "),
        top = render("  "),
        network = spec.network.as_ref().map(|n| private_network(n, vmid)).unwrap_or_default(),
        // Binds the marketplace NIC to our networkd file on first boot. By the
        // time this link appeared, networkd had already bound it to the
        // image's catch-all (dracut's DHCP-everything); a new file is only
        // seen after `reload`, and a bound link is only re-matched by
        // `reconfigure`. Both are D-Bus calls, which is why this cannot live
        // in bootcmd. First boot only: later boots bind the file directly.
        network_final = spec
            .network
            .as_ref()
            .map(|n| {
                format!(
                    "  - |\n    {}\n    systemctl enable systemd-networkd 2>/dev/null || true\n    networkctl reload\n    networkctl reconfigure $DEV\n",
                    resolve_dev(&n.mac)
                )
            })
            .unwrap_or_default(),
    )
}

/// Configures the machine's place on the buyer's private network.
///
/// **On-link across the project prefix, and nothing else** — no route, no
/// next hop, no resolver. That is the whole of the v2 change here, and it
/// inverts what this used to do.
///
/// Under v1 the address was a `/32` and the project prefix was routed through
/// the provider's gateway at `.1`, because machines on other providers were
/// only reachable through it. The gateway is gone: every machine is an overlay
/// peer, the tunnel installs its own routes for every peer in the project, and
/// a `/24` route through `.1` would name a VM that was deleted.
///
/// What the segment is still for is the machine *next to this one*. Two of a
/// buyer's machines on the same provider share it, and without a local address
/// on it WireGuard has no local candidate to offer: `@private` drops their
/// public-side addresses and Linux does not hairpin its own masquerade, so two
/// machines 30 cm apart would meet on a relay. On-link across the prefix is
/// exactly what gives them that candidate.
///
/// Two machines of the same project on *different* providers are not on the
/// same wire, and now nothing pretends they are: they never ARP for each
/// other, because the overlay's route for the far peer is more specific and
/// wins.
///
/// Private names are resolved by the overlay client from the zone its own
/// network map carries — not by a `DNS=` line pointing at the gateway's `.1`,
/// which after v2 would have sent every `.internal` lookup to a dead address
/// and timed out while every status said `RUNNING`.
pub fn private_network(net: &NetworkAttachment, vmid: u32) -> String {
    // One YAML block scalar (`- |`), not `[ sh, -c, "..." ]` flow entries: the
    // MAC-resolution shell needs both single quotes (awk) and double quotes
    // (`[ -n "$DEV" ]`), and a double quote inside a flow scalar closes it and
    // makes cloud-init reject the entire config. A literal block is verbatim.
    format!(
        r#"  # The buyer's private network. This interface is on the provider's
  # isolated marketplace bridge, which has no uplink: this machine has no path
  # to the provider's own network at all.
  - |
    {resolve}
    ip link set dev $DEV up
    # On-link across the project prefix. No route and no next hop: the segment
    # has no uplink, and the overlay carries everything that is not on this
    # wire.
    ip addr replace {address}/{prefix} dev $DEV
    # `RequiredForOnline=degraded`, and it is not cosmetic. This link has an
    # address and no route beyond its own segment — by design, under topology
    # v2 — so networkd settles it at `degraded`, never `routable`.
    # `systemd-networkd-wait-online` requires `routable` from every managed
    # link by default, so it waited for this one until it timed out:
    #
    #     Failed to wait for network: ... systemd-networkd-wait-online.service
    #     failed because the control process exited with error code
    #
    # on every boot of every machine, pushing `modules:config` two minutes late
    # and making cloud-init's own recoverable-error list something nobody could
    # read for the noise. `degraded` says what is true: the link is up and
    # addressed, and a route is not what it is for.
    #
    # The declarative copy. No DNS= line: private names are answered by the
    # overlay client's own resolver, from the zone its network map carries, so
    # pointing this link at a resolver would be pointing it at nothing.
    #
    # Only written here, not applied: bootcmd runs before D-Bus is up, so
    # networkctl and resolvectl cannot act yet (they fail silently). runcmd
    # applies it on first boot; on every later boot networkd binds the file
    # itself, and its name sorts before the image's catch-all and any netplan
    # file so it always wins the match.
    printf '[Match]\nMACAddress={mac}\n\n[Link]\nRequiredForOnline=degraded\n\n[Network]\nAddress={address}/{prefix}\n' > /etc/systemd/network/05-onv.network
"#,
        address = crate::segment::segment_address(vmid),
        prefix = SEGMENT_PREFIX,
        mac = net.mac,
        resolve = resolve_dev(&net.mac),
    )
}

/// The prefix the segment range is carved from — see `names::SEGMENT_RANGE`.
pub const SEGMENT_PREFIX: u8 = 16;

#[cfg(test)]
mod mac_tests {
    /// The derivation this crate carried until protocol v0.28.0, kept only
    /// to hold the protocol's to it: a MAC that moved would leave every
    /// existing machine's first boot matching an interface it no longer has.
    fn as_it_was(id: &str, salt: &[u8]) -> String {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in id.as_bytes().iter().chain(salt) {
            h ^= *b as u64;
            h = h.wrapping_mul(0x1000_0000_01b3);
        }
        format!(
            "02:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            (h >> 32) as u8, (h >> 24) as u8, (h >> 16) as u8, (h >> 8) as u8, h as u8
        )
    }

    /// **Every MAC is the one the old copy derived**, both interfaces, over
    /// ids of the shapes machines have (a uuid, a short test id, empty, and
    /// one long enough to wrap the hash many times); and the two interfaces
    /// of one machine still differ.
    #[test]
    fn the_protocols_macs_are_the_ones_this_crate_derived() {
        let long = "x".repeat(300);
        for id in ["c4d90fd2-be3d-4225-a4a6-265138a76e49", "m-a", "", long.as_str(), "0a0b0c0d-0000-4000-8000-ffffffffffff"] {
            assert_eq!(super::marketplace_mac(id), as_it_was(id, b""), "the marketplace MAC of {id:?} moved");
            assert_eq!(super::egress_mac(id), as_it_was(id, b"onv-egress"), "the egress MAC of {id:?} moved");
            assert_ne!(super::marketplace_mac(id), super::egress_mac(id));
        }
    }
}
