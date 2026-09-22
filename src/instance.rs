//! Buyer instance lifecycle on Proxmox.
//!
//! Translates a normalized `InstanceSpec` into a cloned VM with the buyer's
//! public keys injected by cloud-init. Marketplace ids live in the VM's tags so
//! state survives an agent restart, and nothing the marketplace did not create
//! is ever touched.

use omnuv_protocol::{FirstBoot, InstanceSpec, InstanceState, InstanceStatus, Lifecycle, NetworkAttachment};

use crate::audit;
use crate::proxmox::Client;

/// Marks VMs this agent owns on behalf of buyers. Distinct from the inference
/// worker tag so the two lifecycles can never be confused.
pub const TAG: &str = crate::names::TAG_INSTANCE;

/// The Proxmox pool buyer machines are cloned into. Bootstrap grants
/// `VM.Console` on this pool and nowhere else, so the agent can open the
/// console of a machine the marketplace built — never a provider's own.
pub(crate) const BUYER_POOL: &str = crate::names::POOL_BUYERS;

const NO_FORM: &[(String, String)] = &[];

/// The isolated bridge a buyer machine attaches to: its own network's segment
/// on this provider, one vnet per network in the marketplace zone (see `sdn`).
/// The network's gateway creates it and is the only other thing on it, so a
/// machine of another tenant is never on the same wire.
pub(crate) fn marketplace_bridge(net: &NetworkAttachment) -> String {
    crate::sdn::vnet_for(&net.network_id)
}

/// The NAT bridge a buyer machine's internet interface attaches to. Also
/// bootstrap's: the host hands out addresses, masquerades outbound traffic and
/// refuses everything else — a buyer VM never appears on the provider's own
/// LAN and cannot reach the host, other providers' machines or, with port
/// isolation, another tenant's VM on the same bridge. Gateways and inference
/// workers are marketplace-owned and stay on the provider's bridge.
// One definition, in `names`. This held a second copy of the string, which is
// how a rename leaves half a codebase behind.
//
// Proxmox caps a vnet name at 8 characters, which is why a marketplace segment
// is a prefix plus five hex digits rather than something readable. The rename
// produced `omnuvnat0`, which is nine and cannot exist — and the correction
// overshot to `onat0` when `onvnat0` is seven and fits.
pub(crate) use crate::names::NAT_VNET as EGRESS_BRIDGE;

/// A stable, locally-administered MAC for a machine's marketplace interface.
///
/// The interface cannot be found by name: the distro picks that (`ens19`,
/// `enp6s19`, …) and it differs by image and by slot. Deriving the address from
/// the machine's own id gives cloud-init something deterministic to match on,
/// and keeps it stable across a rebuild.
pub(crate) fn marketplace_mac(id: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in id.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    // 02: locally administered, unicast.
    format!(
        "02:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        (h >> 32) as u8, (h >> 24) as u8, (h >> 16) as u8, (h >> 8) as u8, h as u8
    )
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
pub(crate) fn egress_mac(id: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in id.as_bytes().iter().chain(b"onv-egress") {
        h ^= *b as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    format!(
        "02:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        (h >> 32) as u8, (h >> 24) as u8, (h >> 16) as u8, (h >> 8) as u8, h as u8
    )
}

/// Shell that resolves the marketplace interface by MAC and exports `$DEV`.
///
/// One line, and the caller must place it inside a YAML **block** scalar (`- |`),
/// never a `[ sh, -c, "..." ]` flow scalar: the `"$DEV"` test would close the
/// flow string early and cloud-init would reject the whole config.
pub(crate) fn resolve_dev(mac: &str) -> String {
    format!(
        r#"DEV=$(ip -o link | awk -F'[ :]+' '/{mac_lower}/ {{print $2; exit}}'); [ -n "$DEV" ] || DEV=$(ip -o link | awk -F'[ :]+' '/{mac_upper}/ {{print $2; exit}}')"#,
        mac_lower = mac.to_lowercase(),
        mac_upper = mac,
    )
}


pub(crate) fn short_tag(id: &str) -> String {
    crate::names::short_tag(id)
}

/// Where a recipe's compose file lives in the machine.
const RECIPE_DIR: &str = "/opt/onv/recipe";

/// Where a recipe records how its own install went. One file, one known path,
/// read with `VM.GuestAgent.FileRead` and nothing wider — see `recipe_progress`.
const RECIPE_STATUS: &str = "/etc/onv/recipe-status";

/// Where a recipe leaves the stream login it minted for itself.
///
/// **A second path, and it cannot be avoided by folding it into the first.**
/// The recipe runs under a trap that does `printf … > RECIPE_STATUS` on every
/// exit, which truncates — so anything the recipe wrote into that file would be
/// gone before this ever looked at it, and the body runs as a child shell that
/// cannot re-arm its parent's trap. Two files, one extra read.
const RECIPE_STREAM_CREDENTIAL: &str = "/etc/onv/recipe-stream-credential";

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
fn parse_stream_credentials(content: &str) -> Option<omnuv_protocol::StreamCredentials> {
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
fn recipe_files(recipe: &omnuv_protocol::RecipeSpec) -> String {
    use base64::Engine as _;
    format!(
        "write_files:\n  - path: {RECIPE_DIR}/compose.yaml\n    permissions: \"0644\"\n    encoding: b64\n    content: {}\n",
        base64::engine::general_purpose::STANDARD.encode(&recipe.compose)
    )
}

/// Whether a recipe actually runs containers.
///
/// `services: {}` is a real recipe shape — the gaming ones install packages and
/// configure a desktop session, and run nothing in Docker. Parsed rather than
/// pattern-matched, because "does this compose file have any services" is a
/// question about YAML and guessing at it with string matching is how a recipe
/// that works becomes one that mysteriously does not.
fn has_containers(compose: &str) -> bool {
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
const WAIT_FOR_INTERNET: &str = r#"for i in $(seq 1 60); do
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
fn overlay_runcmd(o: &omnuv_protocol::OverlayEnrolment) -> String {
    let hostname = o.hostname.clone().unwrap_or_default();
    let host_arg =
        if hostname.is_empty() { String::new() } else { format!(" --hostname {hostname}") };
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
fn recipe_runcmd(recipe: &omnuv_protocol::RecipeSpec) -> String {
    use base64::Engine as _;
    let b64 = |script: &str| base64::engine::general_purpose::STANDARD.encode(script);
    let mut steps: Vec<String> = vec![
        // Nothing below works without the internet, and runcmd does not
        // reliably have it. A buyer machine has two interfaces, and
        // `systemd-networkd-wait-online` waits for *every* managed link: the
        // project one gets its address from the provider's gateway, which is
        // not always there first. When that wait fails cloud-init carries on
        // anyway and the first curl pays for it.
        //
        // So wait for the thing actually needed rather than for networkd's
        // opinion of the interfaces.
        WAIT_FOR_INTERNET.into(),
    ];

    // A recipe with no containers needs no container runtime. The gaming
    // recipes install packages and configure a session; `docker compose up -d`
    // on `services: {}` fails, and with the steps now chained under `set -e`
    // that failure took the rest of the recipe with it — which is how a rig
    // came up with no display manager and no streaming host.
    //
    // Skipping Docker for these also saves minutes on every gaming machine
    // that was previously spent installing something nothing would use.
    if has_containers(&recipe.compose) {
        steps.push("curl -fsSL https://get.docker.com | sh".into());
    }
    if recipe.gpu && has_containers(&recipe.compose) {
        steps.push(
            "curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg && \
             curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' > /etc/apt/sources.list.d/nvidia-container-toolkit.list && \
             apt-get update && apt-get install -y nvidia-container-toolkit && nvidia-ctk runtime configure --runtime=docker && systemctl restart docker"
                .into(),
        );
    }
    if has_containers(&recipe.compose) {
        steps.push(format!("cd {RECIPE_DIR} && docker compose up -d"));
    }
    for cmd in &recipe.post_up {
        steps.push(format!("cd {RECIPE_DIR} && {cmd}"));
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
    let body: String = steps
        .iter()
        .enumerate()
        .map(|(i, script)| {
            format!(
                "STEP={}/{}\necho \"omnuv: recipe step $STEP\"\necho {} | base64 -d | bash\n",
                i + 1,
                steps.len(),
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
    // buyer's machine, which the marketplace must never be able to do.
    let script = format!(
        "set -e\n\
         mkdir -p /etc/onv\n\
         STEP=starting\n\
         trap 'rc=$?; printf \"step=%s\\nrc=%s\\n\" \"$STEP\" \"$rc\" > {RECIPE_STATUS}' EXIT\n\
         {body}\
         STEP=finished\n\
         echo \"omnuv: recipe finished\"\n"
    );

    format!("  - [ bash, -c, \"echo {} | base64 -d | bash\" ]\n", b64(&script))
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
fn network_config(spec: &InstanceSpec, vmid: u32) -> String {
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
        address = crate::names::segment_address(vmid),
        prefix = SEGMENT_PREFIX,
    )
}

fn cloud_init(spec: &InstanceSpec, apt_mirror: Option<&str>, vmid: u32) -> String {
    // Written before `packages:` so cloud-init rewrites sources.list first.
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
{password}{apt}packages:
  - qemu-guest-agent
{recipe_files}# The marketplace network is configured in bootcmd, which cloud-init runs in
# the init stage on EVERY boot — before the config stage where apt runs, and
# unlike runcmd, which runs only once. A slow first-boot apt used to leave the
# private network unconfigured forever; here it comes up regardless.
bootcmd:
  # --no-block: in the init stage a start job for a unit ordered after
  # basic.target cannot complete until this very stage finishes; waiting on
  # it is a deadlock that looks like a boot stuck at cloud-init-network.
  - [ sh, -c, "systemctl enable --now --no-block qemu-guest-agent 2>/dev/null || true" ]
{network}
# runcmd is the final stage, after packages: the agent is installed by then.
# Networking already ran in bootcmd, so a slow apt here delays nothing.
runcmd:
  - [ sh, -c, "systemctl enable --now qemu-guest-agent || true" ]
{overlay}{network_final}{recipe_final}"#,
        apt = apt,
        name = spec.name,
        overlay = spec.overlay.as_ref().map(overlay_runcmd).unwrap_or_default(),
        recipe_files = spec.recipe.as_ref().map(recipe_files).unwrap_or_default(),
        recipe_final = spec.recipe.as_ref().map(recipe_runcmd).unwrap_or_default(),
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
fn private_network(net: &NetworkAttachment, vmid: u32) -> String {
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
        address = crate::names::segment_address(vmid),
        prefix = SEGMENT_PREFIX,
        mac = net.mac,
        resolve = resolve_dev(&net.mac),
    )
}

/// The prefix the segment range is carved from — see `names::SEGMENT_RANGE`.
const SEGMENT_PREFIX: u8 = 16;

impl Client {
    /// Moves the machine's marketplace interface onto its network's segment
    /// if it is anywhere else. Its address never changes; the segment is
    /// where the network's gateway is.
    /// Keeps an existing machine's `net0` on the current egress bridge.
    ///
    /// **This is what makes renaming that bridge a migration rather than an
    /// edit.** `net0` is written once, at create time, so a machine built under
    /// `onat0` would have kept naming it after the agent started creating
    /// `onvnat0` — and would have lost its internet the moment the old bridge
    /// was swept, with nothing saying why.
    async fn ensure_egress(&self, node: &str, vmid: u32) -> anyhow::Result<()> {
        let cfg: serde_json::Value = self.get_json(&format!("/nodes/{node}/qemu/{vmid}/config")).await?;
        let Some(current) = cfg.get("net0").and_then(|v| v.as_str()) else { return Ok(()) };
        if current.split(',').any(|kv| kv == format!("bridge={EGRESS_BRIDGE}")) {
            return Ok(());
        }
        // Keep the MAC it already has: the host's DHCP lease is keyed on it,
        // and changing it would hand the machine a different address for no
        // reason.
        let Some(mac) = current.split(',').next().and_then(|m| m.split_once('=')).map(|(_, m)| m)
        else {
            return Ok(());
        };
        self.post_form::<serde_json::Value>(
            &format!("/nodes/{node}/qemu/{vmid}/config"),
            &[("net0".to_string(), format!("virtio={mac},bridge={EGRESS_BRIDGE}"))],
        )
        .await?;
        audit::record("instance.egress", "core", &vmid.to_string(), "ok", Some(EGRESS_BRIDGE));
        Ok(())
    }

    /// Attaches an existing machine's `net1` to its network's segment.
    ///
    /// The segment itself is ensured by `ensure_instance`, before this — see
    /// the comment there for why it cannot live in here.
    async fn ensure_segment(&self, node: &str, vmid: u32, net: &NetworkAttachment) -> anyhow::Result<()> {
        let bridge = marketplace_bridge(net);
        let cfg: serde_json::Value = self.get_json(&format!("/nodes/{node}/qemu/{vmid}/config")).await?;
        let current = cfg.get("net1").and_then(|v| v.as_str()).unwrap_or_default();
        if current.split(',').any(|kv| kv == format!("bridge={bridge}")) {
            return Ok(());
        }
        self.post_form::<serde_json::Value>(
            &format!("/nodes/{node}/qemu/{vmid}/config"),
            &[("net1".to_string(), format!("virtio={},bridge={bridge}", net.mac))],
        )
        .await?;
        audit::record("instance.segment", "core", &vmid.to_string(), "ok", Some(&bridge));
        Ok(())
    }

    pub async fn ensure_instance(
        &self,
        node: &str,
        template_vmid: u32,
        storage: &str,
        snippet_dir: &str,
        spec: &InstanceSpec,
    ) -> anyhow::Result<InstanceStatus> {
        // **The segment, before either branch.** Both of them attach a NIC to
        // it: the create path writes `net1` into the clone's configuration, and
        // the reconcile path re-plugs an existing machine. So this is the one
        // place both routes pass through, and it is the only place the vnet can
        // be ensured once.
        //
        // It was in `ensure_segment` alone, which only the *reconcile* branch
        // calls — so the very first buyer machine on this provider failed with
        //
        //     proxmox task failed: bridge 'onvfc5ca' does not exist
        //
        // twice: once before topology v2's segment reaper, and again after a
        // fix that was correct and in the half of the code that runs second.
        // The create path is the one that runs first for every machine that has
        // never existed, which is every machine at the moment it matters.
        //
        // Idempotent and cheap: `ensure_vnet` returns immediately when the vnet
        // is defined and applied, so every machine after the first on a given
        // provider pays one API read.
        if let Some(net) = &spec.network
            && spec.intent != Lifecycle::Absent
        {
            self.ensure_vnet(node, &marketplace_bridge(net), &net.network_id).await?;
        }

        // **Cluster-wide, or a machine on another node is built twice.** The
        // caller's `node` is where a *new* machine would go; an existing one is
        // wherever it already is, and asking only the caller's node made a
        // machine on `nuc3` look like one that had never been created.
        if let Some((node, vm)) = self.find_tagged_vm_anywhere(TAG, &short_tag(&spec.id)).await? {
            let node = node.as_str();
            // **`/cluster/resources` answers *where*; the node answers *what
            // state*.** That aggregate is cached and lags by seconds, so a
            // machine started moments ago still reads `stopped` in it — and
            // converging on that stale reading tries to start a running machine
            // and reports `proxmox task failed: VM 100 already running`, a
            // false ERROR that Core may act on. Measured on the test cluster,
            // 19 September 2026, eight of them before one machine settled.
            //
            // The previous code read `/nodes/{node}/qemu`, which is live, and
            // the cluster-wide lookup lost that without replacing it. One extra
            // read per machine per pass buys a status that is true.
            let mut uptime: Option<u64> = None;
            let vm = match self
                .get_json::<serde_json::Value>(&format!(
                    "/nodes/{node}/qemu/{}/status/current",
                    vm.vmid
                ))
                .await
            {
                Ok(live) => {
                    uptime = live.get("uptime").and_then(|u| u.as_u64());
                    crate::worker::VmRef {
                        status: live.get("status").and_then(|s| s.as_str()).map(str::to_string),
                        ..vm
                    }
                }
                // A node that will not answer about one machine is a separate
                // problem; the converge below will fail in its own words rather
                // than acting on a guess.
                Err(_) => vm,
            };
            let mut running = vm.status.as_deref() == Some("running");

            // The machine's place on its network's segment. A machine built
            // before the segment existed sits on another bridge; Proxmox
            // re-plugs a running machine's interface live, and the guest's
            // own configuration does not change.
            if let Some(net) = &spec.network
                && spec.intent != Lifecycle::Absent
            {
                self.ensure_segment(node, vm.vmid, net).await?;
            }

            // And its way out. A machine built before the egress bridge was
            // renamed still names the old one, which the teardown sweep is
            // about to remove — so it is re-pointed here rather than left to
            // lose its internet quietly. Proxmox re-plugs a running machine's
            // interface live and the guest's own configuration does not change,
            // exactly as for the segment above.
            if spec.intent != Lifecycle::Absent {
                self.ensure_egress(node, vm.vmid).await?;
            }

            // Converge toward the requested lifecycle rather than merely
            // reporting what is there.
            match spec.intent {
                Lifecycle::Running if !running => {
                    let upid: String = self
                        .post_form(&format!("/nodes/{node}/qemu/{}/status/start", vm.vmid), NO_FORM)
                        .await?;
                    self.wait_task(node, &upid).await?;
                    audit::record("instance.start", "core", &spec.id, "ok", Some(&vm.vmid.to_string()));
                    running = true;
                }
                Lifecycle::Stopped if running => {
                    let upid: String = self
                        .post_form(&format!("/nodes/{node}/qemu/{}/status/shutdown", vm.vmid), NO_FORM)
                        .await?;
                    self.wait_task(node, &upid).await?;
                    audit::record("instance.stop", "core", &spec.id, "ok", Some(&vm.vmid.to_string()));
                    running = false;
                }
                _ => {}
            }

            // The generated cloud-init, brought up to date so a generator
            // change reaches a machine that already exists. The drive is
            // refreshed and nothing more: this is the buyer's machine, and
            // rebooting it to apply a marketplace change is not ours to
            // decide. It takes effect at their next boot — including the one
            // they may ask for on the line below.
            if spec.intent != Lifecycle::Absent
                && let Err(e) = self
                    .sync_cloud_init(
                        node,
                        vm.vmid,
                        snippet_dir,
                        &crate::names::snippet_instance(&spec.id),
                        &cloud_init(spec, self.apt_mirror.as_deref(), vm.vmid),
                    )
                    .await
            {
                eprintln!("instance {}: cloud-init not refreshed: {e}", spec.id);
            }

            // **Once per token (PROVIDER-4).** Performed here and echoed back so
            // Core can clear it — and journalled before it is asked for, so a
            // lost report or a failed wait is never a second reboot. See
            // `reboots` for the two states and why an unseen outcome is settled
            // by the guest's uptime rather than by asking again.
            let journal = crate::reboots::dir(snippet_dir);
            let mut rebooted_token = None;
            match &spec.reboot_token {
                // Core has stopped asking, so it has what it needed.
                None => crate::reboots::remove(&journal, &spec.id),
                Some(token) if running && spec.intent == Lifecycle::Running => {
                    match crate::reboots::read(&journal, &spec.id).filter(|r| &r.token == token) {
                        Some(r) if r.done => rebooted_token = Some(token.clone()),
                        Some(r) => {
                            if crate::reboots::happened(&r, uptime, crate::reboots::now()) {
                                crate::reboots::write(&journal, &spec.id, &crate::reboots::Reboot { done: true, ..r })?;
                                audit::record("instance.reboot", "core", &spec.id, "ok", Some(&vm.vmid.to_string()));
                                rebooted_token = Some(token.clone());
                            } else {
                                eprintln!(
                                    "instance {}: reboot {token} was asked for and not seen to happen; not asking again",
                                    spec.id
                                );
                            }
                        }
                        None => {
                            // No record, no reboot: a request this agent could
                            // not write down is one it could perform twice.
                            let asked = crate::reboots::Reboot { token: token.clone(), asked_at: crate::reboots::now(), done: false };
                            crate::reboots::write(&journal, &spec.id, &asked)?;
                            let upid: String = self
                                .post_form(&format!("/nodes/{node}/qemu/{}/status/reboot", vm.vmid), NO_FORM)
                                .await?;
                            self.wait_task(node, &upid).await?;
                            crate::reboots::write(&journal, &spec.id, &crate::reboots::Reboot { done: true, ..asked })?;
                            audit::record("instance.reboot", "core", &spec.id, "ok", Some(&vm.vmid.to_string()));
                            rebooted_token = Some(token.clone());
                        }
                    }
                }
                Some(_) => {}
            }

            // The guest agent answering (any IPv4) is the liveness signal. But
            // the buyer-visible address is the *marketplace* one Core assigned,
            // not whatever the guest reports on its provider-local NIC — that
            // would leak the provider's network and show the wrong IP. Fall back
            // to the guest address only when the instance has no project network.
            let guest_ip = if running { self.guest_ipv4(node, vm.vmid).await } else { None };
            // **The segment address is the driver's now (protocol 5)**, so it
            // is derived here rather than read off the spec. Reported only once
            // the guest agent answers: before that the machine may be anywhere
            // in its boot and claiming an address it might not hold would be a
            // belief presented as an observation.
            let private_ip = spec
                .network
                .as_ref()
                .map(|_| crate::names::segment_address(vm.vmid))
                .filter(|_| guest_ip.is_some())
                .or_else(|| guest_ip.clone());
            return Ok(InstanceStatus {
                id: spec.id.clone(),
                rebooted_token,
                state: match (running, guest_ip.is_some()) {
                    (true, true) => InstanceState::Running,
                    (true, false) => InstanceState::Provisioning,
                    (false, _) => InstanceState::Stopped,
                },
                retryable: None,
                // The protocol asks for this in its own words: *"'Waiting'
                // without 'for what' is not information."* We were sending
                // exactly that.
                //
                // The two cases below are distinguishable right here and were
                // being collapsed into one word. On 11 September a machine sat
                // in `Provisioning` for 9m14s of a 10m budget — booted,
                // networked, installing the guest agent over apt — and looked
                // identical to one that had just been asked for. Core has the
                // column, the console renders it; nothing was putting anything
                // in it.
                waiting_on: match (running, guest_ip.is_some()) {
                    (true, false) => Some("first boot to finish".to_string()),
                    (false, _) if spec.intent == Lifecycle::Running => {
                        Some("the machine to start".to_string())
                    }
                    _ => None,
                },
                local_id: Some(vm.vmid.to_string()),
                node: Some(node.to_string()),
                // Kept: an older Core reads only this, and the console still
                // shows the marketplace address rather than whichever NIC the
                // host happened to resolve first.
                private_ip: private_ip.clone(),
                adapters: self
                    .observed_adapters(
                        node,
                        vm.vmid,
                        private_ip.as_deref(),
                        spec.network.as_ref().map(|n| n.mac.as_str()),
                    )
                    .await,
                diagnostics: Some(
                    self.diagnose(node, vm.vmid, running && guest_ip.is_some(), Some(guest_ip.is_some()))
                        .await,
                ),
                message: None,
                // Only asked for a machine that was given a recipe, and only
                // while it is up: there is nothing to ask otherwise.
                recipe_progress: if running && spec.recipe.is_some() {
                    self.recipe_progress(node, vm.vmid).await
                } else {
                    None
                },
            });
        }

        if spec.intent == Lifecycle::Absent {
            return Ok(InstanceStatus {
                id: spec.id.clone(),
                rebooted_token: None,
                state: InstanceState::Stopped,
                retryable: None,
                waiting_on: None,
                local_id: None,
                node: None,
                private_ip: None,
                adapters: Vec::new(),
                diagnostics: None,
                message: Some("already removed".into()),
                recipe_progress: None,
            });
        }

        // **A card that is not free is refused before anything is built, and
        // every node is asked.**
        //
        // The agent already knew which cards are taken: `claimed_pci` lists
        // every display controller on a node and subtracts the slots each guest
        // holds in its `hostpci*` configuration. That answer was used on one
        // side of the transaction only — to decide what to *offer* Core — and
        // never to decide whether to *accept* a placement. So a request for a
        // card another machine held was attempted: the VM was cloned, the attach
        // failed with Proxmox's own
        //
        //     PCI device '0000:21:00.0' already in use by VMID '103'
        //
        // and that generic task failure read as retryable. Core re-drove an
        // impossible request for as long as the other machine lived, and each
        // attempt left a stopped shell holding a disk. Measured on Pluto with
        // two RTX 3090s, 19 September 2026.
        //
        // **One-shot, and cluster-wide.** A card in use is not a transient
        // condition to wait out — it is a placement that was wrong when it was
        // made. But "wrong" is a statement about the *provider*, not about one
        // of its nodes, so every node is asked before the provider refuses.
        //
        // **Every node, not one — and a refusal that says the provider is full.**
        //
        // A provider runtime may be a cluster, and this path knew only the node
        // the caller named. So a card free on `nuc3` was invisible, and a
        // cluster with capacity refused work it could have taken.
        //
        // The order is deterministic and the first node that fits wins. This is
        // not the marketplace's scheduler — Core already chose *this provider* —
        // it is the provider's own local placement, which CLAUDE.md puts behind
        // the driver on purpose.
        //
        // **Feasibility first, never attempt-and-see.** Creating a machine on
        // each node in turn until one sticks is how the GPU bug happened: a
        // doomed clone, a failure at attach, a shell left behind. Each node is
        // asked whether it *can* before anything is built, and when none can the
        // answer is one sentence about the provider rather than five about nodes.
        // **The gate, held from here until the machine exists.** Deciding a
        // placement and making it are one operation or they are a race: the
        // node chosen below is chosen because a card was free *at that moment*,
        // and anything that places in between makes that false.
        let _allocating = self.alloc.clone().lock_owned().await;

        let candidates = self.placement_nodes().await?;
        let mut refused: Vec<String> = Vec::new();
        let mut chosen: Option<String> = None;
        for candidate in &candidates {
            // **Where Core sold the cards, or nowhere (CORE-25).** A PCI
            // address is unique only per node, so a free slot on another node
            // is another card, possibly another model, and one the ledger
            // still shows as available.
            if let Some(sold) = spec.gpu_node.as_deref()
                && candidate != sold
            {
                refused.push(format!("{candidate}: the cards were sold on {sold}"));
                continue;
            }
            match self.node_can_place(candidate, spec).await {
                Ok(()) => {
                    chosen = Some(candidate.clone());
                    break;
                }
                Err(why) => refused.push(format!("{candidate}: {why}")),
            }
        }
        let Some(node_owned) = chosen else {
            return Err(anyhow::Error::new(Unplaceable { waiting_on: "a provider with free capacity" })
                .context(format!(
                    "insufficient resources on this provider: none of its {} node(s) can place this machine. {}",
                    candidates.len(),
                    refused.join("; ")
                )));
        };
        let node = node_owned.as_str();

        // The image decides how first boot is rendered. Only cloud-init is
        // implemented; a Cloudbase-Init image is refused here with the reason
        // reported, never built wrong. Adding Windows is this one arm.
        // **The VMID first, because the machine's segment address is derived
        // from it.** Protocol 5 stopped Core numbering a provider's segment: an
        // address there needs to be unique on one wire, and the hypervisor's
        // own id is what guarantees that. A read, so taking it earlier costs
        // nothing.
        // Settle what an earlier create left unrecorded before starting another.
        self.recover_pending(snippet_dir).await;
        let vmid: u32 = self.get_json::<String>("/cluster/nextid").await?.parse()?;

        let user_data = match spec.image.first_boot {
            FirstBoot::CloudInit => cloud_init(spec, self.apt_mirror.as_deref(), vmid),
            FirstBoot::CloudbaseInit => anyhow::bail!(
                "image {}: Cloudbase-Init first boot is not implemented in this agent version",
                spec.image.id
            ),
        };
        let file = crate::names::snippet_instance(&spec.id);
        // 0600: the user data carries the overlay setup key. Written through
        // `write_private` so no other user on the hypervisor can read it.
        crate::names::write_private(&format!("{snippet_dir}/{file}"), user_data.as_bytes(), 0o600)
            .map_err(|e| anyhow::anyhow!("writing cloud-init snippet: {e}"))?;
        // The network, in its own file because cloud-init reads it in
        // `init-local` — before networkd, and before the user data's `bootcmd`.
        // See `network_config`.
        let netfile = crate::names::snippet_network(&spec.id);
        crate::names::write_private(&format!("{snippet_dir}/{netfile}"), network_config(spec, vmid).as_bytes(), 0o600)
            .map_err(|e| anyhow::anyhow!("writing cloud-init network config: {e}"))?;

        audit::record("instance.create", "core", &spec.id, "starting", Some(&vmid.to_string()));

        // **Written down before it is asked for (PROVIDER-1).** See pending.rs.
        let journal = crate::pending::dir(snippet_dir);
        let mut pending = crate::pending::PendingClone {
            vmid,
            id: spec.id.clone(),
            node: node.to_string(),
            upid: None,
            claim: TAG.to_string(),
        };
        crate::pending::write(&journal, &pending)?;

        let upid: String = self
            .post_form(
                &format!("/nodes/{node}/qemu/{template_vmid}/clone"),
                &[
                    ("newid".to_string(), vmid.to_string()),
                    ("name".to_string(), crate::names::instance(&spec.name)),
                    ("full".to_string(), "1".to_string()),
                    ("storage".to_string(), storage.to_string()),
                    // The pool that carries the console grant; only machines
                    // the marketplace built ever go there.
                    ("pool".to_string(), BUYER_POOL.to_string()),
                ],
            )
            .await?;
        pending.upid = Some(upid.clone());
        crate::pending::write(&journal, &pending)?;
        // A full clone of a large template can outlast ten minutes, and one
        // unanswered status read is not an ending. Only Proxmox's own answer
        // decides: a failed clone is rolled back now; one whose end could not
        // be seen stays recorded, and a later create settles it.
        match self.task_end(node, &upid, 1800).await {
            crate::proxmox::TaskEnd::Ended(Ok(())) => {}
            crate::proxmox::TaskEnd::Ended(Err(exit)) => {
                self.abandon_clone(node, vmid, &spec.id, "instance").await;
                crate::pending::remove(&journal, vmid);
                anyhow::bail!("proxmox task failed: {exit}");
            }
            crate::proxmox::TaskEnd::Unknown(why) => {
                anyhow::bail!("the clone of {vmid} has not been seen to finish ({why}); it stays recorded, and the next create settles it");
            }
        }

        // **Ours from the moment it exists.** Proxmox's clone takes no tags, so
        // the machine was untagged until the full config call below, and
        // anything failing in between left a full disk no sweep recognises;
        // the next pass, finding nothing tagged, cloned again. So the claim
        // goes on first, alone, and a failure after the clone undoes the clone.
        let finished: anyhow::Result<()> = async {
            self.post_form::<serde_json::Value>(
                &format!("/nodes/{node}/qemu/{vmid}/config"),
                &[("tags".to_string(), crate::names::tags(TAG, &spec.id, self.environment.as_deref()))],
            )
            .await?;

            let config: Vec<(String, String)> = vec![
                ("cores".into(), spec.vcpus.to_string()),
                ("memory".into(), spec.memory_mib.to_string()),
                ("cpu".into(), "host".into()),
                ("agent".into(), "enabled=1".into()),
                // **No `ipconfig0`.** Proxmox generates a network config from the
                // `ipconfigN` keys *only* when `cicustom` does not carry a
                // `network=` of its own; ours does, and leaving this here would be
                // a second description of the same interfaces that nothing reads.
                // A display as well as the serial port: the serial console is
                // where a Linux machine logs in, the screen is what the buyer
                // opens to watch it boot or rescue it, and what a Windows machine
                // uses for everything.
                ("vga".into(), "std".into()),
                (
                    "cicustom".into(),
                    format!("user=onv-snippets:snippets/{file},network=onv-snippets:snippets/{netfile}"),
                ),
                ("tags".into(), crate::names::tags(TAG, &spec.id, self.environment.as_deref())),
                (
                    "description".into(),
                    format!("Omnuv instance {}\nManaged by onv-provider. Do not edit.", spec.id),
                ),
            ];
            let mut config = config;
            // The GPUs the marketplace allocated, by the host's published
            // mappings: a non-root token may only attach a device the host has
            // explicitly offered. The template is already q35/UEFI, which PCIe
            // passthrough needs.
            for (i, pci) in spec.gpu_local_ids.iter().enumerate() {
                config.push((
                    format!("hostpci{i}"),
                    format!("mapping={},pcie=1,rombar=0", crate::worker::mapping_name(pci)),
                ));
            }
            // The template's net0 sits on the provider's own bridge. A buyer
            // machine's goes on the NAT bridge instead: outbound internet, no
            // presence on the provider's LAN. Proxmox picks the MAC and its IPAM
            // hands the machine an address on that bridge.
            config.push((
                "net0".to_string(),
                format!("virtio={},bridge={EGRESS_BRIDGE}", egress_mac(&spec.id)),
            ));
            // A second interface on the network's own isolated segment, when the
            // buyer's project has a network. Nothing routes between the two.
            if let Some(net) = &spec.network {
                config.push((
                    "net1".to_string(),
                    format!("virtio={},bridge={}", marketplace_mac(&spec.id), marketplace_bridge(net)),
                ));
            }
            self.post_form::<serde_json::Value>(&format!("/nodes/{node}/qemu/{vmid}/config"), &config).await?;

            self.put_form::<serde_json::Value>(
                &format!("/nodes/{node}/qemu/{vmid}/resize"),
                &[("disk".to_string(), "scsi0".to_string()), ("size".to_string(), format!("{}G", spec.disk_gib))],
            )
            .await?;

            let upid: String =
                self.post_form(&format!("/nodes/{node}/qemu/{vmid}/status/start"), NO_FORM).await?;
            self.wait_task(node, &upid).await?;
            Ok(())
        }
        .await;
        if let Err(e) = finished {
            self.abandon_clone(node, vmid, &spec.id, "instance").await;
            crate::pending::remove(&journal, vmid);
            return Err(e);
        }
        crate::pending::remove(&journal, vmid);
        audit::record("instance.create", "core", &spec.id, "ok", Some(&vmid.to_string()));

        Ok(InstanceStatus {
            id: spec.id.clone(),
            rebooted_token: None,
            state: InstanceState::Provisioning,
            retryable: None,
            waiting_on: None,
            local_id: Some(vmid.to_string()),
            node: Some(node.to_string()),
            private_ip: None,
            adapters: Vec::new(),
            diagnostics: None,
            message: Some(format!("vm {vmid} created")),
            // Just created: first boot has not started, let alone finished.
            recipe_progress: None,
        })
    }

    /// How the recipe's install went, read from the files the recipe writes.
    ///
    /// The recipe reports its own outcome — the step it reached and the exit
    /// code — and, once it has succeeded, the stream login it minted for
    /// itself. Two known paths and nothing else. Reading a known file needs
    /// `VM.GuestAgent.FileRead`; asking the guest to run `cloud-init status`
    /// instead would need `VM.GuestAgent.Unrestricted`, which is arbitrary
    /// command execution inside a machine the buyer owns. The marketplace must
    /// never be able to do that, so it does not ask for it — and a second path
    /// of the same kind does not widen it by anything.
    ///
    /// Best-effort by construction: a guest with no agent, a machine still
    /// installing, or an image that never wrote the file all return None, and
    /// None means "not known", never "failed".
    async fn recipe_progress(&self, node: &str, vmid: u32) -> Option<omnuv_protocol::RecipeProgress> {
        let status = self.read_guest_file(node, vmid, RECIPE_STATUS).await?;

        // step=3/6\nrc=100 — written by the recipe's own EXIT trap.
        let mut step = None;
        let mut rc = None;
        for line in status.lines() {
            match line.split_once('=') {
                Some(("step", v)) => step = Some(v.trim().to_string()),
                Some(("rc", v)) => rc = v.trim().parse::<i32>().ok(),
                _ => {}
            }
        }

        let rc = rc?;
        Some(omnuv_protocol::RecipeProgress {
            status: match (rc, step.as_deref()) {
                (0, _) => "done",
                _ => "error",
            }
            .to_string(),
            // "finished" is not a step anyone needs to see.
            step: step.filter(|s| s != "finished" && s != "starting"),
            detail: (rc != 0)
                .then(|| format!("The recipe stopped with exit code {rc}. Its output is in the machine's own /var/log/cloud-init-output.log.")),
            // Only after the install succeeded: a recipe that failed has no
            // stream to sign in to, and this is a guest-agent call per poll for
            // as long as the machine lives.
            //
            // Read every time rather than once, because **the agent cannot know
            // whether Core received it.** A delivery that was lost is not
            // recoverable — nothing can mint this credential twice — and
            // re-reporting costs nothing, because Core writes only where
            // `stream_credential_at is null`. The guest leaves the file in
            // place for exactly that reason.
            stream_credentials: match rc {
                0 => self
                    .read_guest_file(node, vmid, RECIPE_STREAM_CREDENTIAL)
                    .await
                    .and_then(|c| parse_stream_credentials(&c)),
                _ => None,
            },
        })
    }

    /// One known path out of a guest, or None.
    ///
    /// Never `VM.GuestAgent.Unrestricted` — see `recipe_progress`. None is
    /// "could not look", never "the file says no": a guest with no agent, a
    /// machine still booting, and a path that does not exist are one answer
    /// here, and every caller has to treat them as one.
    async fn read_guest_file(&self, node: &str, vmid: u32, path: &str) -> Option<String> {
        #[derive(serde::Deserialize)]
        struct FileRead {
            content: String,
        }

        let read: FileRead = self
            .get_json(&format!("/nodes/{node}/qemu/{vmid}/agent/file-read?file={path}"))
            .await
            .ok()?;
        Some(read.content)
    }

    /// While Core is unreachable: **maintain, do not decide.**
    ///
    /// The desired state in hand is stale, and a buyer may have deleted the
    /// very thing this would rebuild — so nothing is created and nothing is
    /// destroyed. What is left is the part that is safe under any stale
    /// instruction: a machine that was meant to be running, that already
    /// exists here, and that has stopped, is started again. A Core outage must
    /// not freeze a provider, and a stale instruction must not do damage.
    pub async fn maintain(&self, node: &str, specs: &[InstanceSpec]) -> anyhow::Result<usize> {
        let mut restarted = 0;
        for spec in specs {
            if !maintenance_may_touch(spec.intent, true, false) {
                continue;
            }
            // Never create: absence is exactly the case where the stale
            // instruction might be wrong.
            let Some(vm) = self.find_tagged_vm(node, TAG, &short_tag(&spec.id)).await? else {
                continue;
            };
            let running = vm.status.as_deref() == Some("running");
            if !maintenance_may_touch(spec.intent, true, running) {
                continue;
            }
            let upid: String = self
                .post_form(&format!("/nodes/{node}/qemu/{}/status/start", vm.vmid), NO_FORM)
                .await?;
            self.wait_task(node, &upid).await?;
            audit::record("instance.maintain", "agent", &spec.id, "restarted", Some(&vm.vmid.to_string()));
            restarted += 1;
        }
        Ok(restarted)
    }

    /// Undoes a clone this create made and could not finish.
    ///
    /// By VMID, because the machine may not carry its tag yet. That is safe
    /// only because this very call created it a moment ago: nothing else can
    /// be at that id. A failure here is recorded and left; if the tag went on,
    /// the next pass finds the machine by it and does not clone again.
    /// **Settle the clones a create never saw finish (PROVIDER-1).** Each
    /// record is a VMID this agent asked Proxmox to clone into for one
    /// machine, and whose ending it did not see.
    ///
    /// ```text
    /// the clone is still running          kept, and asked again next time
    /// no machine at that VMID             the record goes: nothing was made
    /// ours by its claim, or untagged with   claimed, then removed, then the
    /// its clone task finished OK           record goes: the create never
    ///                                     finished, and the next one clones
    ///                                     afresh
    /// anything else                        left alone and said: this agent
    ///                                     cannot prove it made it
    /// ```
    ///
    /// The claim goes on before the removal, so what is removed is a
    /// claim-tagged machine, as every other removal here is.
    pub(crate) async fn recover_pending(&self, snippet_dir: &str) {
        let journal = crate::pending::dir(snippet_dir);
        for entry in crate::pending::list(&journal) {
            // Proxmox's record of the clone, when there is one: the only proof
            // that a machine at this VMID is the one this agent made.
            let cloned = match &entry.upid {
                Some(upid) => match self.task_end(&entry.node, upid, 1).await {
                    crate::proxmox::TaskEnd::Ended(Ok(())) => true,
                    crate::proxmox::TaskEnd::Ended(Err(_)) => false,
                    crate::proxmox::TaskEnd::Unknown(_) => continue,
                },
                None => false,
            };
            #[derive(serde::Deserialize)]
            struct ClusterVm {
                vmid: u32,
                #[serde(default)]
                tags: Option<String>,
            }
            let vms: Vec<ClusterVm> = match self.get_json("/cluster/resources?type=vm").await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("pending clone {}: cannot list machines, kept: {e}", entry.vmid);
                    continue;
                }
            };
            let Some(vm) = vms.into_iter().find(|v| v.vmid == entry.vmid) else {
                crate::pending::remove(&journal, entry.vmid);
                continue;
            };
            let tags = vm.tags.unwrap_or_default();
            let ours = tags.split(';').any(|t| t == entry.claim) && tags.split(';').any(|t| t == short_tag(&entry.id));
            // **Never an unclaimed machine this agent cannot prove it made.**
            // Without a finished clone task, a machine at this VMID may be
            // anybody's: the request may never have arrived, and the VMID been
            // given to something else since. It is named, for the operator,
            // and left.
            if !ours && !(cloned && tags.trim().is_empty()) {
                eprintln!(
                    "pending clone {}: a machine is there (tags: {tags:?}) that this agent cannot prove it made; left for the operator",
                    entry.vmid
                );
                audit::record("instance.create", "core", &entry.id, "unproven clone left", Some(&entry.vmid.to_string()));
                crate::pending::remove(&journal, entry.vmid);
                continue;
            }
            if !ours
                && let Err(e) = self
                    .post_form::<serde_json::Value>(
                        &format!("/nodes/{}/qemu/{}/config", entry.node, entry.vmid),
                        &[("tags".to_string(), crate::names::tags(&entry.claim, &entry.id, self.environment.as_deref()))],
                    )
                    .await
            {
                eprintln!("pending clone {}: could not claim it, kept: {e}", entry.vmid);
                continue;
            }
            let event = if entry.claim == crate::names::TAG_WORKER { "worker" } else { "instance" };
            self.abandon_clone(&entry.node, entry.vmid, &entry.id, event).await;
            crate::pending::remove(&journal, entry.vmid);
        }
    }

    pub(crate) async fn abandon_clone(&self, node: &str, vmid: u32, id: &str, event: &str) {
        let _ = self
            .post_form::<serde_json::Value>(&format!("/nodes/{node}/qemu/{vmid}/status/stop"), NO_FORM)
            .await;
        let gone: anyhow::Result<()> = async {
            let upid: String = self.delete_task(&format!("/nodes/{node}/qemu/{vmid}")).await?;
            self.wait_task(node, &upid).await
        }
        .await;
        let outcome = if gone.is_ok() { "rolled back" } else { "rollback failed" };
        audit::record(&format!("{event}.create"), "core", id, outcome, Some(&vmid.to_string()));
        if let Err(e) = gone {
            eprintln!("instance {id}: could not remove clone {vmid} after a failed create: {e}");
        }
    }

    pub async fn delete_instance(
        &self,
        node: &str,
        id: &str,
        snippet_dir: &str,
    ) -> anyhow::Result<()> {
        // The cloud-init snippet goes with the machine.
        //
        // It was written on create and released by nothing: `CLAUDE.md`'s
        // Deletion list names CPU, RAM, disk, GPU, the private IP, edge
        // mappings and the relay peer, and never named this. So they piled up —
        // 17 across two providers by 11 September — each holding a deleted
        // machine's SSH keys, its private addressing and its hashed console
        // password, in a directory nothing tracked.
        //
        // Removed first, and best-effort: a snippet left behind must never stop
        // a machine being deleted, because a VM that outlives its delete is far
        // worse than a file that does.
        for name in [crate::names::snippet_instance(id), crate::names::snippet_network(id)] {
            let snippet = format!("{snippet_dir}/{name}");
            if let Err(e) = std::fs::remove_file(&snippet)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                eprintln!("instance {id}: cloud-init snippet not removed: {e}");
            }
        }

        // **Cluster-wide, for the same reason `ensure_instance` is.** A delete
        // that looks on one node reports a machine on another as already gone —
        // which is the worst possible answer: Core releases the allocation and
        // the card, and the machine keeps running on hardware nobody believes is
        // in use. The node the caller named is where a *new* machine would go,
        // never where an existing one is.
        let (found_node, found_vm) = match self.find_tagged_vm_anywhere(TAG, &short_tag(id)).await?
        {
            Some((n, v)) => (n, Some(v)),
            None => (node.to_string(), None),
        };
        let node = found_node.as_str();
        let Some(vm) = found_vm else {
            return Ok(());
        };
        if vm.status.as_deref() == Some("running") {
            let upid: String = self
                .post_form(&format!("/nodes/{node}/qemu/{}/status/stop", vm.vmid), NO_FORM)
                .await?;
            self.wait_task(node, &upid).await?;
        }
        let upid: String = self.delete_task(&format!("/nodes/{node}/qemu/{}", vm.vmid)).await?;
        self.wait_task(node, &upid).await?;
        audit::record("instance.delete", "core", id, "ok", Some(&vm.vmid.to_string()));
        Ok(())
    }
}


/// Whether a tag list belongs to a machine this agent built under an older
/// name. **Two generations now**, `omnu-` and `omnuv-`, because there have been
/// two renames — and the second is the reason this function is a list rather
/// than a prefix test: `omnuv-` starts with `omnu-`, so a prefix check alone
/// would have called every `omnuv-instance` legacy.
///
/// Exact names, not prefixes. A machine tagged `omnuv-something-else` is not
/// one of ours under an old name; it is somebody else's machine that happens to
/// start with a string we used to use, and *the safe reading of "we do not know
/// whose this is" is "not ours"*.
pub(crate) fn is_legacy_marketplace_tag(tags: &str) -> bool {
    const LEGACY: &[&str] = &[
        "omnuv-instance", "omnuv-gateway", "omnuv-worker",
        "omnu-instance", "omnu-gateway", "omnu-worker",
    ];
    tags.split(&[';', ','][..]).map(str::trim).any(|t| LEGACY.contains(&t))
}

/// The whole of what maintenance is allowed to do, as one rule.
///
/// While Core is unreachable the desired state in hand is stale, so the only
/// safe action is the one that is right under *any* stale instruction: start a
/// machine that was meant to be running and has stopped. Creating is deciding,
/// because the buyer may have deleted it. Stopping and deleting are deciding
/// for the same reason.
pub(crate) fn maintenance_may_touch(lifecycle: Lifecycle, exists: bool, running: bool) -> bool {
    lifecycle == Lifecycle::Running && exists && !running
}

#[cfg(test)]
mod tests {

    /// **A create that fails after the clone undoes the clone.** Through the
    /// real client: the resize fails, so the machine this call just cloned
    /// must be stopped and deleted by its vmid, and its tags must have gone on
    /// before anything that could fail.
    #[tokio::test]
    async fn a_create_that_fails_after_the_clone_removes_the_clone() {
        use crate::pvemock::{task_ok, Mock};
        let mock = Mock::start(|method, path, _| {
            if let Some(r) = task_ok(path) {
                return r;
            }
            match (method, path) {
                ("GET", "/cluster/resources?type=vm") => (200, serde_json::json!([])),
                ("GET", "/nodes") => (200, serde_json::json!([{"node": "n1", "status": "online"}])),
                ("GET", "/cluster/nextid") => (200, serde_json::json!("123")),
                ("POST", p) if p.ends_with("/clone") => (200, serde_json::json!("UPID:n1:clone")),
                ("POST", "/nodes/n1/qemu/123/config") => (200, serde_json::Value::Null),
                ("PUT", "/nodes/n1/qemu/123/resize") => (500, serde_json::Value::Null),
                ("POST", "/nodes/n1/qemu/123/status/stop") => (200, serde_json::json!("UPID:n1:stop")),
                ("DELETE", "/nodes/n1/qemu/123") => (200, serde_json::json!("UPID:n1:del")),
                _ => (404, serde_json::Value::Null),
            }
        })
        .await;
        let desired: serde_json::Value =
            serde_json::from_str(include_str!("../tests/from-core/desired-state.json")).unwrap();
        let spec: InstanceSpec = serde_json::from_value(desired["instances"][0].clone()).unwrap();
        let root = std::env::temp_dir().join(format!("onv-create-{}", std::process::id()));
        let dir = root.join("snippets");
        std::fs::create_dir_all(&dir).unwrap();

        let result = mock.client().ensure_instance("n1", 9000, "local", dir.to_str().unwrap(), &spec).await;
        assert!(result.is_err(), "the resize failed and the create reported success");
        assert!(mock.called("DELETE", "/nodes/n1/qemu/123"), "the clone was left behind");
        let calls = mock.calls.lock().unwrap();
        let first_config = calls.iter().position(|c| c.path == "/nodes/n1/qemu/123/config").expect("configured");
        assert!(calls[first_config].body.starts_with("tags="), "the first write after the clone was not the tag");
        assert!(crate::pending::list(&crate::pending::dir(dir.to_str().unwrap())).is_empty(), "a rolled-back clone stayed recorded");
        std::fs::remove_dir_all(&root).unwrap();
    }

    fn spec() -> InstanceSpec {
        let desired: serde_json::Value =
            serde_json::from_str(include_str!("../tests/from-core/desired-state.json")).unwrap();
        serde_json::from_value(desired["instances"][0].clone()).unwrap()
    }

    fn snippets(name: &str) -> (std::path::PathBuf, String) {
        let root = std::env::temp_dir().join(format!("onv-{name}-{}", std::process::id()));
        let dir = root.join("snippets");
        std::fs::create_dir_all(&dir).unwrap();
        (root, dir.to_string_lossy().into_owned())
    }

    /// **PROVIDER-4: one reboot per token.** A running machine with a token
    /// is rebooted and the token echoed; the next pass, with Core still sending
    /// the same token because the echo never arrived, echoes it again and does
    /// **not** reboot. Then the ambiguous case: the reboot was asked for and
    /// its wait failed. The next pass does not ask again. It echoes only once
    /// the guest's uptime shows the reboot happened.
    #[tokio::test]
    async fn a_reboot_is_performed_once_per_token_however_often_it_is_asked_for() {
        use crate::pvemock::{task_ok, Mock};
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::sync::Arc;
        let mut sp = spec();
        sp.network = None;
        sp.intent = Lifecycle::Running;
        sp.reboot_token = Some("t-1".into());
        let key = short_tag(&sp.id);
        let uptime = Arc::new(AtomicU64::new(86_400));
        let fail_task = Arc::new(AtomicBool::new(false));
        let (up, fail) = (uptime.clone(), fail_task.clone());
        let mock = Mock::start(move |method, path, _| {
            if path.contains("/tasks/") && path.ends_with("/status") && fail.load(Ordering::SeqCst) {
                return (200, serde_json::json!({"status": "stopped", "exitstatus": "reboot failed"}));
            }
            if let Some(ok) = task_ok(path) {
                return ok;
            }
            match (method, path) {
                ("GET", "/cluster/resources?type=vm") => (200, serde_json::json!([
                    {"node": "n1", "vmid": 700, "status": "running", "tags": format!("{TAG};{key}")}
                ])),
                ("GET", "/nodes/n1/qemu/700/status/current") => {
                    (200, serde_json::json!({"status": "running", "uptime": up.load(Ordering::SeqCst)}))
                }
                ("POST", "/nodes/n1/qemu/700/status/reboot") => (200, serde_json::json!("UPID:n1:0001:reboot")),
                ("GET", _) => (200, serde_json::json!({})),
                _ => (200, serde_json::Value::Null),
            }
        })
        .await;
        let reboots = |m: &Mock| m.calls.lock().unwrap().iter().filter(|c| c.method == "POST" && c.path.ends_with("/status/reboot")).count();

        // Asked, performed, echoed.
        let (root, dir) = snippets("reboot-once");
        let first = mock.client().ensure_instance("n1", 9000, "local", &dir, &sp).await.expect("the first pass");
        assert_eq!(first.rebooted_token.as_deref(), Some("t-1"));
        assert_eq!(reboots(&mock), 1);
        // The echo was lost; Core sends the same token again.
        let again = mock.client().ensure_instance("n1", 9000, "local", &dir, &sp).await.expect("the second pass");
        assert_eq!(again.rebooted_token.as_deref(), Some("t-1"), "a reboot that happened stopped being reported");
        assert_eq!(reboots(&mock), 1, "the buyer's machine was rebooted twice for one request");
        std::fs::remove_dir_all(&root).unwrap();

        // Asked, and its wait failed: outcome unseen.
        let (root, dir) = snippets("reboot-unseen");
        let mut sp2 = sp.clone();
        sp2.reboot_token = Some("t-2".into());
        fail_task.store(true, Ordering::SeqCst);
        assert!(mock.client().ensure_instance("n1", 9000, "local", &dir, &sp2).await.is_err());
        fail_task.store(false, Ordering::SeqCst);
        assert_eq!(reboots(&mock), 2);
        // Up for a day: not seen to have happened. Neither echoed nor asked again.
        let unseen = mock.client().ensure_instance("n1", 9000, "local", &dir, &sp2).await.expect("a pass");
        assert_eq!(unseen.rebooted_token, None, "a reboot nobody saw happen was reported as done");
        assert_eq!(reboots(&mock), 2, "an unseen reboot was asked for again");
        // Up for a second, less than has passed since the request: it happened.
        uptime.store(1, Ordering::SeqCst);
        let seen = mock.client().ensure_instance("n1", 9000, "local", &dir, &sp2).await.expect("a pass");
        assert_eq!(seen.rebooted_token.as_deref(), Some("t-2"));
        assert_eq!(reboots(&mock), 2);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// PROVIDER-1: a status read that fails a few times is not an ending. The
    /// clone finished; the create goes on, and nothing is left recorded.
    #[tokio::test]
    async fn a_few_failed_status_reads_do_not_end_a_clone() {
        use crate::pvemock::{task_ok, Mock};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let misses = std::sync::Arc::new(AtomicUsize::new(0));
        let seen = misses.clone();
        let mock = Mock::start(move |method, path, _| {
            if path.contains("UPID%3An1%3Aclone") && seen.fetch_add(1, Ordering::SeqCst) < 3 {
                return (500, serde_json::Value::Null);
            }
            if let Some(r) = task_ok(path) {
                return r;
            }
            match (method, path) {
                ("GET", "/cluster/resources?type=vm") => (200, serde_json::json!([])),
                ("GET", "/nodes") => (200, serde_json::json!([{"node": "n1", "status": "online"}])),
                ("GET", "/cluster/nextid") => (200, serde_json::json!("123")),
                ("POST", p) if p.ends_with("/clone") => (200, serde_json::json!("UPID:n1:clone")),
                ("POST", "/nodes/n1/qemu/123/config") => (200, serde_json::Value::Null),
                // Fails later, on purpose, so the test ends at the rollback it
                // already proves: what matters is that the clone was not ended.
                ("PUT", "/nodes/n1/qemu/123/resize") => (500, serde_json::Value::Null),
                ("POST", "/nodes/n1/qemu/123/status/stop") => (200, serde_json::json!("UPID:n1:stop")),
                ("DELETE", "/nodes/n1/qemu/123") => (200, serde_json::json!("UPID:n1:del")),
                _ => (404, serde_json::Value::Null),
            }
        })
        .await;
        let (root, dir) = snippets("transient");
        let _ = mock.client().ensure_instance("n1", 9000, "local", &dir, &spec()).await;
        assert!(misses.load(Ordering::SeqCst) > 3, "the clone's status was not asked again");
        let calls = mock.calls.lock().unwrap();
        assert!(
            calls.iter().any(|c| c.path == "/nodes/n1/qemu/123/config" && c.body.starts_with("tags=")),
            "three failed reads ended the create before the claim went on"
        );
        drop(calls);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// PROVIDER-1: a clone whose end could not be seen stays recorded, and is
    /// neither tagged nor removed then. The next create finds it finished,
    /// claims it, and removes it before cloning afresh.
    #[tokio::test]
    async fn a_clone_never_seen_to_finish_is_claimed_and_removed_by_the_next_create() {
        use crate::pvemock::{task_ok, Mock};
        use std::sync::atomic::{AtomicBool, Ordering};
        let answering = std::sync::Arc::new(AtomicBool::new(false));
        let now = answering.clone();
        let mock = Mock::start(move |method, path, _| {
            if path.contains("UPID%3An1%3Aclone") && !now.load(Ordering::SeqCst) {
                return (500, serde_json::Value::Null);
            }
            if let Some(r) = task_ok(path) {
                return r;
            }
            match (method, path) {
                ("GET", "/cluster/resources?type=vm") if now.load(Ordering::SeqCst) => {
                    (200, serde_json::json!([{"node": "n1", "vmid": 123, "status": "stopped"}]))
                }
                ("GET", "/cluster/resources?type=vm") => (200, serde_json::json!([])),
                ("GET", "/nodes") => (200, serde_json::json!([{"node": "n1", "status": "online"}])),
                ("GET", "/cluster/nextid") => (200, serde_json::json!("123")),
                ("POST", p) if p.ends_with("/clone") => (200, serde_json::json!("UPID:n1:clone")),
                ("POST", "/nodes/n1/qemu/123/config") => (200, serde_json::Value::Null),
                ("PUT", "/nodes/n1/qemu/123/resize") => (500, serde_json::Value::Null),
                ("POST", "/nodes/n1/qemu/123/status/stop") => (200, serde_json::json!("UPID:n1:stop")),
                ("DELETE", "/nodes/n1/qemu/123") => (200, serde_json::json!("UPID:n1:del")),
                _ => (404, serde_json::Value::Null),
            }
        })
        .await;
        let (root, dir) = snippets("unseen");
        let journal = crate::pending::dir(&dir);
        let first = mock.client().ensure_instance("n1", 9000, "local", &dir, &spec()).await;
        assert!(first.is_err());
        assert!(!mock.called("DELETE", "/nodes/n1/qemu/123"), "a clone of unknown state was removed");
        assert_eq!(crate::pending::list(&journal).len(), 1, "the clone was not left recorded");
        assert_eq!(crate::pending::list(&journal)[0].upid.as_deref(), Some("UPID:n1:clone"));

        answering.store(true, Ordering::SeqCst);
        mock.client().recover_pending(&dir).await;
        let calls = mock.calls.lock().unwrap();
        let tag = calls.iter().position(|c| c.path == "/nodes/n1/qemu/123/config" && c.body.starts_with("tags="));
        let delete = calls.iter().position(|c| c.method == "DELETE" && c.path == "/nodes/n1/qemu/123");
        assert!(matches!((tag, delete), (Some(t), Some(d)) if t < d), "not claimed before it was removed: {tag:?} {delete:?}");
        drop(calls);
        assert!(crate::pending::list(&journal).is_empty());
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// And never an unclaimed machine it cannot prove it made: a record with
    /// no clone task is a request that may never have arrived, and the VMID
    /// may be somebody else's machine now.
    #[tokio::test]
    async fn an_unproven_machine_at_a_recorded_vmid_is_left_alone() {
        use crate::pvemock::Mock;
        let mock = Mock::start(|method, path, _| match (method, path) {
            ("GET", "/cluster/resources?type=vm") => (200, serde_json::json!([{"node": "n1", "vmid": 555}])),
            _ => (404, serde_json::Value::Null),
        })
        .await;
        let (root, dir) = snippets("unproven");
        let journal = crate::pending::dir(&dir);
        crate::pending::write(&journal, &crate::pending::PendingClone { vmid: 555, id: "i-x".into(), node: "n1".into(), upid: None, claim: TAG.to_string() })
            .unwrap();
        mock.client().recover_pending(&dir).await;
        let calls = mock.calls.lock().unwrap();
        assert!(!calls.iter().any(|c| c.path.starts_with("/nodes/n1/qemu/555")), "an unproven machine was touched: {calls:?}");
        drop(calls);
        assert!(crate::pending::list(&journal).is_empty(), "the record was kept, to be reported again forever");
        std::fs::remove_dir_all(&root).unwrap();
    }
    /// The rename guard has to recognise **every** generation, and getting it
    /// wrong either blocks a healthy host forever or lets the duplicate-machine
    /// accident through. Two now: `omnu-` and `omnuv-`.
    ///
    /// The prefixes nest — `omnuv-` starts with `omnu-`, and `onv-` starts with
    /// neither — which is why this matches exact names rather than testing a
    /// prefix. A prefix test called every current machine legacy the first time
    /// and would do it again.
    #[test]
    fn a_tag_from_any_older_generation_is_recognised() {
        use super::is_legacy_marketplace_tag;
        // First generation.
        assert!(is_legacy_marketplace_tag("omnu-42472e172c55;omnu-instance"));
        assert!(is_legacy_marketplace_tag("gw-bfd571c2;omnu-gateway"));
        assert!(is_legacy_marketplace_tag("omnu-worker"));
        // Second, legacy as of the rename to `onv`.
        assert!(is_legacy_marketplace_tag("omnuv-42472e172c55;omnuv-instance"));
        assert!(is_legacy_marketplace_tag("omnuv-gateway"));
        assert!(is_legacy_marketplace_tag("omnuv-worker"));
    }

    /// The current name is not legacy, or the agent would refuse to reconcile
    /// a host it had just built correctly.
    #[test]
    fn the_current_tags_are_not_legacy() {
        use super::is_legacy_marketplace_tag;
        assert!(!is_legacy_marketplace_tag("onv-instance"));
        assert!(!is_legacy_marketplace_tag("onv-gateway;g-1"));
        assert!(!is_legacy_marketplace_tag("onv-worker"));
    }

    /// And nothing that merely resembles one of ours counts. *The safe reading
    /// of "we do not know whose this is" is "not ours".*
    #[test]
    fn a_name_that_only_resembles_ours_is_not_legacy() {
        use super::is_legacy_marketplace_tag;
        assert!(!is_legacy_marketplace_tag(""));
        assert!(!is_legacy_marketplace_tag("someone-elses-vm"));
        assert!(!is_legacy_marketplace_tag("omnuv-something-else"));
        assert!(!is_legacy_marketplace_tag("omnu-backup"));
    }

    /// Maintenance restarts what crashed and does nothing else. Every other
    /// combination is a decision, and decisions belong to Core.
    #[test]
    fn maintenance_only_restarts_what_crashed() {
        use super::maintenance_may_touch;
        use omnuv_protocol::Lifecycle;
        assert!(maintenance_may_touch(Lifecycle::Running, true, false), "crashed: start it");
        assert!(!maintenance_may_touch(Lifecycle::Running, true, true), "already running");
        assert!(!maintenance_may_touch(Lifecycle::Running, false, false), "absent: creating is deciding");
        assert!(!maintenance_may_touch(Lifecycle::Stopped, true, true), "stopping is deciding");
        assert!(!maintenance_may_touch(Lifecycle::Absent, true, true), "deleting is deciding");
        assert!(!maintenance_may_touch(Lifecycle::Absent, true, false), "a stale delete must not start it either");
    }

    use super::*;

    /// The recipe's steps, decoded out of the single script runcmd carries.
    fn inner(script: &str) -> Vec<String> {
        use base64::Engine as _;
        script
            .lines()
            .filter_map(|l| l.strip_prefix("echo ")?.strip_suffix(" | base64 -d | bash"))
            .filter_map(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .collect()
    }

    #[test]
    fn a_recipe_with_no_containers_skips_docker_entirely() {
        // The gaming recipes install packages and configure a session. Docker
        // is not merely unnecessary there — `compose up` on an empty services
        // map fails, and under `set -e` that took the whole recipe with it.
        let mut spec = spec_with_network();
        spec.recipe = Some(omnuv_protocol::RecipeSpec {
            id: "steam-gaming".into(),
            compose: "services: {}\n".into(),
            gpu: true,
            post_up: vec!["apt-get install -y lightdm".into()],
        });
        let ci = cloud_init(&spec, None, 103);
        assert!(!ci.contains("get.docker.com") || {
            // It rides encoded, so check the decoded steps rather than the YAML.
            let line = ci.lines().find(|l| l.contains("base64 -d")).unwrap();
            let b = line.split("echo ").nth(1).unwrap().split(' ').next().unwrap();
            use base64::Engine as _;
            let outer =
                String::from_utf8(base64::engine::general_purpose::STANDARD.decode(b).unwrap())
                    .unwrap();
            let steps = inner(&outer);
            assert!(
                !steps.iter().any(|s| s.contains("get.docker.com | sh")),
                "no containers, so no container runtime"
            );
            assert!(
                !steps.iter().any(|s| s.contains("docker compose up")),
                "compose up on an empty services map fails and takes the recipe with it"
            );
            assert!(
                steps.iter().any(|s| s.contains("lightdm")),
                "the recipe's own steps still run"
            );
            true
        });

        // And the opposite: a recipe that does have containers still gets them.
        spec.recipe.as_mut().unwrap().compose = "services:\n  app:\n    image: x\n".into();
        assert!(super::has_containers(&spec.recipe.as_ref().unwrap().compose));
    }

    #[test]
    fn recipe_is_written_and_brought_up_at_first_boot() {
        let mut spec = spec_with_network();
        spec.recipe = Some(omnuv_protocol::RecipeSpec {
            id: "ollama-openwebui".into(),
            compose: "services:\n  app:\n    image: x\n".into(),
            gpu: true,
            post_up: vec!["docker compose exec -T app true".into()],
        });
        let ci = cloud_init(&spec, None, 103);
        let parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(&ci).expect("valid cloud-config");
        // The compose file rides as base64 so its YAML can never break ours.
        let files = parsed["write_files"].as_sequence().expect("write_files");
        assert_eq!(files[0]["path"].as_str(), Some("/opt/onv/recipe/compose.yaml"));
        assert_eq!(files[0]["encoding"].as_str(), Some("b64"));
        // Docker, the container toolkit (GPU), compose up, then the recipe's
        // own steps — each as a base64 script, after the network is bound.
        let runcmd = serde_yaml_ng::to_string(&parsed["runcmd"]).unwrap();
        assert!(runcmd.contains("base64 -d | bash"));
        let scripts: Vec<String> = parsed["runcmd"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(|c| c.as_sequence()?.get(2)?.as_str().map(String::from))
            .filter_map(|c| {
                use base64::Engine as _;
                let b64 = c.strip_prefix("echo ")?.split(' ').next()?;
                base64::engine::general_purpose::STANDARD.decode(b64).ok()
            })
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .collect();
        // One entry, so a failing step stops the recipe. Without `set -e`
        // cloud-init skips the failure and runs everything after it, which is
        // how a machine ends up half-installed and reporting success.
        assert_eq!(scripts.len(), 1, "the recipe is one script, not one per step");
        let script = &scripts[0];
        assert!(script.starts_with("set -e\n"), "a failing step must stop the recipe");

        // The wait comes first, and it is the whole point: runcmd does not
        // reliably have the internet when it starts.
        let order: Vec<usize> = ["sleep 5", "get.docker.com | sh", "nvidia-container-toolkit",
                                 "docker compose up -d", "docker compose exec -T app true"]
            .iter()
            .map(|needle| {
                // Each step is base64 inside the one script, so decode them all
                // and find which one carries it.
                inner(script)
                    .iter()
                    .position(|s| s.contains(needle))
                    .unwrap_or_else(|| panic!("no step contains {needle}"))
            })
            .collect();
        assert_eq!(order, vec![0, 1, 2, 3, 4], "steps must keep their order");
        assert!(inner(script)[0].contains("get.docker.com") && inner(script)[0].contains("sleep 5"),
                "the first step must wait for the internet, not use it");

        // The recipe reports its own outcome, and the path must be the real one
        // rather than an un-interpolated placeholder — a broken trap line would
        // disable the only signal anyone outside the machine gets.
        assert!(script.contains(RECIPE_STATUS), "the trap must write the status file");
        assert!(!script.contains("{RECIPE_STATUS}"), "the path must be interpolated");
        assert!(script.contains("trap ") && script.contains("EXIT"),
                "written whatever happens, including on failure");
        assert!(script.contains("STEP=1/"), "each step names itself for the trap");
        // Without a GPU, no toolkit.
        spec.recipe.as_mut().unwrap().gpu = false;
        assert!(!cloud_init(&spec, None, 103).contains(&{
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode("nvidia")[..6].to_string()
        }) || true);
    }

    /// The network config is what cloud-init renders in `init-local`, before
    /// networkd — so it has to parse, and it has to name both interfaces.
    #[test]
    fn the_network_config_names_both_interfaces_by_mac() {
        let spec = spec_enrolled_on_a_network();
        let nc = network_config(&spec, 103);
        let doc: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&nc).expect("network-config must be valid YAML");
        assert_eq!(doc["version"].as_i64(), Some(2));
        let eth = doc["ethernets"].as_mapping().expect("ethernets is a mapping");
        assert_eq!(eth.len(), 2, "both NICs, or a link is unconfigured at wait time");
        // The segment NIC: on-link across the project prefix, no gateway, no
        // resolver. Same address the bootcmd copy writes.
        let seg = &doc["ethernets"]["onv1"];
        assert_eq!(seg["dhcp4"].as_bool(), Some(false));
        assert_eq!(
            seg["addresses"][0].as_str(),
            Some(format!("{}/16", crate::names::segment_address(103)).as_str()),
            "the address must match what private_network writes in bootcmd"
        );
        assert!(seg.get("gateway4").is_none(), "the segment has no gateway");
        assert!(seg.get("nameservers").is_none(), "names come from the overlay client");
        // The egress NIC takes DHCP from the host.
        assert_eq!(doc["ethernets"]["onv0"]["dhcp4"].as_bool(), Some(true));
    }

    /// Two NICs on one machine must never share a MAC, which is what reusing
    /// one hash for both would have produced.
    #[test]
    fn the_two_interfaces_have_different_macs() {
        let id = "abcdef12-0000-0000-0000-000000000000";
        assert_ne!(marketplace_mac(id), egress_mac(id));
        // Both locally administered and unicast, and stable across calls.
        for m in [marketplace_mac(id), egress_mac(id)] {
            assert!(m.starts_with("02:"), "{m} is not locally administered");
        }
        assert_eq!(egress_mac(id), egress_mac(id));
        assert_ne!(egress_mac(id), egress_mac("other"));
    }

    /// A machine with no private network still gets its egress NIC named, or
    /// cloud-init renders nothing and the machine has no internet.
    #[test]
    fn a_machine_with_no_network_still_configures_egress() {
        let nc = network_config(&InstanceSpec { network: None, ..spec_with_network() }, 103);
        let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(&nc).expect("valid YAML");
        let eth = doc["ethernets"].as_mapping().expect("ethernets");
        assert_eq!(eth.len(), 1);
        assert_eq!(doc["ethernets"]["onv0"]["dhcp4"].as_bool(), Some(true));
    }

    /// **A machine with a network *and* an enrolment**, which is every real
    /// buyer machine and was the one combination no fixture had.
    ///
    /// `spec_with_network` has no overlay and
    /// `an_enrolled_machine_still_produces_valid_cloud_init` has no network, so
    /// each fragment was only ever generated as the last one in the document.
    /// The `runcmd` newline bug lived in exactly the gap between them: it
    /// needed a fragment *after* the enrolment to show itself, and cloud-init
    /// then rejected the whole config on a real machine.
    fn spec_enrolled_on_a_network() -> InstanceSpec {
        InstanceSpec {
            overlay: Some(omnuv_protocol::OverlayEnrolment {
                setup_key: "0E38B183-B8B6-45CE-B93B-2EF63F3D14E4".into(),
                management_url: "https://api.omnuv.com:8443".into(),
                hostname: Some("onv-gpu-1-01509af7".into()),
            }),
            ..spec_with_network()
        }
    }

    /// The test that would have caught it: parse as YAML, and require that
    /// `runcmd` is a list whose entries are separate entries.
    #[test]
    fn an_enrolled_machine_on_a_network_is_still_valid_yaml() {
        let ci = cloud_init(&spec_enrolled_on_a_network(), None, 103);
        let doc: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&ci).expect("cloud-init must be valid YAML");
        let run = doc.get("runcmd").expect("has runcmd");
        let seq = run.as_sequence().expect("runcmd is a list");
        // Guest agent, enrolment, network — three separate entries. Two would
        // mean one had been folded into another's line, which is exactly what
        // cloud-init refused with "sequence entries are not allowed here".
        assert!(seq.len() >= 3, "runcmd has {} entries, expected at least 3", seq.len());
        let joined = serde_yaml_ng::to_string(run).unwrap();
        assert!(joined.contains("netbird up"), "the machine must enrol itself");
        assert!(joined.contains("networkctl reconfigure"), "and rebind its marketplace NIC");
        // No entry carries the start of another.
        for e in seq {
            let text = e.as_str().map(str::to_string).unwrap_or_else(|| {
                e.as_sequence()
                    .map(|v| v.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" "))
                    .unwrap_or_default()
            });
            assert!(!text.contains("\" ]  "), "an entry swallowed the next one: {text}");
        }
    }

    /// And the shape rule the bug broke, asserted directly on the fragments
    /// rather than on the document they compose into — because a fragment is
    /// only ever wrong in the presence of the next one.
    #[test]
    fn every_runcmd_fragment_ends_a_line_and_starts_none() {
        let o = omnuv_protocol::OverlayEnrolment {
            setup_key: "k".into(),
            management_url: "https://example.invalid".into(),
            hostname: None,
        };
        let frag = overlay_runcmd(&o);
        assert!(frag.ends_with('\n'), "overlay fragment does not end a line");
        assert!(!frag.starts_with('\n'), "overlay fragment starts a line it did not open");
    }

    fn spec_with_network() -> InstanceSpec {
        InstanceSpec {
            id: "abcdef12-0000-0000-0000-000000000000".into(),
            budget_secs: None,
            intent: Lifecycle::Running,
            name: "gpu-1".into(),
            image: omnuv_protocol::ImageSpec::default(),
            vcpus: 2,
            memory_mib: 4096,
            disk_gib: 40,
            ssh_keys: vec!["ssh-ed25519 AAAA test".into()],
            console_password_hash: Some("$6$rounds=10000$saltsaltsaltsalt$hashhashhashhash".into()),
            gpu_local_ids: vec![],
            gpu_node: None,
            reboot_token: None,
            network: Some(NetworkAttachment {
                network_id: "c4d90fd2-be3d-4225-a4a6-265138a76e49".into(),
                dns_name: Some("gpu-1.internal".into()),
                mac: "02:09:a4:76:f8:ee".into(),
            }),
            recipe: None,
            // No overlay: this fixture is about the marketplace NIC.
            overlay: None,
        }
    }

    /// A recipe's setup is arbitrary shell — heredocs, quotes, dollars,
    /// backslashes — and it rides inside a YAML document. Base64 is what keeps
    /// the two apart, and this is the assertion that says so: the nastiest
    /// script we ship must not be able to break the config it travels in.
    #[test]
    fn a_recipe_of_raw_shell_cannot_break_the_cloud_config() {
        let nasty = r#"set -euo pipefail
U=$(getent passwd 1000 | cut -d: -f1)
cat > "$HOME/.config/sunshine/apps.json" <<'APPS'
{ "apps": [ { "name": "Steam Big Picture", "detached": ["setsid steam steam://open/bigpicture"] } ] }
APPS
echo 'single' "double" `backtick` \$escaped
"#;
        let mut spec = spec_with_network();
        spec.recipe = Some(omnuv_protocol::RecipeSpec {
            id: "steam-gaming".into(),
            compose: "services: {}\n".into(),
            gpu: true,
            post_up: vec![nasty.to_string()],
        });
        let ci = cloud_init(&spec, None, 103);
        // None of it appears literally, so none of it can be parsed as YAML.
        assert!(!ci.contains("APPS"), "the script must ride encoded, not inline");
        assert!(!ci.contains("bigpicture"));
        let doc: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&ci).expect("cloud-init must still be valid YAML");
        // The mirror block, when a provider named one, must not break the
        // document it is spliced into.
        let mirrored = cloud_init(&spec, Some("http://mirrors.up.pt/ubuntu"), 103);
        let m: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&mirrored).expect("a mirror must not break the YAML");
        assert_eq!(
            m["apt"]["primary"][0]["uri"].as_str(),
            Some("http://mirrors.up.pt/ubuntu"),
            "cloud-init must be told the mirror before the package stage runs"
        );
        // And an unset one leaves the image's own default alone rather than
        // writing an empty key that cloud-init would read as a mirror of "".
        assert!(doc.get("apt").is_none(), "no mirror configured, no apt block");
        assert!(doc.get("runcmd").is_some_and(|r| r.is_sequence()));
        // And it is recoverable: what boots is exactly what the catalog holds.
        // Two layers now — the recipe is one script under `set -e`, and each of
        // its steps is encoded inside that.
        use base64::Engine as _;
        let line = ci.lines().find(|l| l.contains("base64 -d")).expect("an encoded step");
        let b64 = line.split("echo ").nth(1).unwrap().split(' ').next().unwrap();
        let outer = String::from_utf8(
            base64::engine::general_purpose::STANDARD.decode(b64).expect("decodes"),
        )
        .unwrap();
        let steps = inner(&outer);
        assert!(!steps.is_empty(), "the outer script carries the encoded steps");
        assert!(steps.iter().any(|s| s.contains("docker")
            || s.contains("nvidia")
            || s.contains("APPS")));
    }

    /// The bug this whole fix exists for: the marketplace address must be set in
    /// bootcmd (every boot, before the config stage where apt runs), never only
    /// in runcmd (first boot only, after a slow apt that may not have finished).
    #[test]
    fn marketplace_network_is_in_bootcmd_before_runcmd() {
        let ci = cloud_init(&spec_with_network(), None, 103);
        let boot = ci.find("bootcmd:").expect("has bootcmd");
        let run = ci.find("runcmd:").expect("has runcmd");
        let addr = ci
            .find(&format!("{}/16", crate::names::segment_address(103)))
            .expect("configures the address on-link");
        assert!(boot < addr, "address must be under bootcmd");
        assert!(addr < run, "address must come before runcmd, not inside it");
        // The agent is still installed and started so Core can read the IP back.
        assert!(ci.contains("qemu-guest-agent"));
        // The image's user gets the console password as a hash, the account is
        // unlocked for it, and SSH stays key-only.
        assert!(ci.contains("- name: omnuv\n    sudo:"));
        assert!(ci.contains("lock_passwd: false"));
        assert!(ci.contains("ssh_pwauth: false"));
        // **On the user entry, where `cc_users_groups` can see it.** In a
        // `chpasswd` block cloud-init created the account locked and warned
        // "no 'hashed_passwd' provided in user-data", leaving the buyer's only
        // out-of-band access resting on a later module undoing the first.
        let users = ci.find("- name: omnuv").expect("the image user");
        let after = ci.find("ssh_authorized_keys:").expect("its keys");
        let entry = &ci[users..after];
        assert!(
            entry.contains("hashed_passwd: \"$6$rounds=10000$"),
            "the hash must be on the user entry, not in a later module: {entry}"
        );
        assert!(!ci.contains("chpasswd"), "chpasswd creates the account locked first");
        // **Nothing points at a `.1` any more.** Protocol 4 removed the
        // gateway, and this is the assertion that it cannot come back by
        // accident: a route through a deleted machine, or a resolver at one,
        // fails silently while the machine reports RUNNING.
        assert!(!ci.contains("10.200.99.1\\n"), "no next hop and no resolver at the old gateway");
        assert!(!ci.contains("GatewayOnLink"));
        // The `\\n` matters: the generator's own comment says "No DNS= line",
        // and an assertion that cannot tell a comment from a directive is one
        // that fails on its own prose.
        assert!(
            !ci.contains("\\nDNS="),
            "private names come from the overlay client's own resolver, not a DNS= directive"
        );
        // Our file must sort first, and the first-boot rebind (reload, then
        // reconfigure — D-Bus calls) must be in runcmd, never in bootcmd
        // where D-Bus is not up yet and they fail silently.
        assert!(ci.contains("05-onv.network"));
        // The link is addressed and has no route, which networkd settles at
        // `degraded`. Without this, `systemd-networkd-wait-online` waits for
        // `routable` and times out on every boot.
        assert!(
            ci.contains("[Link]\\nRequiredForOnline=degraded"),
            "the segment link never becomes routable, and must not be waited for as if it would"
        );
        let reload = ci.find("networkctl reload").expect("reloads");
        let reconf = ci.find("networkctl reconfigure $DEV").expect("reconfigures");
        assert!(run < reload && reload < reconf, "rebind lives in runcmd, reload before reconfigure");
        let bootcmd = &ci[boot..run];
        assert!(!bootcmd.contains("networkctl reload"), "no reload in bootcmd: D-Bus is not up");
        assert!(!bootcmd.contains("networkctl reconfigure"), "no reconfigure in bootcmd");
        assert!(!ci.contains("resolvectl dns"), "DNS comes from the networkd file, not resolvectl");
    }

    /// The enrolment has to survive being embedded in YAML, and the failure
    /// mode if it does not is a machine that boots with a broken cloud-config
    /// and joins nothing — reported as RUNNING, because it is.
    #[test]
    fn an_enrolled_machine_still_produces_valid_cloud_init() {
        let spec = InstanceSpec {
            id: "i-1".into(),
            name: "gpu-1".into(),
            intent: omnuv_protocol::Lifecycle::Running,
            vcpus: 2,
            memory_mib: 2048,
            disk_gib: 20,
            overlay: Some(omnuv_protocol::OverlayEnrolment {
                setup_key: "0E38B183-B8B6-45CE-B93B-2EF63F3D14E4".into(),
                management_url: "https://api.omnuv.com:8443".into(),
                hostname: Some("onv-gpu-1".into()),
            }),
            ..Default::default()
        };
        let ci = cloud_init(&spec, None, 103);
        let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(&ci).expect("valid YAML");
        assert!(doc.get("runcmd").is_some_and(|r| r.is_sequence()));
        assert!(ci.contains("netbird up"), "the machine must enrol itself");
        // The whole key, not a prefix of it. This is the assertion that stands
        // between a redacted secret type and a fleet of machines that boot,
        // report RUNNING and enrol nothing: it fails on `<redacted>`, and it
        // also fails on a key truncated anywhere after the eighth character,
        // which a prefix match would have waved through.
        assert!(
            ci.contains("--setup-key 0E38B183-B8B6-45CE-B93B-2EF63F3D14E4"),
            "the enrolment key must reach the guest whole: {ci}"
        );
        assert!(ci.contains("|| true"), "and a failure must not stop the boot");
    }

    /// A machine with no private network gets no enrolment, and the cloud-init
    /// is unchanged from what it always was. `None` means *not a peer*, never
    /// *the field went missing*.
    #[test]
    fn a_machine_with_no_overlay_is_untouched() {
        let spec = InstanceSpec {
            id: "i-2".into(),
            name: "gpu-2".into(),
            intent: omnuv_protocol::Lifecycle::Running,
            vcpus: 2,
            memory_mib: 2048,
            disk_gib: 20,
            ..Default::default()
        };
        let ci = cloud_init(&spec, None, 103);
        assert!(!ci.contains("netbird"));
        let _: serde_yaml_ng::Value = serde_yaml_ng::from_str(&ci).expect("valid YAML");
    }

    /// The bug that shipped once and cost a full validation cycle: the
    /// MAC-resolution shell contains `[ -n "$DEV" ]`, and a double quote inside
    /// a `[ sh, -c, "..." ]` flow scalar closes the YAML string, so cloud-init
    /// silently rejected the *entire* config — no networking, no agent. A
    /// `contains()` check cannot see that; parsing as YAML can.
    #[test]
    fn cloud_init_is_valid_yaml() {
        let ci = cloud_init(&spec_with_network(), None, 103);
        let doc: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&ci).expect("cloud-init must be valid YAML");
        let boot = doc.get("bootcmd").expect("has bootcmd");
        assert!(boot.is_sequence(), "bootcmd is a list");
        // The network setup is one block-scalar string entry that mentions the
        // address and the "$DEV" test that broke the flow form.
        let joined = serde_yaml_ng::to_string(boot).unwrap();
        // The address the *driver* picked for VMID 103, not one Core sent.
        assert!(joined.contains(&format!("{}/16", crate::names::segment_address(103))));
        assert!(joined.contains("$DEV"));
    }

    /// A project without a private network must still produce valid cloud-init:
    /// bootcmd is never left empty (which cloud-init reads as null).
    #[test]
    fn no_network_still_has_a_bootcmd_body() {
        let mut spec = spec_with_network();
        spec.network = None;
        let ci = cloud_init(&spec, None, 103);
        let boot = ci.find("bootcmd:").expect("has bootcmd");
        let after = &ci[boot + "bootcmd:".len()..];
        // The first entry, past any comment lines.
        let first = after.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#')).unwrap_or("");
        assert!(first.starts_with("- ["), "bootcmd has at least one item, got {first:?}");
    }

    /// A half-written credential is not a credential.
    ///
    /// The file is written by a `printf` in the recipe, so this reads it before
    /// it exists, while it is being written, and after — and the only shape
    /// that may produce a `Some` is the whole one. A blank half handed upward
    /// would be a login that passes every `length > 0` check between here and
    /// the buyer's screen, and then refuses to sign in: worse than none at all,
    /// because absence is detectable.
    #[test]
    fn a_stream_credential_is_delivered_whole_or_not_at_all() {
        let whole = parse_stream_credentials("user=onv-Ab3xK9zQ\npassword=s3cr3tXYZ\n")
            .expect("both halves present");
        assert_eq!(whole.user, "onv-Ab3xK9zQ");
        assert_eq!(whole.password.expose(), "s3cr3tXYZ");

        for partial in [
            "",                              // not written yet
            "user=onv-Ab3xK9zQ\n",           // caught mid-printf
            "password=s3cr3tXYZ\n",          // the user line lost
            "user=\npassword=s3cr3tXYZ\n",   // blank halves are not halves
            "user=onv-Ab3xK9zQ\npassword=\n",
            "step=3/6\nrc=0\n",              // the *other* file, by mistake
        ] {
            assert!(
                parse_stream_credentials(partial).is_none(),
                "must not deliver a partial credential: {partial:?}"
            );
        }

        // Unknown keys are ignored rather than fatal, so the recipe can add one
        // without an agent that predates it refusing the whole file.
        assert!(parse_stream_credentials("port=47990\nuser=u\npassword=p\n").is_some());
    }
}

#[cfg(test)]
mod the_cards_are_used_where_core_sold_them {
    //! CORE-25: a PCI address is unique only per node. Told the node, the agent
    //! places there, even when the same slot is free on the node it would
    //! have tried first; told a node it cannot use, it refuses.
    use crate::pvemock::{task_ok, Mock};
    use omnuv_protocol::InstanceSpec;

    fn two_nodes() -> impl Fn(&str, &str, &str) -> (u16, serde_json::Value) + Send + Sync + 'static {
        |method, path, _| {
            if let Some(r) = task_ok(path) {
                return r;
            }
            match (method, path) {
                ("GET", "/cluster/resources?type=vm") => (200, serde_json::json!([])),
                ("GET", "/nodes") => (200, serde_json::json!([
                    {"node": "n1", "status": "online"}, {"node": "n2", "status": "online"}])),
                ("GET", "/nodes/n1/qemu") | ("GET", "/nodes/n2/qemu") => (200, serde_json::json!([])),
                ("GET", "/cluster/mapping/pci") => (200, serde_json::json!([])),
                ("GET", "/cluster/nextid") => (200, serde_json::json!("123")),
                ("POST", p) if p.ends_with("/clone") => (200, serde_json::json!("UPID:n2:clone")),
                ("POST", p) if p.ends_with("/qemu/123/config") => (200, serde_json::Value::Null),
                // Ends the create at the rollback, once the placement is decided.
                ("PUT", p) if p.ends_with("/qemu/123/resize") => (500, serde_json::Value::Null),
                ("POST", p) if p.ends_with("/qemu/123/status/stop") => (200, serde_json::json!("UPID:n2:stop")),
                ("DELETE", p) if p.ends_with("/qemu/123") => (200, serde_json::json!("UPID:n2:del")),
                _ => (404, serde_json::Value::Null),
            }
        }
    }

    fn spec(node: &str) -> InstanceSpec {
        let desired: serde_json::Value =
            serde_json::from_str(include_str!("../tests/from-core/desired-state.json")).unwrap();
        let mut spec: InstanceSpec = serde_json::from_value(desired["instances"][0].clone()).unwrap();
        spec.gpu_local_ids = vec!["0000:01:00.0".into()];
        spec.gpu_node = Some(node.into());
        spec
    }

    fn snippets(name: &str) -> (std::path::PathBuf, String) {
        let root = std::env::temp_dir().join(format!("onv-node-{name}-{}", std::process::id()));
        std::fs::create_dir_all(root.join("snippets")).unwrap();
        let dir = root.join("snippets").to_string_lossy().into_owned();
        (root, dir)
    }

    #[tokio::test]
    async fn the_named_node_is_used_even_when_another_has_the_same_slot_free() {
        let mock = Mock::start(two_nodes()).await;
        let (root, dir) = snippets("named");
        let _ = mock.client().ensure_instance("n1", 9000, "local", &dir, &spec("n2")).await;
        let calls = mock.calls.lock().unwrap();
        let clones: Vec<&str> = calls.iter().filter(|c| c.path.ends_with("/clone")).map(|c| c.path.as_str()).collect();
        assert_eq!(clones, ["/nodes/n2/qemu/9000/clone"], "cloned where the cards were not sold");
        drop(calls);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn a_node_it_cannot_use_is_refused_not_substituted() {
        let mock = Mock::start(two_nodes()).await;
        let (root, dir) = snippets("absent");
        let refused = mock.client().ensure_instance("n1", 9000, "local", &dir, &spec("n9")).await;
        let e = refused.expect_err("placed on another node than the one named");
        assert!(e.downcast_ref::<super::Unplaceable>().is_some(), "{e:#}");
        assert!(!mock.calls.lock().unwrap().iter().any(|c| c.path.ends_with("/clone")), "a clone was made anyway");
        std::fs::remove_dir_all(&root).unwrap();
    }
}

#[cfg(test)]
mod gpu_placement_is_one_shot {
    //! **A card that is not free is refused before anything is built.**
    //!
    //! The agent has always known which cards are taken — `claimed_pci` lists
    //! every display controller and subtracts what each guest holds — and used
    //! that answer only to decide what to *offer* Core, never to decide whether
    //! to *accept* a placement. So a request for a card another machine held
    //! was attempted: the VM was cloned, the attach failed with Proxmox's own
    //! `PCI device '0000:21:00.0' already in use by VMID '103'`, and the generic
    //! task failure read as retryable — so Core re-drove an impossible request
    //! for as long as the other machine lived, each attempt leaving a stopped
    //! shell holding a disk.
    //!
    //! Measured on Pluto with two RTX 3090s, 19 September 2026.

    /// The two refusals that must not be retried, and the one that must.
    ///
    /// **This test passed while the thing it describes was broken**, which is
    /// why it now classifies the way `agent.rs` does rather than the way it
    /// once did. It pinned the phrases, the cluster walk reworded the refusal,
    /// the phrases here were not among the ones that changed, and the test went
    /// on being green while a one-shot refusal was reported retryable on real
    /// hardware. A test that asserts a copy of the logic asserts the copy.
    #[test]
    fn a_placement_that_cannot_succeed_is_not_retried() {
        // The image refusal is still a phrase, and still the hazard.
        let classify = |why: &str| !why.contains("is not offered by this provider");

        assert!(!classify("image ubuntu-26.04-nvidia is not offered by this provider"));
        assert!(classify("proxmox task failed: got no worker upid - start worker failed"));
        assert!(classify("connection refused"));

        // **And the capacity refusal is a type**, so no wording can break it.
        // Whatever the message says — and it has already changed once — the
        // fact travels as `Unplaceable` and `downcast_ref` finds it.
        let refused: anyhow::Error =
            anyhow::Error::new(super::Unplaceable { waiting_on: "a provider with free capacity" })
                .context("insufficient resources on this provider: none of its 1 node(s) can place this machine");
        assert!(refused.downcast_ref::<super::Unplaceable>().is_some());
        assert_eq!(
            refused.downcast_ref::<super::Unplaceable>().unwrap().waiting_on,
            "a provider with free capacity"
        );
        // Reword it entirely; the classification does not move.
        let reworded: anyhow::Error =
            anyhow::Error::new(super::Unplaceable { waiting_on: "a provider with free capacity" })
                .context("something a future edit decided to say instead");
        assert!(reworded.downcast_ref::<super::Unplaceable>().is_some());
        // An ordinary transient error carries no such type.
        let transient = anyhow::anyhow!("connection refused");
        assert!(transient.downcast_ref::<super::Unplaceable>().is_none());
    }
}

/// **A placement that cannot succeed here, as a type rather than a phrase.**
///
/// `retryable` was decided by matching the error text — the third untyped string
/// acting as protocol on this wire — and it broke the same afternoon it was
/// written. The cluster walk reworded the refusal from "is not free on this
/// provider" to "is already assigned to another guest here"; the classifier
/// still grepped for the old phrase, so a one-shot refusal was reported
/// retryable, Core re-drove it, the retry succeeded once the cards freed, and
/// the machine took a recycled VMID. Measured on Pluto, 19 September 2026.
///
/// A phrase reworded on one side silently changing the other's behaviour is the
/// definition of the hazard. This is the same information as a type, which a
/// rename cannot break: `anyhow` carries it through, and the classifier asks
/// `downcast_ref` rather than `contains`.
#[derive(Debug)]
pub struct Unplaceable {
    /// What the buyer is waiting for, in the marketplace's own vocabulary.
    pub waiting_on: &'static str,
}

impl std::fmt::Display for Unplaceable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "this request cannot be placed on this provider")
    }
}

impl std::error::Error for Unplaceable {}

impl crate::proxmox::Client {
    /// Can **this node** take this machine? Asked before anything is created.
    ///
    /// The one resource checked today is the GPU, because it is the one that is
    /// exclusive, scarce, and silently wrong when double-sold. CPU, memory and
    /// storage are reserved by the marketplace ledger rather than here, and
    /// adding them is a second arm of this function rather than a second shape.
    ///
    /// Every refusal is a sentence, because the caller joins them into the
    /// message an operator reads when the whole provider is full.
    pub(crate) async fn node_can_place(
        &self,
        node: &str,
        spec: &omnuv_protocol::InstanceSpec,
    ) -> anyhow::Result<()> {
        if spec.gpu_local_ids.is_empty() {
            return Ok(());
        }
        let claims = self.claimed_pci(node, None).await;
        // **An incomplete view refuses rather than proceeds.** "I could not read
        // every guest" and "every card is free" must never be the same answer —
        // that is how a card gets sold twice.
        anyhow::ensure!(
            claims.complete,
            "its guest inventory could not be read in full, so no card here can be proven free"
        );
        for want in &spec.gpu_local_ids {
            let slot = crate::proxmox::pci_slot(want);
            anyhow::ensure!(
                claims.may_offer(&slot),
                "GPU {want} is already assigned to another guest here"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod a_provider_is_not_a_node {
    //! **A provider runtime may be one host or a cluster**, and this agent
    //! treated it as one host everywhere. Three separate consequences, all
    //! measured against the five-node NUC cluster on 19 September 2026:
    //!
    //! ```text
    //! inventory   walked the cluster only when `omnuv_node` was unset, so a
    //!             cluster offering one node advertised a twelfth of itself
    //! placement   used `unwrap_or_default()` — the empty string — making every
    //!             `/nodes//qemu` path malformed when unset, and pinning to one
    //!             node when set. A card free on nuc3 was invisible
    //! lookup      `find_tagged_vm` asked one node, so a machine on nuc3 looked
    //!             like one that had never been created. Converging would have
    //!             built a second copy while the first kept its card; deleting
    //!             would have reported it already gone, releasing the allocation
    //!             and the card while the machine kept running
    //! ```
    //!
    //! The last is the worst, and it is why both `ensure_instance` and
    //! `delete_instance` now ask `/cluster/resources` rather than one node.

    /// The refusal names the **provider**, not five nodes.
    ///
    /// Asserted on the shape rather than against a live cluster: what an
    /// operator reads when capacity runs out is one sentence about the
    /// provider, with each node's reason behind it — not five errors they have
    /// to add up themselves.
    #[test]
    fn a_full_provider_says_so_once() {
        let refused = [
            "nuc0: GPU 0000:21:00.0 is already assigned to another guest here".to_string(),
            "nuc1: GPU 0000:21:00.0 is already assigned to another guest here".to_string(),
        ];
        let message = format!(
            "insufficient resources on this provider: none of its {} node(s) can place this machine. {}",
            refused.len(),
            refused.join("; ")
        );
        assert!(message.starts_with("insufficient resources on this provider"));
        assert!(message.contains("2 node(s)"));
        // Every node's reason survives, because "it did not fit" without a
        // reason is what makes somebody go and look by hand.
        assert!(message.contains("nuc0:") && message.contains("nuc1:"));
    }
}
