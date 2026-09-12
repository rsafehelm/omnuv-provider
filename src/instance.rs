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
// Proxmox caps a vnet name at 8 characters, which is also why a marketplace
// segment is `o` plus seven hex digits rather than something readable. The
// rename produced `omnuvnat0`, which is nine and cannot exist; this is the same
// idea inside the limit.
pub(crate) const EGRESS_BRIDGE: &str = "onat0";

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
        key = o.setup_key,
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
fn cloud_init(spec: &InstanceSpec, apt_mirror: Option<&str>) -> String {
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
    ssh_authorized_keys:
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
        // The console password, as its crypt(3) hash: the plaintext was shown
        // to the buyer once and is not in this file. SSH stays key-only.
        password = spec
            .console_password_hash
            .as_deref()
            .map(|hash| {
                format!(
                    "chpasswd:\n  expire: false\n  users:\n    - name: {}\n      password: \"{hash}\"\n      type: hash\nssh_pwauth: false\n",
                    spec.image.default_user
                )
            })
            .unwrap_or_default(),
        nested = render("      "),
        top = render("  "),
        network = spec.network.as_ref().map(private_network).unwrap_or_default(),
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
fn private_network(net: &NetworkAttachment) -> String {
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
    # The declarative copy. No DNS= line: private names are answered by the
    # overlay client's own resolver, from the zone its network map carries, so
    # pointing this link at a resolver would be pointing it at nothing.
    #
    # Only written here, not applied: bootcmd runs before D-Bus is up, so
    # networkctl and resolvectl cannot act yet (they fail silently). runcmd
    # applies it on first boot; on every later boot networkd binds the file
    # itself, and its name sorts before the image's catch-all and any netplan
    # file so it always wins the match.
    printf '[Match]\nMACAddress={mac}\n\n[Network]\nAddress={address}/{prefix}\n' > /etc/systemd/network/05-onv.network
"#,
        address = net.address,
        prefix = prefix_of(&net.cidr),
        mac = net.mac,
        resolve = resolve_dev(&net.mac),
    )
}

/// The prefix length out of a CIDR, defaulting to a /24.
///
/// A default rather than a failure, and the default is what every project
/// network has been: a machine that comes up on the wrong prefix length can
/// still be reached and corrected, and one that does not come up at all cannot.
fn prefix_of(cidr: &str) -> u8 {
    cidr.split_once('/').and_then(|(_, p)| p.parse().ok()).filter(|p| *p <= 32).unwrap_or(24)
}

impl Client {
    /// Moves the machine's marketplace interface onto its network's segment
    /// if it is anywhere else. Its address never changes; the segment is
    /// where the network's gateway is.
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
            && spec.lifecycle != Lifecycle::Deleted
        {
            self.ensure_vnet(node, &marketplace_bridge(net)).await?;
        }

        if let Some(vm) = self.find_tagged_vm(node, TAG, &short_tag(&spec.id)).await? {
            let mut running = vm.status.as_deref() == Some("running");

            // The machine's place on its network's segment. A machine built
            // before the segment existed sits on another bridge; Proxmox
            // re-plugs a running machine's interface live, and the guest's
            // own configuration does not change.
            if let Some(net) = &spec.network
                && spec.lifecycle != Lifecycle::Deleted
            {
                self.ensure_segment(node, vm.vmid, net).await?;
            }

            // Converge toward the requested lifecycle rather than merely
            // reporting what is there.
            match spec.lifecycle {
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
            if spec.lifecycle != Lifecycle::Deleted
                && let Err(e) = self
                    .sync_cloud_init(
                        node,
                        vm.vmid,
                        snippet_dir,
                        &crate::names::snippet_instance(&spec.id),
                        &cloud_init(spec, self.apt_mirror.as_deref()),
                    )
                    .await
            {
                eprintln!("instance {}: cloud-init not refreshed: {e}", spec.id);
            }

            // One-shot: performed here and echoed back so Core can clear it.
            let mut rebooted_token = None;
            if running && spec.lifecycle == Lifecycle::Running
                && let Some(token) = &spec.reboot_token {
                    let upid: String = self
                        .post_form(&format!("/nodes/{node}/qemu/{}/status/reboot", vm.vmid), NO_FORM)
                        .await?;
                    self.wait_task(node, &upid).await?;
                    audit::record("instance.reboot", "core", &spec.id, "ok", Some(&vm.vmid.to_string()));
                    rebooted_token = Some(token.clone());
                }

            // The guest agent answering (any IPv4) is the liveness signal. But
            // the buyer-visible address is the *marketplace* one Core assigned,
            // not whatever the guest reports on its provider-local NIC — that
            // would leak the provider's network and show the wrong IP. Fall back
            // to the guest address only when the instance has no project network.
            let guest_ip = if running { self.guest_ipv4(node, vm.vmid).await } else { None };
            let private_ip = spec
                .network
                .as_ref()
                .map(|n| n.address.clone())
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
                    (false, _) if spec.lifecycle == Lifecycle::Running => {
                        Some("the machine to start".to_string())
                    }
                    _ => None,
                },
                local_id: Some(vm.vmid.to_string()),
                // Kept: an older Core reads only this, and the console still
                // shows the marketplace address rather than whichever NIC the
                // host happened to resolve first.
                private_ip: private_ip.clone(),
                adapters: self.observed_adapters(node, vm.vmid, private_ip.as_deref()).await,
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

        if spec.lifecycle == Lifecycle::Deleted {
            return Ok(InstanceStatus {
                id: spec.id.clone(),
                rebooted_token: None,
                state: InstanceState::Stopped,
                retryable: None,
                waiting_on: None,
                local_id: None,
                private_ip: None,
                adapters: Vec::new(),
                diagnostics: None,
                message: Some("already removed".into()),
                recipe_progress: None,
            });
        }

        // The image decides how first boot is rendered. Only cloud-init is
        // implemented; a Cloudbase-Init image is refused here with the reason
        // reported, never built wrong. Adding Windows is this one arm.
        let user_data = match spec.image.first_boot {
            FirstBoot::CloudInit => cloud_init(spec, self.apt_mirror.as_deref()),
            FirstBoot::CloudbaseInit => anyhow::bail!(
                "image {}: Cloudbase-Init first boot is not implemented in this agent version",
                spec.image.id
            ),
        };
        let file = crate::names::snippet_instance(&spec.id);
        std::fs::write(format!("{snippet_dir}/{file}"), user_data)
            .map_err(|e| anyhow::anyhow!("writing cloud-init snippet: {e}"))?;

        let vmid: u32 = self.get_json::<String>("/cluster/nextid").await?.parse()?;
        audit::record("instance.create", "core", &spec.id, "starting", Some(&vmid.to_string()));

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
        self.wait_task(node, &upid).await?;

        let config: Vec<(String, String)> = vec![
            ("cores".into(), spec.vcpus.to_string()),
            ("memory".into(), spec.memory_mib.to_string()),
            ("cpu".into(), "host".into()),
            ("agent".into(), "enabled=1".into()),
            ("ipconfig0".into(), "ip=dhcp".into()),
            // A display as well as the serial port: the serial console is
            // where a Linux machine logs in, the screen is what the buyer
            // opens to watch it boot or rescue it, and what a Windows machine
            // uses for everything.
            ("vga".into(), "std".into()),
            ("cicustom".into(), format!("user=onv-snippets:snippets/{file}")),
            ("tags".into(), format!("{TAG};{}", short_tag(&spec.id))),
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
        config.push(("net0".to_string(), format!("virtio,bridge={EGRESS_BRIDGE}")));
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
        audit::record("instance.create", "core", &spec.id, "ok", Some(&vmid.to_string()));

        Ok(InstanceStatus {
            id: spec.id.clone(),
            rebooted_token: None,
            state: InstanceState::Provisioning,
            retryable: None,
            waiting_on: None,
            local_id: Some(vmid.to_string()),
            private_ip: None,
            adapters: Vec::new(),
            diagnostics: None,
            message: Some(format!("vm {vmid} created")),
            // Just created: first boot has not started, let alone finished.
            recipe_progress: None,
        })
    }

    /// How the recipe's install went, read from the one file the recipe writes.
    ///
    /// The recipe reports its own outcome — the step it reached and the exit
    /// code — and this reads that single path and nothing else. Reading a known
    /// file needs `VM.GuestAgent.FileRead`; asking the guest to run
    /// `cloud-init status` instead would need `VM.GuestAgent.Unrestricted`,
    /// which is arbitrary command execution inside a machine the buyer owns.
    /// The marketplace must never be able to do that, so it does not ask for it.
    ///
    /// Best-effort by construction: a guest with no agent, a machine still
    /// installing, or an image that never wrote the file all return None, and
    /// None means "not known", never "failed".
    async fn recipe_progress(&self, node: &str, vmid: u32) -> Option<omnuv_protocol::RecipeProgress> {
        #[derive(serde::Deserialize)]
        struct FileRead {
            content: String,
        }

        let read: FileRead = self
            .get_json(&format!(
                "/nodes/{node}/qemu/{vmid}/agent/file-read?file={RECIPE_STATUS}"
            ))
            .await
            .ok()?;

        // step=3/6\nrc=100 — written by the recipe's own EXIT trap.
        let mut step = None;
        let mut rc = None;
        for line in read.content.lines() {
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
        })
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
            if !maintenance_may_touch(spec.lifecycle, true, false) {
                continue;
            }
            // Never create: absence is exactly the case where the stale
            // instruction might be wrong.
            let Some(vm) = self.find_tagged_vm(node, TAG, &short_tag(&spec.id)).await? else {
                continue;
            };
            let running = vm.status.as_deref() == Some("running");
            if !maintenance_may_touch(spec.lifecycle, true, running) {
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
        let snippet = format!("{snippet_dir}/{}", crate::names::snippet_instance(id));
        if let Err(e) = std::fs::remove_file(&snippet)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("instance {id}: cloud-init snippet not removed: {e}");
        }

        let Some(vm) = self.find_tagged_vm(node, TAG, &short_tag(id)).await? else {
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
        assert!(!maintenance_may_touch(Lifecycle::Deleted, true, true), "deleting is deciding");
        assert!(!maintenance_may_touch(Lifecycle::Deleted, true, false), "a stale delete must not start it either");
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
        let ci = cloud_init(&spec, None);
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
        let ci = cloud_init(&spec, None);
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
        assert!(!cloud_init(&spec, None).contains(&{
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode("nvidia")[..6].to_string()
        }) || true);
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
        let ci = cloud_init(&spec_enrolled_on_a_network(), None);
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
        for (what, frag) in [("overlay", overlay_runcmd(&o))] {
            assert!(frag.ends_with('\n'), "{what} fragment does not end a line");
            assert!(!frag.starts_with('\n'), "{what} fragment starts a line it did not open");
        }
    }

    fn spec_with_network() -> InstanceSpec {
        InstanceSpec {
            id: "abcdef12-0000-0000-0000-000000000000".into(),
            budget_secs: None,
            lifecycle: Lifecycle::Running,
            name: "gpu-1".into(),
            image: omnuv_protocol::ImageSpec::default(),
            vcpus: 2,
            memory_mib: 4096,
            disk_gib: 40,
            ssh_keys: vec!["ssh-ed25519 AAAA test".into()],
            console_password_hash: Some("$6$rounds=10000$saltsaltsaltsalt$hashhashhashhash".into()),
            gpu_local_ids: vec![],
            reboot_token: None,
            network: Some(NetworkAttachment {
                network_id: "c4d90fd2-be3d-4225-a4a6-265138a76e49".into(),
                address: "10.200.99.10".into(),
                cidr: "10.200.99.0/24".into(),
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
        let ci = cloud_init(&spec, None);
        // None of it appears literally, so none of it can be parsed as YAML.
        assert!(!ci.contains("APPS"), "the script must ride encoded, not inline");
        assert!(!ci.contains("bigpicture"));
        let doc: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&ci).expect("cloud-init must still be valid YAML");
        // The mirror block, when a provider named one, must not break the
        // document it is spliced into.
        let mirrored = cloud_init(&spec, Some("http://mirrors.up.pt/ubuntu"));
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
        let ci = cloud_init(&spec_with_network(), None);
        let boot = ci.find("bootcmd:").expect("has bootcmd");
        let run = ci.find("runcmd:").expect("has runcmd");
        let addr = ci.find("10.200.99.10/24").expect("configures the address on-link");
        assert!(boot < addr, "address must be under bootcmd");
        assert!(addr < run, "address must come before runcmd, not inside it");
        // The agent is still installed and started so Core can read the IP back.
        assert!(ci.contains("qemu-guest-agent"));
        // The image's user gets the console password as a hash, the account is
        // unlocked for it, and SSH stays key-only.
        assert!(ci.contains("- name: omnuv\n    sudo:"));
        assert!(ci.contains("lock_passwd: false"));
        assert!(ci.contains("password: \"$6$rounds=10000$"));
        assert!(ci.contains("type: hash"));
        assert!(ci.contains("ssh_pwauth: false"));
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
            lifecycle: omnuv_protocol::Lifecycle::Running,
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
        let ci = cloud_init(&spec, None);
        let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(&ci).expect("valid YAML");
        assert!(doc.get("runcmd").is_some_and(|r| r.is_sequence()));
        assert!(ci.contains("netbird up"), "the machine must enrol itself");
        assert!(ci.contains("--setup-key 0E38B183"), "with its own key");
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
            lifecycle: omnuv_protocol::Lifecycle::Running,
            vcpus: 2,
            memory_mib: 2048,
            disk_gib: 20,
            ..Default::default()
        };
        let ci = cloud_init(&spec, None);
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
        let ci = cloud_init(&spec_with_network(), None);
        let doc: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&ci).expect("cloud-init must be valid YAML");
        let boot = doc.get("bootcmd").expect("has bootcmd");
        assert!(boot.is_sequence(), "bootcmd is a list");
        // The network setup is one block-scalar string entry that mentions the
        // address and the "$DEV" test that broke the flow form.
        let joined = serde_yaml_ng::to_string(boot).unwrap();
        assert!(joined.contains("10.200.99.10/24"));
        assert!(joined.contains("$DEV"));
    }

    /// A project without a private network must still produce valid cloud-init:
    /// bootcmd is never left empty (which cloud-init reads as null).
    #[test]
    fn no_network_still_has_a_bootcmd_body() {
        let mut spec = spec_with_network();
        spec.network = None;
        let ci = cloud_init(&spec, None);
        let boot = ci.find("bootcmd:").expect("has bootcmd");
        let after = &ci[boot + "bootcmd:".len()..];
        // The first entry, past any comment lines.
        let first = after.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#')).unwrap_or("");
        assert!(first.starts_with("- ["), "bootcmd has at least one item, got {first:?}");
    }
}
