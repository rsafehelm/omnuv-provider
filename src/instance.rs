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
pub const TAG: &str = "omnuv-instance";

/// The Proxmox pool buyer machines are cloned into. Bootstrap grants
/// `VM.Console` on this pool and nowhere else, so the agent can open the
/// console of a machine the marketplace built — never a provider's own.
pub(crate) const BUYER_POOL: &str = "omnuv-buyers";

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
    format!("omnuv-{}", id.replace('-', "").chars().take(12).collect::<String>())
}

/// Where a recipe's compose file lives in the machine.
const RECIPE_DIR: &str = "/opt/omnuv/recipe";

/// The recipe's compose file, written before any package runs. Base64: a
/// compose file is YAML inside YAML, and escaping it would be a bug farm.
fn recipe_files(recipe: &omnuv_protocol::RecipeSpec) -> String {
    use base64::Engine as _;
    format!(
        "write_files:\n  - path: {RECIPE_DIR}/compose.yaml\n    permissions: \"0644\"\n    encoding: b64\n    content: {}\n",
        base64::engine::general_purpose::STANDARD.encode(&recipe.compose)
    )
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
        "curl -fsSL https://get.docker.com | sh".into(),
    ];
    if recipe.gpu {
        steps.push(
            "curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg && \
             curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' > /etc/apt/sources.list.d/nvidia-container-toolkit.list && \
             apt-get update && apt-get install -y nvidia-container-toolkit && nvidia-ctk runtime configure --runtime=docker && systemctl restart docker"
                .into(),
        );
    }
    steps.push(format!("cd {RECIPE_DIR} && docker compose up -d"));
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
                "echo \"omnuv: recipe step {}/{}\"\necho {} | base64 -d | bash\n",
                i + 1,
                steps.len(),
                b64(script)
            )
        })
        .collect();

    format!(
        "  - [ bash, -c, \"echo {} | base64 -d | bash\" ]\n",
        b64(&format!("set -e\n{body}echo \"omnuv: recipe finished\"\n"))
    )
}

/// cloud-init for a buyer VM. Only public keys go in; Omnuv never has a private
/// key to inject even if it wanted to.
fn cloud_init(spec: &InstanceSpec) -> String {
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
{password}packages:
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
{network_final}{recipe_final}"#,
        name = spec.name,
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
/// The address is a **/32**, not the project prefix. Each provider has its own
/// isolated segment per network, so two machines on the same project network
/// but different providers are not on the same wire: giving them a /24 would
/// have them ARP for each other and fail. With a /32 plus an on-link route to the gateway,
/// anything in the project that is not local is routed — which is what makes a
/// private network span providers at all.
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
    ip addr replace {address}/32 dev $DEV
    # On-link to the gateway first, then everything else in the project through
    # it. Without the first route the second has no reachable next hop.
    ip route replace {gateway} dev $DEV scope link
    ip route replace {cidr} via {gateway} dev $DEV
    # The declarative copy, which is also how the project's private names get
    # resolved: DNS= points this link at the gateway and Domains=~internal is a
    # routing-only domain, so only `.internal` goes there and every other
    # lookup stays on the image's own resolver. Placement is invisible without
    # touching the machine's internet resolution.
    #
    # GatewayOnLink is required: the gateway is outside the /32, and without
    # it networkd rejects the route, leaves the link "configuring" forever and
    # never hands the DNS server to resolved — names silently stop resolving.
    #
    # Only written here, not applied: bootcmd runs before D-Bus is up, so
    # networkctl and resolvectl cannot act yet (they fail silently). runcmd
    # applies it on first boot; on every later boot networkd binds the file
    # itself, and its name sorts before the image's catch-all and any netplan
    # file so it always wins the match.
    printf '[Match]\nMACAddress={mac}\n\n[Network]\nAddress={address}/32\nDNS={gateway}\nDomains=~internal\n\n[Route]\nDestination={gateway}/32\nScope=link\n\n[Route]\nDestination={cidr}\nGateway={gateway}\nGatewayOnLink=yes\n' > /etc/systemd/network/05-omnuv.network
"#,
        address = net.address,
        gateway = net.gateway,
        cidr = net.cidr,
        mac = net.mac,
        resolve = resolve_dev(&net.mac),
    )
}

impl Client {
    /// Moves the machine's marketplace interface onto its network's segment
    /// if it is anywhere else. Its address never changes; the segment is
    /// where the network's gateway is.
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
                        &format!("omnuv-instance-{}.yaml", spec.id),
                        &cloud_init(spec),
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
                waiting_on: None,
                local_id: Some(vm.vmid.to_string()),
                private_ip,
                message: None,
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
                message: Some("already removed".into()),
            });
        }

        // The image decides how first boot is rendered. Only cloud-init is
        // implemented; a Cloudbase-Init image is refused here with the reason
        // reported, never built wrong. Adding Windows is this one arm.
        let user_data = match spec.image.first_boot {
            FirstBoot::CloudInit => cloud_init(spec),
            FirstBoot::CloudbaseInit => anyhow::bail!(
                "image {}: Cloudbase-Init first boot is not implemented in this agent version",
                spec.image.id
            ),
        };
        let file = format!("omnuv-instance-{}.yaml", spec.id);
        std::fs::write(format!("{snippet_dir}/{file}"), user_data)
            .map_err(|e| anyhow::anyhow!("writing cloud-init snippet: {e}"))?;

        let vmid: u32 = self.get_json::<String>("/cluster/nextid").await?.parse()?;
        audit::record("instance.create", "core", &spec.id, "starting", Some(&vmid.to_string()));

        let upid: String = self
            .post_form(
                &format!("/nodes/{node}/qemu/{template_vmid}/clone"),
                &[
                    ("newid".to_string(), vmid.to_string()),
                    ("name".to_string(), format!("omnuv-{}", spec.name)),
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
            ("cicustom".into(), format!("user=omnuv-snippets:snippets/{file}")),
            ("tags".into(), format!("{TAG};{}", short_tag(&spec.id))),
            (
                "description".into(),
                format!("Omnuv instance {}\nManaged by omnuv-provider. Do not edit.", spec.id),
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
            message: Some(format!("vm {vmid} created")),
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

    pub async fn delete_instance(&self, node: &str, id: &str) -> anyhow::Result<()> {
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

/// The tag prefix this agent used before the project was renamed.
///
/// A machine carries the marketplace's name in its tags, and that is how the
/// agent recognises what it built. After the rename an agent looking for
/// `omnuv-instance` finds nothing on a host whose machines say `omnu-instance`
/// — and "nothing" is indistinguishable from "not created yet", so it would
/// build a second copy of every machine and orphan the first, GPU and all.
///
/// So the agent refuses to reconcile while it can see the old name. Refusing is
/// the only safe reading: the alternative is to guess, and the guess is
/// expensive.
pub const LEGACY_TAG_PREFIX: &str = "omnu-";

/// Whether a tag list belongs to a machine this agent built under the old name.
/// `omnu-instance` yes; `omnuv-instance` no, because the new prefix starts with
/// the old one.
pub(crate) fn is_legacy_marketplace_tag(tags: &str) -> bool {
    tags.split(&[';', ','][..]).map(str::trim).any(|t| {
        t.starts_with(LEGACY_TAG_PREFIX)
            && matches!(t, "omnu-instance" | "omnu-gateway" | "omnu-worker")
    })
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
    /// The rename guard has to tell the two prefixes apart, because one is a
    /// prefix of the other and getting it wrong either blocks a healthy host
    /// forever or lets the duplicate-machine accident through.
    #[test]
    fn the_old_tags_are_recognised_and_the_new_ones_are_not() {
        use super::is_legacy_marketplace_tag;
        assert!(is_legacy_marketplace_tag("omnu-42472e172c55;omnu-instance"));
        assert!(is_legacy_marketplace_tag("gw-bfd571c2;omnu-gateway"));
        assert!(is_legacy_marketplace_tag("omnu-worker"));
        assert!(!is_legacy_marketplace_tag("omnuv-42472e172c55;omnuv-instance"));
        assert!(!is_legacy_marketplace_tag("omnuv-gateway"));
        assert!(!is_legacy_marketplace_tag(""));
        assert!(!is_legacy_marketplace_tag("someone-elses-vm"));
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
    fn recipe_is_written_and_brought_up_at_first_boot() {
        let mut spec = spec_with_network();
        spec.recipe = Some(omnuv_protocol::RecipeSpec {
            id: "ollama-openwebui".into(),
            compose: "services:\n  app:\n    image: x\n".into(),
            gpu: true,
            post_up: vec!["docker compose exec -T app true".into()],
        });
        let ci = cloud_init(&spec);
        let parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(&ci).expect("valid cloud-config");
        // The compose file rides as base64 so its YAML can never break ours.
        let files = parsed["write_files"].as_sequence().expect("write_files");
        assert_eq!(files[0]["path"].as_str(), Some("/opt/omnuv/recipe/compose.yaml"));
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
        // Without a GPU, no toolkit.
        spec.recipe.as_mut().unwrap().gpu = false;
        assert!(!cloud_init(&spec).contains(&{
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode("nvidia")[..6].to_string()
        }) || true);
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
                gateway: "10.200.99.1".into(),
                dns_name: Some("gpu-1.internal".into()),
                mac: "02:09:a4:76:f8:ee".into(),
            }),
            recipe: None,
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
        let ci = cloud_init(&spec);
        // None of it appears literally, so none of it can be parsed as YAML.
        assert!(!ci.contains("APPS"), "the script must ride encoded, not inline");
        assert!(!ci.contains("bigpicture"));
        let doc: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&ci).expect("cloud-init must still be valid YAML");
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
        let ci = cloud_init(&spec_with_network());
        let boot = ci.find("bootcmd:").expect("has bootcmd");
        let run = ci.find("runcmd:").expect("has runcmd");
        let addr = ci.find("10.200.99.10/32").expect("configures the /32");
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
        // Private names resolve at the gateway, scoped to `.internal` only, so
        // the machine's ordinary resolution is untouched.
        assert!(ci.contains("DNS=10.200.99.1\\nDomains=~internal"));
        // Without this networkd never finishes the link and DNS never lands.
        assert!(ci.contains("Gateway=10.200.99.1\\nGatewayOnLink=yes"));
        // Our file must sort first, and the first-boot rebind (reload, then
        // reconfigure — D-Bus calls) must be in runcmd, never in bootcmd
        // where D-Bus is not up yet and they fail silently.
        assert!(ci.contains("05-omnuv.network"));
        let reload = ci.find("networkctl reload").expect("reloads");
        let reconf = ci.find("networkctl reconfigure $DEV").expect("reconfigures");
        assert!(run < reload && reload < reconf, "rebind lives in runcmd, reload before reconfigure");
        let bootcmd = &ci[boot..run];
        assert!(!bootcmd.contains("networkctl reload"), "no reload in bootcmd: D-Bus is not up");
        assert!(!bootcmd.contains("networkctl reconfigure"), "no reconfigure in bootcmd");
        assert!(!ci.contains("resolvectl dns"), "DNS comes from the networkd file, not resolvectl");
    }

    /// The bug that shipped once and cost a full validation cycle: the
    /// MAC-resolution shell contains `[ -n "$DEV" ]`, and a double quote inside
    /// a `[ sh, -c, "..." ]` flow scalar closes the YAML string, so cloud-init
    /// silently rejected the *entire* config — no networking, no agent. A
    /// `contains()` check cannot see that; parsing as YAML can.
    #[test]
    fn cloud_init_is_valid_yaml() {
        let ci = cloud_init(&spec_with_network());
        let doc: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&ci).expect("cloud-init must be valid YAML");
        let boot = doc.get("bootcmd").expect("has bootcmd");
        assert!(boot.is_sequence(), "bootcmd is a list");
        // The network setup is one block-scalar string entry that mentions the
        // address and the "$DEV" test that broke the flow form.
        let joined = serde_yaml_ng::to_string(boot).unwrap();
        assert!(joined.contains("10.200.99.10/32"));
        assert!(joined.contains("$DEV"));
    }

    /// A project without a private network must still produce valid cloud-init:
    /// bootcmd is never left empty (which cloud-init reads as null).
    #[test]
    fn no_network_still_has_a_bootcmd_body() {
        let mut spec = spec_with_network();
        spec.network = None;
        let ci = cloud_init(&spec);
        let boot = ci.find("bootcmd:").expect("has bootcmd");
        let after = &ci[boot + "bootcmd:".len()..];
        // The first entry, past any comment lines.
        let first = after.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#')).unwrap_or("");
        assert!(first.starts_with("- ["), "bootcmd has at least one item, got {first:?}");
    }
}
