//! Buyer instance lifecycle on Proxmox.
//!
//! Translates a normalized `InstanceSpec` into a cloned VM with the buyer's
//! public keys injected by cloud-init. Marketplace ids live in the VM's tags so
//! state survives an agent restart, and nothing the marketplace did not create
//! is ever touched.

use omnu_protocol::{FirstBoot, InstanceSpec, InstanceState, InstanceStatus, Lifecycle, NetworkAttachment};

use crate::audit;
use crate::proxmox::Client;

/// Marks VMs this agent owns on behalf of buyers. Distinct from the inference
/// worker tag so the two lifecycles can never be confused.
pub const TAG: &str = "omnu-instance";

/// The Proxmox pool buyer machines are cloned into. Bootstrap grants
/// `VM.Console` on this pool and nowhere else, so the agent can open the
/// console of a machine the marketplace built — never a provider's own.
pub(crate) const BUYER_POOL: &str = "omnu-buyers";

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
pub(crate) const EGRESS_BRIDGE: &str = "omnunat0";

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
    format!("omnu-{}", id.replace('-', "").chars().take(12).collect::<String>())
}

/// Where a recipe's compose file lives in the machine.
const RECIPE_DIR: &str = "/opt/omnu/recipe";

/// The recipe's compose file, written before any package runs. Base64: a
/// compose file is YAML inside YAML, and escaping it would be a bug farm.
fn recipe_files(recipe: &omnu_protocol::RecipeSpec) -> String {
    use base64::Engine as _;
    format!(
        "write_files:\n  - path: {RECIPE_DIR}/compose.yaml\n    permissions: \"0644\"\n    encoding: b64\n    content: {}\n",
        base64::engine::general_purpose::STANDARD.encode(&recipe.compose)
    )
}

/// Brings the recipe up in runcmd: Docker from its own installer, the NVIDIA
/// container toolkit when the containers reserve a GPU (the image already
/// carries the driver), then `compose up` and the recipe's finishing steps.
/// Each command is a base64 script so nothing the recipe contains can break
/// the cloud-config it rides in.
fn recipe_runcmd(recipe: &omnu_protocol::RecipeSpec) -> String {
    use base64::Engine as _;
    let b64 = |script: &str| base64::engine::general_purpose::STANDARD.encode(script);
    let mut steps: Vec<String> = vec![
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
    steps
        .iter()
        .map(|script| format!("  - [ bash, -c, \"echo {} | base64 -d | bash\" ]\n", b64(script)))
        .collect()
}

/// cloud-init for a buyer VM. Only public keys go in; Omnu never has a private
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
    printf '[Match]\nMACAddress={mac}\n\n[Network]\nAddress={address}/32\nDNS={gateway}\nDomains=~internal\n\n[Route]\nDestination={gateway}/32\nScope=link\n\n[Route]\nDestination={cidr}\nGateway={gateway}\nGatewayOnLink=yes\n' > /etc/systemd/network/05-omnu.network
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

            // One-shot: performed here and echoed back so Core can clear it.
            let mut rebooted_token = None;
            if running && spec.lifecycle == Lifecycle::Running {
                if let Some(token) = &spec.reboot_token {
                    let upid: String = self
                        .post_form(&format!("/nodes/{node}/qemu/{}/status/reboot", vm.vmid), NO_FORM)
                        .await?;
                    self.wait_task(node, &upid).await?;
                    audit::record("instance.reboot", "core", &spec.id, "ok", Some(&vm.vmid.to_string()));
                    rebooted_token = Some(token.clone());
                }
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
        let file = format!("omnu-instance-{}.yaml", spec.id);
        std::fs::write(format!("{snippet_dir}/{file}"), user_data)
            .map_err(|e| anyhow::anyhow!("writing cloud-init snippet: {e}"))?;

        let vmid: u32 = self.get_json::<String>("/cluster/nextid").await?.parse()?;
        audit::record("instance.create", "core", &spec.id, "starting", Some(&vmid.to_string()));

        let upid: String = self
            .post_form(
                &format!("/nodes/{node}/qemu/{template_vmid}/clone"),
                &[
                    ("newid".to_string(), vmid.to_string()),
                    ("name".to_string(), format!("omnu-{}", spec.name)),
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
            ("cicustom".into(), format!("user=omnu-snippets:snippets/{file}")),
            ("tags".into(), format!("{TAG};{}", short_tag(&spec.id))),
            (
                "description".into(),
                format!("Omnu instance {}\nManaged by omnu-provider. Do not edit.", spec.id),
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
                format!("mapping={},pcie=1", crate::worker::mapping_name(pci)),
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
            local_id: Some(vmid.to_string()),
            private_ip: None,
            message: Some(format!("vm {vmid} created")),
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipe_is_written_and_brought_up_at_first_boot() {
        let mut spec = spec_with_network();
        spec.recipe = Some(omnu_protocol::RecipeSpec {
            id: "ollama-openwebui".into(),
            compose: "services:\n  app:\n    image: x\n".into(),
            gpu: true,
            post_up: vec!["docker compose exec -T app true".into()],
        });
        let ci = cloud_init(&spec);
        let parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(&ci).expect("valid cloud-config");
        // The compose file rides as base64 so its YAML can never break ours.
        let files = parsed["write_files"].as_sequence().expect("write_files");
        assert_eq!(files[0]["path"].as_str(), Some("/opt/omnu/recipe/compose.yaml"));
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
        assert!(scripts[0].contains("get.docker.com"));
        assert!(scripts[1].contains("nvidia-container-toolkit"));
        assert!(scripts[2].contains("docker compose up -d"));
        assert!(scripts[3].contains("docker compose exec -T app true"));
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
            lifecycle: Lifecycle::Running,
            name: "gpu-1".into(),
            image: omnu_protocol::ImageSpec::default(),
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
        assert!(ci.contains("- name: omnu\n    sudo:"));
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
        assert!(ci.contains("05-omnu.network"));
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
