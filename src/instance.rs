//! Buyer instance lifecycle on Proxmox.
//!
//! Translates a normalized `InstanceSpec` into a cloned VM with the buyer's
//! public keys injected by cloud-init. Marketplace ids live in the VM's tags so
//! state survives an agent restart, and nothing the marketplace did not create
//! is ever touched.

use omnu_protocol::{InstanceSpec, InstanceState, InstanceStatus, Lifecycle, NetworkAttachment};

use crate::audit;
use crate::proxmox::Client;

/// Marks VMs this agent owns on behalf of buyers. Distinct from the inference
/// worker tag so the two lifecycles can never be confused.
pub const TAG: &str = "omnu-instance";

const NO_FORM: &[(String, String)] = &[];

/// The isolated bridge buyer machines attach to. Created at provider bootstrap,
/// never by the agent: it is host network configuration, and the agent's token
/// holds SDN.Use and deliberately not SDN.Allocate.
pub(crate) const MARKETPLACE_BRIDGE: &str = "omnu0";

fn short_tag(id: &str) -> String {
    format!("omnu-{}", id.replace('-', "").chars().take(12).collect::<String>())
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
  - name: omnu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
{nested}
# Applies to the default user.
ssh_authorized_keys:
{top}
packages:
  - qemu-guest-agent
runcmd:
  - [ systemctl, enable, --now, qemu-guest-agent ]
{network}"#,
        name = spec.name,
        nested = render("      "),
        top = render("  "),
        network = spec.network.as_ref().map(private_network).unwrap_or_default(),
    )
}

/// Configures the machine's place on the buyer's private network.
///
/// The address is a **/32**, not the project prefix. Each provider has its own
/// isolated bridge, so two machines on the same project network but different
/// providers are not on the same segment: giving them a /24 would have them ARP
/// for each other and fail. With a /32 plus an on-link route to the gateway,
/// anything in the project that is not local is routed — which is what makes a
/// private network span providers at all.
fn private_network(net: &NetworkAttachment) -> String {
    let hosts = match &net.dns_name {
        Some(dns) => format!(
            "write_files:\n  - path: /etc/hosts.omnu\n    content: |\n      {} {}\n",
            net.address, dns
        ),
        None => String::new(),
    };
    format!(
        r#"  # The buyer's private network. eth1 is on the provider's isolated
  # marketplace bridge, which has no uplink: this machine has no path to the
  # provider's own network at all.
  - [ sh, -c, "ip link set dev eth1 up || true" ]
  - [ sh, -c, "ip addr add {address}/32 dev eth1 || true" ]
  # On-link to the gateway first, then everything else in the project through
  # it. Without the first route the second has no reachable next hop.
  - [ sh, -c, "ip route add {gateway} dev eth1 scope link || true" ]
  - [ sh, -c, "ip route add {cidr} via {gateway} dev eth1 || true" ]
{hosts}"#,
        address = net.address,
        gateway = net.gateway,
        cidr = net.cidr,
        hosts = hosts,
    )
}

impl Client {
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

            let ip = if running { self.guest_ipv4(node, vm.vmid).await } else { None };
            return Ok(InstanceStatus {
                id: spec.id.clone(),
                rebooted_token,
                state: match (running, ip.is_some()) {
                    (true, true) => InstanceState::Running,
                    (true, false) => InstanceState::Provisioning,
                    (false, _) => InstanceState::Stopped,
                },
                local_id: Some(vm.vmid.to_string()),
                private_ip: ip,
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

        let file = format!("omnu-instance-{}.yaml", spec.id);
        std::fs::write(format!("{snippet_dir}/{file}"), cloud_init(spec))
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
            ("cicustom".into(), format!("user=omnu-snippets:snippets/{file}")),
            ("tags".into(), format!("{TAG};{}", short_tag(&spec.id))),
            (
                "description".into(),
                format!("Omnu instance {}\nManaged by omnu-provider. Do not edit.", spec.id),
            ),
        ];
        let mut config = config;
        // A second interface on the marketplace's isolated bridge, when the
        // buyer's project has a network. `net0` stays on the provider's own
        // bridge for outbound internet; nothing routes between them.
        if spec.network.is_some() {
            config.push((format!("net1"), format!("virtio,bridge={MARKETPLACE_BRIDGE}")));
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
