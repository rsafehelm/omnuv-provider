//! Inference worker lifecycle on Proxmox.
//!
//! Translates a normalized `InferenceWorkerSpec` into a cloned VM with the
//! requested GPUs attached and vLLM running inside. The marketplace id is
//! written into the VM description so state survives an agent restart.

use omnuv_protocol::{InferenceWorkerSpec, Lifecycle, WorkerState, WorkerStatus};
use serde::Deserialize;

use crate::proxmox::Client;

/// Marks VMs this agent owns. Recovery and deletion key off this, so nothing
/// the marketplace did not create is ever touched.
pub const TAG: &str = "omnuv-worker";

/// Typed empty form body for endpoints that take no parameters.
const NO_FORM: &[(String, String)] = &[];

#[derive(Deserialize)]
pub(crate) struct VmRef {
    pub(crate) vmid: u32,
    #[serde(default)]
    pub(crate) tags: Option<String>,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) status: Option<String>,
}

/// The marketplace attaches a card with its option ROM hidden (`rombar=0`).
///
/// A marketplace GPU is a compute device: nothing ever draws on it, so the
/// VBIOS the ROM bar exposes is never needed. Hiding it also makes a host's
/// *boot* GPU usable, which is otherwise unusable — the firmware shadows that
/// card's ROM and a guest driver reading it fails to initialize the adapter.
/// Verified on Pluto's `0000:5d:00.0`, the boot card: with the ROM bar hidden
/// the guest's driver loads and `nvidia-smi` lists the 3090.
pub(crate) fn mapping_name(pci: &str) -> String {
    format!("omnuv-gpu-{}", pci.replace([':', '.'], "-"))
}

/// cloud-init that brings up the NVIDIA stack and serves the model.
/// The HF cache lives on the VM disk; a shared per-node cache is a later
/// optimisation, not something to fake now.
fn cloud_init(spec: &InferenceWorkerSpec) -> String {
    // One argument per line, base64-encoded into the bootcmd.
    //
    // Shell-quoting these was wrong twice over: `$(cat file)` does not perform
    // quote removal, so a quoted argument reached vLLM with its quotes still
    // attached; and an argument like `{"image":0,"video":0}` would be
    // brace-expanded by bash before docker ever saw it. Base64 has no
    // shell-special characters, and the serve script reads the result into an
    // argv array so whitespace and punctuation survive intact.
    use base64::Engine as _;
    let args_b64 = base64::engine::general_purpose::STANDARD.encode(
        spec.vllm_args
            .iter()
            .map(|a| a.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
    );
    format!(
        r#"#cloud-config
package_update: true
packages:
  # Ubuntu cloud images do not ship the guest agent, and without it the host
  # cannot report the VM's address - so the worker could never become READY.
  - qemu-guest-agent
  - ca-certificates
  - curl
  - gnupg
  # Provides ubuntu-drivers, which is not present in the cloud image.
  - ubuntu-drivers-common
# bootcmd runs on EVERY boot, unlike write_files which runs once. Putting the
# arguments here means changing them is a snippet rewrite plus a reboot - the
# disk, and the model cache on it, survive. Rebuilding the VM to change a flag
# costs a ~16 GB re-download.
bootcmd:
  - [ bash, -c, "mkdir -p /etc/omnuv" ]
  - [ bash, -c, "echo {args_b64} | base64 -d > /etc/omnuv/vllm.args" ]
  - [ bash, -c, "echo {image_b64} | base64 -d > /etc/omnuv/vllm.image" ]
write_files:
  - path: /usr/local/bin/omnuv-serve
    permissions: '0755'
    content: |
      #!/bin/bash
      # Reads the image and arguments written at boot. Using an argv array
      # rather than word-splitting a string keeps arguments with spaces or
      # punctuation intact.
      set -euo pipefail
      mapfile -t ARGS < /etc/omnuv/vllm.args
      IMAGE=$(cat /etc/omnuv/vllm.image)
      exec /usr/bin/docker run --rm --name omnuv-vllm \
        --gpus all --ipc=host -p {port}:8000 \
        -v /opt/omnuv/hf:/root/.cache/huggingface \
        "$IMAGE" "${{ARGS[@]}}"
  - path: /etc/systemd/system/omnuv-vllm.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Omnuv inference worker (vLLM)
      After=docker.service
      Requires=docker.service

      [Service]
      Type=simple
      # The NVIDIA driver is only usable after the post-install reboot, so this
      # retries instead of depending on cloud-init ordering that cannot be made
      # reliable. Restarting until the GPU appears is the whole design.
      Restart=always
      RestartSec=15s
      ExecStartPre=-/usr/bin/docker rm -f omnuv-vllm
      # Reads image and arguments from disk at start, so changing them is a
      # reboot rather than a rebuild that re-downloads the model.
      ExecStart=/usr/local/bin/omnuv-serve
      ExecStop=/usr/bin/docker stop omnuv-vllm

      [Install]
      WantedBy=multi-user.target
runcmd:
  - [ systemctl, enable, --now, qemu-guest-agent ]
  - [ bash, -c, "mkdir -p /opt/omnuv/hf /etc/omnuv" ]
  - [ bash, -c, "curl -fsSL https://get.docker.com | sh" ]
  - [ bash, -c, "curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg" ]
  - [ bash, -c, "curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' > /etc/apt/sources.list.d/nvidia-container-toolkit.list" ]
  - [ bash, -c, "apt-get update && apt-get install -y nvidia-container-toolkit" ]
  - [ bash, -c, "nvidia-ctk runtime configure --runtime=docker && systemctl restart docker" ]
  # ubuntu-drivers --gpgpu installs the headless-no-dkms variant WITHOUT
  # nvidia-utils, so nvidia-smi is absent and the container toolkit cannot
  # enumerate /dev/nvidia0 - the container then starts with no GPU and vLLM
  # fails with "Failed to infer device type". Install the full server
  # metapackage for the newest available branch instead.
  - [ bash, -c, "apt-get update && DRV=$(apt-cache search --names-only '^nvidia-driver-[0-9]+-server$' | awk '{{print $1}}' | sort -V | tail -1) && echo \"installing $DRV\" && DEBIAN_FRONTEND=noninteractive apt-get install -y \"$DRV\"" ]
  - [ bash, -c, "command -v nvidia-smi || DEBIAN_FRONTEND=noninteractive apt-get install -y $(apt-cache search --names-only '^nvidia-utils-[0-9]+-server$' | awk '{{print $1}}' | sort -V | tail -1)" ]
  - [ systemctl, enable, omnuv-vllm.service ]
  # The driver is not loadable until the machine restarts; the service comes up
  # by itself afterwards.
  - [ bash, -c, "systemctl reboot" ]
"#,
        port = spec.port,
        args_b64 = args_b64,
        image_b64 = base64::engine::general_purpose::STANDARD.encode(&spec.image),
    )
}

impl Client {
    /// Finds a VM this agent created, by kind tag plus marketplace id tag.
    /// Two tags, not one: a VM must match both to be touched, so nothing the
    /// marketplace did not create is ever acted on.
    pub(crate) async fn find_tagged_vm(
        &self,
        node: &str,
        kind: &str,
        id_tag: &str,
    ) -> anyhow::Result<Option<VmRef>> {
        let vms: Vec<VmRef> = self.get_json(&format!("/nodes/{node}/qemu")).await?;
        Ok(vms.into_iter().find(|v| {
            v.tags.as_deref().is_some_and(|t| {
                t.split(';').any(|x| x == kind) && t.split(';').any(|x| x == id_tag)
            })
        }))
    }

    /// Machines this agent built under the project's old name.
    ///
    /// Their tags no longer match what the agent looks for, so to it they are
    /// invisible — and invisible reads as "not created yet". Converging on that
    /// would build a second copy of every machine and orphan the first, still
    /// holding its GPU. The agent refuses to converge while any are present.
    pub(crate) async fn legacy_marketplace_vms(&self, node: &str) -> anyhow::Result<Vec<u32>> {
        let vms: Vec<VmRef> = self.get_json(&format!("/nodes/{node}/qemu")).await?;
        Ok(vms
            .into_iter()
            .filter(|v| {
                v.tags.as_deref().is_some_and(crate::instance::is_legacy_marketplace_tag)
            })
            .map(|v| v.vmid)
            .collect())
    }

    async fn find_worker_vm(&self, node: &str, worker_id: &str) -> anyhow::Result<Option<VmRef>> {
        self.find_tagged_vm(node, TAG, &short_tag(worker_id)).await
    }

    pub async fn ensure_inference_worker(
        &self,
        node: &str,
        template_vmid: u32,
        storage: &str,
        snippet_dir: &str,
        spec: &InferenceWorkerSpec,
    ) -> anyhow::Result<WorkerStatus> {
        if let Some(vm) = self.find_worker_vm(node, &spec.id).await? {
            let mut running = vm.status.as_deref() == Some("running");

            // Converge, do not merely observe: a worker that exists but is not
            // running when Core wants it running must be started on this pass,
            // otherwise a failed first boot leaves it stopped forever.
            if !running && spec.lifecycle == Lifecycle::Running {
                let upid: String = self
                    .post_form(&format!("/nodes/{node}/qemu/{}/status/start", vm.vmid), NO_FORM)
                    .await?;
                self.wait_task(node, &upid).await?;
                running = true;
            }
            if running && spec.lifecycle == Lifecycle::Stopped {
                let upid: String = self
                    .post_form(&format!("/nodes/{node}/qemu/{}/status/shutdown", vm.vmid), NO_FORM)
                    .await?;
                self.wait_task(node, &upid).await?;
                running = false;
            }

            let endpoint = if running { self.worker_endpoint(node, vm.vmid, spec.port).await } else { None };
            // READY must mean "will serve a request", not "has an IP". A VM
            // boots minutes before vLLM finishes loading weights, and routing
            // traffic in that window fails every request.
            let serving = match &endpoint {
                Some(url) => self.worker_serving(url).await,
                None => false,
            };
            return Ok(WorkerStatus {
                id: spec.id.clone(),
                state: worker_state(running, endpoint.is_some(), serving),
                retryable: None,
                waiting_on: None,
                local_id: Some(vm.vmid.to_string()),
                endpoint: serving.then(|| endpoint.clone()).flatten(),
                message: match (running, endpoint.is_some(), serving) {
                    (true, false, _) => Some("booting; no address yet".into()),
                    (true, true, false) => Some("address up; model still loading".into()),
                    _ => vm.name,
                },
            });
        }

        // Snippet must exist before the VM references it.
        let file = format!("omnuv-{}.yaml", spec.id);
        std::fs::write(format!("{snippet_dir}/{file}"), cloud_init(spec))
            .map_err(|e| anyhow::anyhow!("writing cloud-init snippet: {e}"))?;

        let vmid: u32 = self.get_json::<String>("/cluster/nextid").await?.parse()?;

        let upid: String = self
            .post_form(
                &format!("/nodes/{node}/qemu/{template_vmid}/clone"),
                &[
                    ("newid".to_string(), vmid.to_string()),
                    ("name".to_string(), format!("omnuv-worker-{}", &spec.id[..8])),
                    ("full".to_string(), "1".to_string()),
                    ("storage".to_string(), storage.to_string()),
                ],
            )
            .await?;
        self.wait_task(node, &upid).await?;

        let mut config: Vec<(String, String)> = vec![
            ("cores".into(), spec.vcpus.to_string()),
            ("memory".into(), spec.memory_mib.to_string()),
            ("cpu".into(), "host".into()),
            // q35 is required for PCIe passthrough.
            ("machine".into(), "q35".into()),
            ("agent".into(), "enabled=1".into()),
            ("ipconfig0".into(), "ip=dhcp".into()),
            ("cicustom".into(), format!("user=omnuv-snippets:snippets/{file}")),
            ("tags".into(), format!("{TAG};{}", short_tag(&spec.id))),
            ("description".into(), format!("Omnuv inference worker {}\nManaged by omnuv-provider. Do not edit.", spec.id)),
        ];
        // Mappings rather than raw addresses: a non-root token may only attach
        // a device the host has explicitly published.
        for (i, pci) in spec.gpu_local_ids.iter().enumerate() {
            config.push((format!("hostpci{i}"), format!("mapping={},pcie=1,rombar=0", mapping_name(pci))));
        }
        self.post_form::<serde_json::Value>(&format!("/nodes/{node}/qemu/{vmid}/config"), &config).await?;

        // The template disk is small; grow it to the allocated size.
        self.put_form::<serde_json::Value>(
            &format!("/nodes/{node}/qemu/{vmid}/resize"),
            &[("disk".to_string(), "scsi0".to_string()), ("size".to_string(), format!("{}G", spec.disk_gib))],
        )
        .await?;

        let upid: String =
            self.post_form(&format!("/nodes/{node}/qemu/{vmid}/status/start"), NO_FORM).await?;
        self.wait_task(node, &upid).await?;

        Ok(WorkerStatus {
            id: spec.id.clone(),
            state: WorkerState::Deploying,
            retryable: None,
            waiting_on: None,
            local_id: Some(vmid.to_string()),
            endpoint: None,
            message: Some(format!("vm {vmid} created and started")),
        })
    }

    pub async fn delete_inference_worker(&self, node: &str, worker_id: &str) -> anyhow::Result<()> {
        let Some(vm) = self.find_worker_vm(node, worker_id).await? else { return Ok(()) };
        if vm.status.as_deref() == Some("running") {
            let upid: String =
                self.post_form(&format!("/nodes/{node}/qemu/{}/status/stop", vm.vmid), NO_FORM).await?;
            self.wait_task(node, &upid).await?;
        }
        let upid: String = self.delete_task(&format!("/nodes/{node}/qemu/{}", vm.vmid)).await?;
        self.wait_task(node, &upid).await?;
        Ok(())
    }

    /// True when the worker's OpenAI-compatible server answers. Deliberately
    /// short-timeout: this runs on every reconcile tick and a hung worker must
    /// not stall the loop.
    async fn worker_serving(&self, endpoint: &str) -> bool {
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(4))
            .build()
        {
            Ok(c) => c,
            Err(_) => return false,
        };
        matches!(client.get(format!("{endpoint}/v1/models")).send().await,
                 Ok(r) if r.status().is_success())
    }

    /// The guest's IPv4 address, once qemu-guest-agent is answering.
    pub(crate) async fn guest_ipv4(&self, node: &str, vmid: u32) -> Option<String> {
        let v: serde_json::Value = self
            .get_json(&format!("/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces"))
            .await
            .ok()?;
        v.get("result")?
            .as_array()?
            .iter()
            .filter(|i| i.get("name").and_then(|n| n.as_str()) != Some("lo"))
            .filter_map(|i| i.get("ip-addresses")?.as_array())
            .flatten()
            .find_map(|a| {
                let ip = a.get("ip-address")?.as_str()?;
                // Skip docker's own bridge inside the guest; it is not the
                // address anyone can reach the machine on.
                (a.get("ip-address-type")?.as_str()? == "ipv4"
                    && !ip.starts_with("127.")
                    && !ip.starts_with("172.17."))
                .then(|| ip.to_string())
            })
    }

    async fn worker_endpoint(&self, node: &str, vmid: u32, port: u16) -> Option<String> {
        self.guest_ipv4(node, vmid).await.map(|ip| format!("http://{ip}:{port}"))
    }
}

/// Maps observed facts to a normalized worker state. Pure, so the rules are
/// testable without a hypervisor.
fn worker_state(running: bool, has_address: bool, serving: bool) -> WorkerState {
    match (running, has_address, serving) {
        (false, _, _) => WorkerState::Offline,
        (true, _, true) => WorkerState::Ready,
        (true, true, false) => WorkerState::LoadingModel,
        (true, false, false) => WorkerState::Deploying,
    }
}

/// Tags cannot hold a full UUID with dashes cleanly, so a short prefix keys the
/// association. Collisions are implausible at POC scale and would only ever
/// affect this agent's own VMs.
fn short_tag(worker_id: &str) -> String {
    format!("omnuv-{}", worker_id.replace('-', "").chars().take(12).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_are_written_at_every_boot_not_baked_into_the_unit() {
        use omnuv_protocol::{InferenceWorkerSpec, Lifecycle};
        let spec = InferenceWorkerSpec {
            id: "w1".into(),
            budget_secs: None,
            lifecycle: Lifecycle::Running,
            image: "vllm/vllm-openai:latest".into(),
            model_repo: "org/model".into(),
            vllm_args: vec!["--model".into(), "org/model".into(), "--max-model-len".into(), "8192".into()],
            vcpus: 8,
            memory_mib: 32768,
            disk_gib: 120,
            gpu_local_ids: vec![],
            port: 8000,
        };
        let ci = super::cloud_init(&spec);

        // bootcmd runs on every boot; write_files runs once. The distinction is
        // the whole point: changing a flag must be a reboot, not a rebuild that
        // re-downloads the model.
        assert!(ci.contains("bootcmd:"), "args must be written from bootcmd");
        assert!(ci.contains("/etc/omnuv/vllm.args"));
        assert!(ci.contains("/etc/omnuv/vllm.image"));
        // Read into an argv array, not word-split from a string: `$(cat file)`
        // performs no quote removal and bash would brace-expand a value like
        // {"image":0,"video":0} before docker saw it.
        assert!(ci.contains("mapfile -t ARGS < /etc/omnuv/vllm.args"));
        assert!(ci.contains("\"${ARGS[@]}\""));
        assert!(ci.contains("ExecStart=/usr/local/bin/omnuv-serve"));
        // The arguments must be base64, never shell-quoted text in the unit.
        assert!(!ci.contains("--max-model-len"), "args leaked into the unit in plain text");

        // Round-trip: what bootcmd decodes is exactly the argv we asked for.
        use base64::Engine as _;
        let line = ci.lines().find(|l| l.contains("vllm.args") && l.contains("base64")).unwrap();
        // The payload is the token right after `echo`.
        let mut it = line.split_whitespace().skip_while(|t| !t.ends_with("echo"));
        it.next();
        let b64 = it.next().unwrap();
        let decoded = String::from_utf8(
            base64::engine::general_purpose::STANDARD.decode(b64).unwrap(),
        )
        .unwrap();
        assert_eq!(decoded.lines().collect::<Vec<_>>(), spec.vllm_args);
    }

    #[test]
    fn ready_requires_a_serving_endpoint_not_merely_an_address() {
        use omnuv_protocol::WorkerState::*;
        assert_eq!(worker_state(false, false, false), Offline);
        assert_eq!(worker_state(true, false, false), Deploying);
        // The window that matters: booted, addressable, still loading weights.
        assert_eq!(worker_state(true, true, false), LoadingModel);
        assert_eq!(worker_state(true, true, true), Ready);
    }

    #[test]
    fn maps_pci_addresses_to_published_mapping_names() {
        assert_eq!(mapping_name("0000:21:00.0"), "omnuv-gpu-0000-21-00-0");
        assert_eq!(mapping_name("0000:5d:00.0"), "omnuv-gpu-0000-5d-00-0");
    }

    #[test]
    fn short_tag_is_stable_and_tag_safe() {
        let t = short_tag("b48aedfb-205d-42fd-a6d3-3deafaeae938");
        assert_eq!(t, "omnuv-b48aedfb205d");
        assert!(!t.contains('-') || t.starts_with("omnuv-"));
        assert!(t.len() <= 20);
    }
}
