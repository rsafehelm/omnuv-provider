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
pub const TAG: &str = crate::names::TAG_WORKER;

/// Typed empty form body for endpoints that take no parameters.
const NO_FORM: &[(String, String)] = &[];

#[derive(Deserialize)]
pub(crate) struct VmRef {
    pub(crate) vmid: u32,
    #[serde(default)]
    pub(crate) tags: Option<String>,
    #[serde(default)]
    pub(crate) status: Option<String>,
}

/// The marketplace attaches a card with its option ROM hidden (`rombar=0`).
///
/// A marketplace GPU is a compute device: nothing ever draws on it, so the
/// VBIOS the ROM bar exposes is never needed. Hiding it also makes a host's
/// *boot* GPU usable, which is otherwise unusable — the firmware shadows that
/// card's ROM and a guest driver reading it fails to initialize the adapter.
/// Verified on hardware against an RTX 3090 that was its host's boot display:
/// with the ROM bar hidden the guest's driver loads and `nvidia-smi` lists it.
///
/// **What this does not fix, and what looked like it did.** On 16 September a
/// second RTX 3090 on the same host — not its boot display — failed in the
/// guest with `RmInitAdapter failed! (0x62:0x65:2830)`, and `rombar` was the
/// obvious suspect. It was not: the card failed identically with the ROM bar
/// hidden, with it visible, with a VBIOS dumped from the working card and
/// passed as `romfile=`, and as the guest's primary display. The cause was
/// that the Proxmox mapping named the *video function* (`0000:21:00.0`)
/// rather than the card (`0000:21:00`), so the audio function stayed bound to
/// the host. With the whole device mapped it comes up first time, with no
/// `romfile` and no other change — see `deploy-agent.yml`, which builds the
/// mapping.
///
/// Recorded because three plausible fixes were tested and discarded here, and
/// the next person to meet a 0x62 should check the mapping's path first.
pub(crate) fn mapping_name(pci: &str) -> String {
    crate::names::gpu_mapping(pci)
}

/// cloud-init that brings up the NVIDIA stack and serves the model.
/// The HF cache lives on the VM disk; a shared per-node cache is a later
/// optimisation, not something to fake now.
/// The digest of the Workload Agent built beside this agent, compiled in by
/// `packaging/build-deb.sh`. **Anchored here, not at Core**: Core serves the
/// binary and a worker runs it as root, so the check is against the package
/// the provider installed, and Core only carries bytes. A plain `cargo build`
/// has none, and a worker it builds downloads without a check.
const WORKLOADD_SHA256: Option<&str> = option_env!("OMNUV_WORKLOADD_SHA256");

/// The shell fragment that refuses a download that is not that binary.
fn workloadd_check(sha256: Option<&str>) -> String {
    match sha256.filter(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())) {
        Some(sha) => format!(" && echo '{sha}  /usr/local/bin/onv-workloadd.new' | sha256sum -c --quiet -"),
        None => String::new(),
    }
}

fn cloud_init(spec: &InferenceWorkerSpec, core_url: &str) -> String {
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
  - [ bash, -c, "mkdir -p /etc/onv" ]
  - [ bash, -c, "echo {args_b64} | base64 -d > /etc/onv/vllm.args" ]
  - [ bash, -c, "echo {image_b64} | base64 -d > /etc/onv/vllm.image" ]
write_files:
  - path: /usr/local/bin/onv-serve
    permissions: '0755'
    content: |
      #!/bin/bash
      # Reads the image and arguments written at boot. Using an argv array
      # rather than word-splitting a string keeps arguments with spaces or
      # punctuation intact.
      set -euo pipefail
      mapfile -t ARGS < /etc/onv/vllm.args
      IMAGE=$(cat /etc/onv/vllm.image)
      exec /usr/bin/docker run --rm --name onv-vllm \
        --gpus all --ipc=host -p {port}:8000 \
        -v /opt/onv/hf:/root/.cache/huggingface \
        "$IMAGE" "${{ARGS[@]}}"
  - path: /etc/systemd/system/onv-workloadd.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Omnuv Workload Agent
      # Deliberately not After=onv-vllm: the minutes before vLLM serves are
      # exactly the window this exists to describe.

      [Service]
      Type=simple
      # Fetches its own binary when it is missing, so a machine converges on a
      # reboot rather than only at first boot. cloud-init's runcmd runs once per
      # *instance*, so a machine built before this existed would never acquire
      # it — and "rebuild every worker" is not a convergence story.
      ExecStartPre=/bin/sh -c 'test -x /usr/local/bin/onv-workloadd || (curl -fsSL -o /usr/local/bin/onv-workloadd.new {core_url}/downloads/onv-workloadd{verify} && chmod 0755 /usr/local/bin/onv-workloadd.new && mv /usr/local/bin/onv-workloadd.new /usr/local/bin/onv-workloadd)'
      Environment=OMNUV_WORKLOAD_ID={worker_id}
      Environment=OMNUV_VLLM_URL=http://127.0.0.1:{port}
      Environment=OMNUV_CACHE_DIR=/opt/onv/hf
      ExecStart=/usr/local/bin/onv-workloadd
      Restart=always
      RestartSec=10s
      # It writes one file and opens no socket, so it is confined rather than
      # trusted: no new privileges, a private tmp, the whole filesystem
      # read-only, and the only writable path the one it reports through. It
      # stays root to read the GPU, which is why the rest has to be true: the
      # comment said this before ProtectSystem made it so, when every path was
      # writable and RuntimeDirectory still named /run/omnuv.
      NoNewPrivileges=yes
      PrivateTmp=yes
      ProtectSystem=strict
      ProtectHome=yes
      RuntimeDirectory=onv
      RuntimeDirectoryPreserve=yes
      ReadWritePaths=/run/onv

      [Install]
      WantedBy=multi-user.target
  - path: /etc/systemd/system/onv-vllm.service
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
      ExecStartPre=-/usr/bin/docker rm -f onv-vllm
      # Reads image and arguments from disk at start, so changing them is a
      # reboot rather than a rebuild that re-downloads the model.
      ExecStart=/usr/local/bin/onv-serve
      ExecStop=/usr/bin/docker stop onv-vllm

      [Install]
      WantedBy=multi-user.target
runcmd:
  - [ systemctl, enable, --now, qemu-guest-agent ]
  - [ bash, -c, "mkdir -p /opt/onv/hf /etc/onv /run/onv" ]
  # The Workload Agent. Statically linked, so it does not care that this guest's
  # glibc is older than the one it was built against. Failure to fetch it is not
  # fatal: it reports, it does not serve, and a worker that cannot describe
  # itself is still a worker that answers requests.
  - [ bash, -c, "curl -fsSL -o /usr/local/bin/onv-workloadd.new {core_url}/downloads/onv-workloadd{verify} && chmod 0755 /usr/local/bin/onv-workloadd.new && mv /usr/local/bin/onv-workloadd.new /usr/local/bin/onv-workloadd || echo 'onv-workloadd unavailable or not the one this agent was built with; continuing without telemetry'" ]
  - [ bash, -c, "command -v /usr/local/bin/onv-workloadd && systemctl enable --now onv-workloadd.service || true" ]
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
  - [ systemctl, enable, onv-vllm.service ]
  # The driver is not loadable until the machine restarts; the service comes up
  # by itself afterwards.
  - [ bash, -c, "systemctl reboot" ]
"#,
        port = spec.port,
        worker_id = spec.id,
        core_url = core_url.trim_end_matches('/'),
        verify = workloadd_check(WORKLOADD_SHA256),
        args_b64 = args_b64,
        image_b64 = base64::engine::general_purpose::STANDARD.encode(&spec.image),
    )
}

/// What a machine is doing while it is not yet serving, in words a person can
/// act on. `Downloading` with a byte count that keeps rising is patience;
/// `Downloading` with a count that stopped is a stall, and the two used to look
/// identical from the host.
fn loading_detail(t: Option<&omnuv_protocol::WorkloadReport>) -> Option<String> {
    let m = t?.model.as_ref()?;
    let gib = |b: u64| format!("{:.1} GiB", b as f64 / (1024.0 * 1024.0 * 1024.0));
    Some(match m.stage {
        omnuv_protocol::ModelStage::Downloading => format!(
            "downloading the model; {} cached, {} since the last check",
            gib(m.cached_bytes),
            gib(m.delta_bytes)
        ),
        omnuv_protocol::ModelStage::Loading => {
            format!("loading {} of weights into the card", gib(m.cached_bytes))
        }
        omnuv_protocol::ModelStage::Loaded => "loaded; waiting to serve".to_string(),
    })
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

    /// The same machine, looked for across **every node of the cluster**.
    ///
    /// **A provider is not a node.** `find_tagged_vm` above asks one node, and
    /// that is what the whole agent used: a machine this agent built on `nuc3`
    /// was invisible to a reconcile pointed at `nuc0`, so it looked like a
    /// machine that had never been created — and converging would have built a
    /// *second* copy while the first kept its card attached. That is the
    /// duplicate the rename guard exists to prevent, reached by another door.
    ///
    /// `/cluster/resources` is the runtime's own answer to *where is this*, and
    /// asking it is one request rather than one per node.
    pub(crate) async fn find_tagged_vm_anywhere(
        &self,
        kind: &str,
        id_tag: &str,
    ) -> anyhow::Result<Option<(String, VmRef)>> {
        #[derive(serde::Deserialize)]
        struct ClusterVm {
            node: String,
            vmid: u32,
            #[serde(default)]
            tags: Option<String>,
            #[serde(default)]
            status: Option<String>,
        }
        let tagged = |tags: Option<&str>| {
            tags.is_some_and(|t| t.split(';').any(|x| x == kind) && t.split(';').any(|x| x == id_tag))
        };
        let vms: Vec<ClusterVm> = self.get_json("/cluster/resources?type=vm").await?;
        if let Some(v) = vms.into_iter().find(|v| tagged(v.tags.as_deref())) {
            return Ok(Some((v.node, VmRef { vmid: v.vmid, tags: v.tags, status: v.status })));
        }

        // **A miss is confirmed before anyone acts on it (PROVIDER-5).** That
        // aggregate is cached, and a miss is the dangerous answer: on create it
        // means "clone another", on delete it means "gone — free the card".
        // Whether its tags can lag a moment behind a clone depends on how
        // fresh Proxmox keeps them, which nobody here has measured; so the
        // absence is asked of every online node's live listing, the same way
        // `reap_unused_segments` asks. A node that cannot be read means the
        // absence cannot be concluded, never that nothing is there. An offline
        // node's guests are still in the aggregate, and nothing is created on
        // an offline node, so its freshness is not the question.
        let nodes: Vec<serde_json::Value> = self.get_json("/nodes").await?;
        for n in nodes.iter().filter(|n| n["status"].as_str() == Some("online")) {
            let Some(node) = n["node"].as_str() else { continue };
            let live: Vec<VmRef> = self.get_json(&format!("/nodes/{node}/qemu")).await.map_err(|e| {
                anyhow::anyhow!("{node} could not be listed, so this machine's absence cannot be concluded: {e}")
            })?;
            if let Some(v) = live.into_iter().find(|v| tagged(v.tags.as_deref())) {
                eprintln!("  the cluster listing missed VM {} on {node}; found live", v.vmid);
                return Ok(Some((node.to_string(), v)));
            }
        }
        Ok(None)
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

    /// **No `node` parameter, deliberately.** It took one and, since this path
    /// began choosing its own node under the allocation gate, ignored it — a
    /// signature that accepts a node it will not use is a lie the next caller
    /// believes. Where a worker goes is the provider's own local placement,
    /// which CLAUDE.md puts behind the driver on purpose.
    pub async fn ensure_inference_worker(
        &self,
        template_vmid: u32,
        storage: &str,
        snippet_dir: &str,
        spec: &InferenceWorkerSpec,
        core_url: &str,
    ) -> anyhow::Result<WorkerStatus> {
        // **Cluster-wide, and under the allocation gate — the same two rules as
        // `ensure_instance`.** This path attaches a card too (`hostpci` below)
        // and had neither: it looked on one node, so a worker on another was
        // rebuilt; and it checked nothing before attaching, so it raced every
        // instance placement for the same hardware. An inference worker and a
        // buyer machine competing for one GPU is the exact case *one physical
        // GPU, at most one active allocation* exists to forbid.
        if let Some((found, vm)) =
            self.find_tagged_vm_anywhere(TAG, &short_tag(&spec.id)).await?
        {
            let node = found.as_str();
            // Live status from the node, not the cached cluster aggregate —
            // the same correction as `ensure_instance`, for the same reason:
            // converging on a stale `stopped` starts a running machine and
            // reports a failure that never happened.
            let vm = match self
                .get_json::<serde_json::Value>(&format!(
                    "/nodes/{node}/qemu/{}/status/current",
                    vm.vmid
                ))
                .await
            {
                Ok(live) => VmRef {
                    status: live.get("status").and_then(|s| s.as_str()).map(str::to_string),
                    ..vm
                },
                Err(_) => vm,
            };
            let mut running = vm.status.as_deref() == Some("running");

            // Converge, do not merely observe: a worker that exists but is not
            // running when Core wants it running must be started on this pass,
            // otherwise a failed first boot leaves it stopped forever.
            if !running && spec.intent == Lifecycle::Running {
                let upid: String = self
                    .post_form(&format!("/nodes/{node}/qemu/{}/status/start", vm.vmid), NO_FORM)
                    .await?;
                self.wait_task(node, &upid).await?;
                running = true;
            }
            if running && spec.intent == Lifecycle::Stopped {
                let upid: String = self
                    .post_form(&format!("/nodes/{node}/qemu/{}/status/shutdown", vm.vmid), NO_FORM)
                    .await?;
                self.wait_task(node, &upid).await?;
                running = false;
            }

            let endpoint = if running { self.worker_endpoint(node, vm.vmid, spec.port).await } else { None };
            // From inside the machine, through the hypervisor. Adds detail to
            // the state below; never decides it. A machine with no Workload
            // Agent, or one still booting, simply reports None.
            let telemetry = if running { self.workload_telemetry(node, vm.vmid).await } else { None };
            // READY must mean "will serve a request", not "has an IP". A VM
            // boots minutes before vLLM finishes loading weights, and routing
            // traffic in that window fails every request.
            let serving = match &endpoint {
                Some(url) => self.worker_serving(url).await,
                None => false,
            };
            let telemetry_ref = telemetry.as_ref();
            return Ok(WorkerStatus {
                id: spec.id.clone(),
                state: worker_state(running, endpoint.is_some(), serving),
                retryable: None,
                waiting_on: None,
                local_id: Some(vm.vmid.to_string()),
                endpoint: serving.then(|| endpoint.clone()).flatten(),
                adapters: self.observed_adapters(node, vm.vmid, None, None).await,
                diagnostics: Some(
                    self.diagnose(node, vm.vmid, serving, Some(endpoint.is_some())).await,
                ),
                message: match (running, endpoint.is_some(), serving) {
                    (true, false, _) => Some("booting; no address yet".into()),
                    // "still loading" was all the host could ever say. The
                    // guest can say which of the three things it is doing, and
                    // roughly how far in, which is the whole point of the tier.
                    (true, true, false) => Some(
                        loading_detail(telemetry_ref)
                            .unwrap_or_else(|| "address up; model still loading".into()),
                    ),
                    // Nothing. This was `vm.name`, so a worker that was serving
                    // perfectly reported `omnuv-worker-dd6161d1` here — and Core
                    // stores this column as `last_error` and the console paints
                    // it in a warning box. A healthy machine sat behind a ⚠ for
                    // a day because a free-looking field was filled in.
                    _ => None,
                },
                telemetry: telemetry.clone(),
            });
        }

        // Snippet must exist before the VM references it.
        let file = crate::names::snippet_worker(&spec.id);
        // 0600: a worker's user data carries its credentials to Core.
        crate::names::write_private(&format!("{snippet_dir}/{file}"), cloud_init(spec, core_url).as_bytes(), 0o600)
            .map_err(|e| anyhow::anyhow!("writing cloud-init snippet: {e}"))?;

        // **Queued and serialized, and every node asked** — the same gate and the
        // same walk as `ensure_instance`, because this path attaches a card and
        // had neither. Held from the feasibility check until the machine exists.
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
            match self.worker_node_can_place(candidate, spec).await {
                Ok(()) => {
                    chosen = Some(candidate.clone());
                    break;
                }
                Err(why) => refused.push(format!("{candidate}: {why}")),
            }
        }
        let Some(node_owned) = chosen else {
            return Err(anyhow::Error::new(crate::instance::Unplaceable {
                waiting_on: "a provider with free capacity",
            })
            .context(format!(
                "insufficient resources on this provider: none of its {} node(s) can place this worker. {}",
                candidates.len(),
                refused.join("; ")
            )));
        };
        let node = node_owned.as_str();

        // **Journalled, claimed first, and rolled back (PROVIDER-2, 22
        // September 2026)**, as an instance's create is (PROVIDER-1). This path
        // had none of the three: an untagged clone was leaked and cloned again
        // on every pass, and a tagged but half-built one was started as it was.
        self.recover_pending(snippet_dir).await;
        let vmid: u32 = self.get_json::<String>("/cluster/nextid").await?.parse()?;
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
                    ("name".to_string(), crate::names::worker(&spec.id)),
                    ("full".to_string(), "1".to_string()),
                    ("storage".to_string(), storage.to_string()),
                    // Into the marketplace's own pool, where the file-read
                    // grant lives. Without it a worker is in no pool at all,
                    // the agent's token has no privilege on it, and its
                    // Workload Agent's report can never be collected — the
                    // reporter runs perfectly and nothing upstream ever sees a
                    // word of it.
                    ("pool".to_string(), crate::join::GATEWAY_POOL.to_string()),
                ],
            )
            .await?;
        pending.upid = Some(upid.clone());
        crate::pending::write(&journal, &pending)?;
        match self.task_end(node, &upid, Self::clone_polls(spec.budget_secs)).await {
            crate::proxmox::TaskEnd::Ended(Ok(())) => {}
            crate::proxmox::TaskEnd::Ended(Err(exit)) => {
                self.abandon_clone(node, vmid, &spec.id, "worker").await;
                crate::pending::remove(&journal, vmid);
                anyhow::bail!("proxmox task failed: {exit}");
            }
            crate::proxmox::TaskEnd::Unknown(why) => {
                anyhow::bail!("the clone of {vmid} has not been seen to finish ({why}); it stays recorded, and the next create settles it");
            }
        }

        // The claim alone, before anything that can fail; everything after it
        // is undone if it fails.
        let finished: anyhow::Result<()> = async {
            self.post_form::<serde_json::Value>(
                &format!("/nodes/{node}/qemu/{vmid}/config"),
                &[("tags".to_string(), crate::names::tags(TAG, &spec.id, self.environment.as_deref()))],
            )
            .await?;

            let mut config: Vec<(String, String)> = vec![
                ("cores".into(), spec.vcpus.to_string()),
                ("memory".into(), spec.memory_mib.to_string()),
                ("cpu".into(), "host".into()),
                // q35 is required for PCIe passthrough.
                ("machine".into(), "q35".into()),
                ("agent".into(), "enabled=1".into()),
                ("ipconfig0".into(), "ip=dhcp".into()),
                ("cicustom".into(), format!("user=onv-snippets:snippets/{file}")),
                ("description".into(), format!("Omnuv inference worker {}\nManaged by onv-provider. Do not edit.", spec.id)),
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
            Ok(())
        }
        .await;
        if let Err(e) = finished {
            self.abandon_clone(node, vmid, &spec.id, "worker").await;
            crate::pending::remove(&journal, vmid);
            return Err(e);
        }
        crate::pending::remove(&journal, vmid);

        Ok(WorkerStatus {
            id: spec.id.clone(),
            state: WorkerState::Deploying,
            retryable: None,
            waiting_on: None,
            local_id: Some(vmid.to_string()),
            endpoint: None,
            // Just created: nothing has been on the network yet to observe,
            // and the hypervisor has nothing to say that the create task did
            // not already say.
            adapters: Vec::new(),
            diagnostics: None,
            message: Some(format!("vm {vmid} created and started")),
            telemetry: None,
        })
    }

    /// **No `node` parameter**, for the reason `ensure_inference_worker` gives:
    /// the worker is wherever it is. This looked only on the node it was
    /// handed and returned `Ok` when it found nothing there, so a worker on
    /// another node of a cluster kept running, and kept its GPU, while the
    /// agent reported it deleted and Core freed the card.
    pub async fn delete_inference_worker(
        &self,
        worker_id: &str,
        snippet_dir: &str,
    ) -> anyhow::Result<()> {
        // **The snippet goes with the worker.** Until 13 September 2026 this
        // function stopped the VM, deleted the VM, and touched no file — so every
        // inference worker ever built left its cloud-init behind, carrying that
        // worker's credentials to Core, in a directory nothing swept.
        //
        // Both generations, because a rename is a migration and the old name is
        // what every existing file is called.
        //
        // Best-effort and first, for the same reason the instance path is: a
        // snippet left behind must never stop a machine being deleted, because a
        // VM that outlives its delete is far worse than a file that does. What
        // makes that safe rather than permanent is `sweep_snippets`, which looks
        // again.
        for name in [
            crate::names::snippet_worker(worker_id),
            crate::names::snippet_worker_legacy(worker_id),
        ] {
            let snippet = format!("{snippet_dir}/{name}");
            if let Err(e) = std::fs::remove_file(&snippet)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                eprintln!("worker {worker_id}: cloud-init snippet not removed: {e}");
            }
        }
        // And what its Workload Agent last said, which is keyed by the same id.
        self.workload.forget(worker_id);

        let Some((node, vm)) = self.find_tagged_vm_anywhere(TAG, &short_tag(worker_id)).await? else {
            return Ok(());
        };
        let node = node.as_str();
        if vm.status.as_deref() == Some("running") {
            let upid: String =
                self.post_form(&format!("/nodes/{node}/qemu/{}/status/stop", vm.vmid), NO_FORM).await?;
            self.wait_task(node, &upid).await?;
        }
        let upid: String = self.delete_task(&format!("/nodes/{node}/qemu/{}", vm.vmid)).await?;
        self.wait_task(node, &upid).await?;
        Ok(())
    }

    /// Reads what the Workload Agent inside the machine last wrote.
    ///
    /// Through `agent/file-read`, which needs only `VM.GuestAgent.FileRead` —
    /// not the unrestricted `exec` privilege. Best-effort by construction: no
    /// guest agent, no file, a half-written file, or an image that predates the
    /// Workload Agent all return None, and None means *not known*, never
    /// *unhealthy*.
    pub(crate) async fn workload_telemetry(
        &self,
        node: &str,
        vmid: u32,
    ) -> Option<omnuv_protocol::WorkloadReport> {
        #[derive(serde::Deserialize)]
        struct FileRead {
            content: String,
        }
        let read: FileRead = self
            .get_json(&format!(
                "/nodes/{node}/qemu/{vmid}/agent/file-read?file={}",
                crate::workload::WORKLOAD_STATUS
            ))
            .await
            .ok()?;
        // **Believed only while it moves (PROVIDER-15).** A Workload Agent
        // that died leaves a well-formed file behind, and it was reported as
        // current on every pass — Core stamped it seen *now*, and frozen
        // numbers read as a healthy idle worker. The store drops a report
        // whose uptime has stopped advancing, so it arrives as unknown.
        self.workload.observe(crate::workload::parse_report(&read.content)?)
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

    /// Every adapter on a machine, and whether the host has seen traffic from
    /// it — see `neighbours` for why the host is a better witness than the
    /// guest.
    ///
    /// The neighbour table is re-read per machine rather than threaded through
    /// the reconcile. It is one small file read against a pass that already
    /// makes several HTTP round trips per machine, so the saving would be
    /// invisible and the signature churn would not.
    pub(crate) async fn observed_adapters(
        &self,
        node: &str,
        vmid: u32,
        believed: Option<&str>,
        believed_mac: Option<&str>,
    ) -> Vec<omnuv_protocol::AdapterStatus> {
        let Ok(cfg) = self.get_json::<serde_json::Value>(&format!("/nodes/{node}/qemu/{vmid}/config")).await
        else {
            return Vec::new();
        };
        crate::neighbours::adapters(&cfg, &crate::neighbours::Neighbours::read(), believed, believed_mac, now_unix())
    }

    /// Everything the hypervisor will say about a marketplace machine.
    ///
    /// Two calls on the healthy path — status and config, and the config is one
    /// the adapter reading already needed — plus the task log only when the
    /// machine is *not* healthy. That last one is the point: the answer to
    /// "what went wrong" usually already exists in the hypervisor's own task
    /// log, and until now nothing carried it upward, so every root-cause
    /// analysis of a failed clone or a refused start began with an ssh.
    pub(crate) async fn diagnose(
        &self,
        node: &str,
        vmid: u32,
        healthy: bool,
        guest_agent_answered: Option<bool>,
    ) -> omnuv_protocol::Diagnostics {
        let current = self
            .get_json::<crate::diagnostics::Current>(&format!(
                "/nodes/{node}/qemu/{vmid}/status/current"
            ))
            .await
            .ok();
        let config =
            self.get_json::<serde_json::Value>(&format!("/nodes/{node}/qemu/{vmid}/config")).await.ok();
        let failure = if healthy {
            None
        } else {
            self.get_json::<Vec<crate::diagnostics::Task>>(&format!(
                "/nodes/{node}/tasks?vmid={vmid}&limit=10&errors=1"
            ))
            .await
            .ok()
            .as_deref()
            .and_then(crate::diagnostics::failure_in)
        };
        crate::diagnostics::build(node, current, config.as_ref(), guest_agent_answered, failure)
    }

    async fn worker_endpoint(&self, node: &str, vmid: u32, port: u16) -> Option<String> {
        self.guest_ipv4(node, vmid).await.map(|ip| format!("http://{ip}:{port}"))
    }
}

pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
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
    crate::names::short_tag(worker_id)
}

#[cfg(test)]
mod tests {

    /// **The worker is deleted where it is.** It runs on n2; the agent is on
    /// n1. The old delete looked only on n1, found nothing, returned Ok and
    /// left the worker running on its card.
    #[tokio::test]
    async fn a_worker_on_another_node_is_stopped_and_deleted_there() {
        use crate::pvemock::{task_ok, Mock};
        let id = "2f8a1c0d-dead-beef-0000-000000000000";
        let tags = format!("{};{}", super::TAG, crate::names::short_tag(id));
        let mock = Mock::start(move |method, path, _| {
            if let Some(r) = task_ok(path) {
                return r;
            }
            match (method, path) {
                ("GET", "/cluster/resources?type=vm") => (200, serde_json::json!([
                    {"node": "n2", "vmid": 321, "tags": tags, "status": "running"}])),
                ("POST", "/nodes/n2/qemu/321/status/stop") => (200, serde_json::json!("UPID:n2:stop")),
                ("DELETE", "/nodes/n2/qemu/321") => (200, serde_json::json!("UPID:n2:del")),
                _ => (404, serde_json::Value::Null),
            }
        })
        .await;
        let dir = std::env::temp_dir().join(format!("onv-wdel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        mock.client().delete_inference_worker(id, dir.to_str().unwrap()).await.expect("delete");
        assert!(mock.called("POST", "/nodes/n2/qemu/321/status/stop"), "the running worker was not stopped");
        assert!(mock.called("DELETE", "/nodes/n2/qemu/321"), "the worker on another node was not deleted");
        std::fs::remove_dir_all(&dir).unwrap();
    }
    use super::*;

    #[test]
    fn args_are_written_at_every_boot_not_baked_into_the_unit() {
        use omnuv_protocol::{InferenceWorkerSpec, Lifecycle};
        let spec = InferenceWorkerSpec {
            id: "w1".into(),
            budget_secs: None,
            intent: Lifecycle::Running,
            image: "vllm/vllm-openai:latest".into(),
            model_repo: "org/model".into(),
            vllm_args: vec!["--model".into(), "org/model".into(), "--max-model-len".into(), "8192".into()],
            vcpus: 8,
            memory_mib: 32768,
            disk_gib: 120,
            gpu_local_ids: vec![],
            gpu_node: None,
            port: 8000,
        };
        let ci = super::cloud_init(&spec, "https://api.example.com/");

        // bootcmd runs on every boot; write_files runs once. The distinction is
        // the whole point: changing a flag must be a reboot, not a rebuild that
        // re-downloads the model.
        assert!(ci.contains("bootcmd:"), "args must be written from bootcmd");
        assert!(ci.contains("/etc/onv/vllm.args"));
        assert!(ci.contains("/etc/onv/vllm.image"));
        // Read into an argv array, not word-split from a string: `$(cat file)`
        // performs no quote removal and bash would brace-expand a value like
        // {"image":0,"video":0} before docker saw it.
        assert!(ci.contains("mapfile -t ARGS < /etc/onv/vllm.args"));
        assert!(ci.contains("\"${ARGS[@]}\""));
        assert!(ci.contains("ExecStart=/usr/local/bin/onv-serve"));
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
        assert_eq!(mapping_name("0000:21:00.0"), "onv-gpu-0000-21-00-0");
        assert_eq!(mapping_name("0000:5d:00.0"), "onv-gpu-0000-5d-00-0");
    }

    #[test]
    fn short_tag_is_stable_and_tag_safe() {
        let t = short_tag("b48aedfb-205d-42fd-a6d3-3deafaeae938");
        assert_eq!(t, "onv-b48aedfb205d");
        assert!(!t.contains('-') || t.starts_with("onv-"));
        assert!(t.len() <= 20);
    }
}

#[cfg(test)]
mod workload_agent_tests {
    use omnuv_protocol::{InferenceWorkerSpec, Lifecycle, ModelProgress, ModelStage, WorkloadHealth, WorkloadReport};

    fn spec() -> InferenceWorkerSpec {
        InferenceWorkerSpec {
            id: "worker_abc".into(),
            intent: Lifecycle::Running,
            image: "vllm/vllm-openai:latest".into(),
            model_repo: "org/model".into(),
            vllm_args: vec!["--model".into(), "org/model".into()],
            vcpus: 8,
            memory_mib: 32768,
            disk_gib: 120,
            gpu_local_ids: vec![],
            gpu_node: None,
            port: 8000,
            budget_secs: None,
        }
    }

    #[test]
    fn the_worker_is_built_with_a_workload_agent() {
        let ci = super::cloud_init(&spec(), "https://api.omnuv.com/");
        assert!(ci.contains("onv-workloadd.service"));
        // Fetched from Core, which already serves /downloads over TLS. The
        // trailing slash must not survive into a doubled one.
        assert!(ci.contains("https://api.omnuv.com/downloads/onv-workloadd"));
        assert!(!ci.contains("omnuv.com//downloads"));
        // It is told which workload it is. Inventing an id would attribute
        // telemetry to a machine that does not exist.
        assert!(ci.contains("OMNUV_WORKLOAD_ID=worker_abc"));
        assert!(ci.contains("OMNUV_VLLM_URL=http://127.0.0.1:8000"));
    }

    /// The download is checked against the digest this agent was built
    /// with, in both places it can happen, and a malformed digest is no check
    /// rather than a broken shell line.
    #[test]
    fn the_workload_agent_download_is_checked_against_the_packaged_digest() {
        let sha = "ab".repeat(32);
        let check = super::workloadd_check(Some(&sha));
        assert_eq!(check, format!(" && echo '{sha}  /usr/local/bin/onv-workloadd.new' | sha256sum -c --quiet -"));
        assert_eq!(super::workloadd_check(None), "");
        assert_eq!(super::workloadd_check(Some("not-a-digest")), "");
        // The check sits between the download and the install, in both paths.
        let ci = super::cloud_init(&spec(), "https://api.omnuv.com");
        for l in ci.lines().filter(|l| l.contains("/downloads/onv-workloadd")) {
            assert!(l.contains("onv-workloadd.new"), "a path installs without staging: {l}");
        }
    }

    /// A worker that cannot fetch the reporter must still become a worker.
    /// Telemetry is detail; serving is the product.
    #[test]
    fn a_missing_workload_agent_does_not_stop_the_worker() {
        let ci = super::cloud_init(&spec(), "https://api.omnuv.com");
        let fetch = ci.lines().find(|l| l.contains("onv-workloadd &&")).expect("fetch line");
        assert!(fetch.contains("||"), "the download must not be able to fail the boot");
    }

    /// It must describe the window *before* vLLM serves — so ordering it after
    /// vLLM would remove the only thing it was built to see.
    #[test]
    fn the_reporter_does_not_wait_for_the_thing_it_reports_on() {
        let ci = super::cloud_init(&spec(), "https://api.omnuv.com");
        let unit = ci
            .split("onv-workloadd.service")
            .nth(1)
            .and_then(|s| s.split("onv-vllm.service").next())
            .unwrap_or("");
        // A directive, not a substring: the unit's own comment says
        // "Deliberately not After=onv-vllm", and a naive contains() finds it.
        assert!(
            !unit.lines().any(|l| l.trim_start().starts_with("After=onv-vllm")),
            "the reporter must start before the thing it reports on"
        );
    }

    fn loading(stage: ModelStage, cached: u64, delta: u64) -> WorkloadReport {
        WorkloadReport {
            workload_id: "w".into(),
            uptime_s: 30,
            health: WorkloadHealth::Starting,
            model: Some(ModelProgress { stage, cached_bytes: cached, delta_bytes: delta }),
            gpus: vec![],
            serving: None,
            observed: vec![],
        }
    }

    /// The host could only ever say "still loading". These are the three
    /// different things that were hiding behind that one sentence, and the
    /// difference between the first two is the difference between waiting and
    /// intervening.
    #[test]
    fn loading_says_which_of_the_three_things_is_happening() {
        let gib = 1024u64 * 1024 * 1024;

        let downloading = super::loading_detail(Some(&loading(ModelStage::Downloading, 6 * gib, gib))).unwrap();
        assert!(downloading.contains("downloading"), "{downloading}");
        assert!(downloading.contains("6.0 GiB"), "{downloading}");

        // Same stage, nothing arriving: a stall, and it must not read the same.
        let stalled = super::loading_detail(Some(&loading(ModelStage::Downloading, 6 * gib, 0))).unwrap();
        assert!(stalled.contains("0.0 GiB since"), "{stalled}");
        assert_ne!(downloading, stalled);

        let into_vram = super::loading_detail(Some(&loading(ModelStage::Loading, 16 * gib, 0))).unwrap();
        assert!(into_vram.contains("into the card"), "{into_vram}");
    }

    #[test]
    fn no_telemetry_means_no_detail_rather_than_a_guess() {
        assert!(super::loading_detail(None).is_none());
        let mut r = loading(ModelStage::Loading, 0, 0);
        r.model = None;
        assert!(super::loading_detail(Some(&r)).is_none());
    }
}

#[cfg(test)]
mod workload_unit_tests {
    use omnuv_protocol::{InferenceWorkerSpec, Lifecycle};

    fn ci() -> String {
        super::cloud_init(
            &InferenceWorkerSpec {
                id: "worker_abc".into(),
                intent: Lifecycle::Running,
                image: "vllm/vllm-openai:latest".into(),
                model_repo: "org/model".into(),
                vllm_args: vec!["--model".into(), "org/model".into()],
                vcpus: 8,
                memory_mib: 32768,
                disk_gib: 120,
                gpu_local_ids: vec![],
                gpu_node: None,
                port: 8000,
                budget_secs: None,
            },
            "https://api.omnuv.com",
        )
    }

    /// cloud-init's runcmd runs once per *instance*, so a machine built before
    /// a feature existed never acquires it — and "rebuild every worker" is not
    /// a convergence story. The unit fetches its own binary when it is absent,
    /// so a reboot is enough.
    #[test]
    fn the_unit_installs_its_own_binary_when_missing() {
        let ci = ci();
        assert!(ci.contains("ExecStartPre="), "no self-install");
        let pre = ci
            .lines()
            .find(|l| l.contains("ExecStartPre="))
            .expect("ExecStartPre");
        assert!(pre.contains("test -x /usr/local/bin/onv-workloadd"), "{pre}");
        assert!(pre.contains("/downloads/onv-workloadd"), "{pre}");
        // Written aside and renamed: overwriting a running binary in place is
        // ETXTBSY, which turns a restart into a permanent failure loop.
        assert!(pre.contains(".new"), "must not overwrite in place: {pre}");
    }

    /// It writes to /usr/local/bin, so DynamicUser cannot work — but it must
    /// still be confined rather than simply trusted.
    #[test]
    fn the_reporter_is_confined() {
        let ci = ci();
        assert!(ci.contains("NoNewPrivileges=yes"));
        assert!(ci.contains("ReadWritePaths=/run/onv"));
        assert!(!ci.contains("DynamicUser=yes"), "cannot install its own binary");
    }
}

impl Client {
    /// Can this node take this **worker**? The instance path's twin.
    ///
    /// Two functions rather than one generic over the spec, because the two
    /// specs are different protocol types and a trait to unify them would be
    /// more machinery than the four lines it saves. They must stay in step:
    /// the shared part is `claimed_pci`, and both refuse on an incomplete view
    /// for the same reason — "I could not look" and "every card is free" must
    /// never be the same answer.
    pub(crate) async fn worker_node_can_place(
        &self,
        node: &str,
        spec: &InferenceWorkerSpec,
    ) -> anyhow::Result<()> {
        if spec.gpu_local_ids.is_empty() {
            return Ok(());
        }
        self.cards_can_be_placed(node, &spec.gpu_local_ids).await
    }
}

#[cfg(test)]
mod a_worker_is_claimed_before_it_can_fail {
    //! PROVIDER-2: a worker's create had no claim-first tag and no rollback,
    //! so an untagged clone was leaked and cloned again on every pass, and a
    //! tagged but half-built one was started as it was.
    use crate::pvemock::{task_ok, Mock};
    use omnuv_protocol::{InferenceWorkerSpec, Lifecycle};

    fn spec() -> InferenceWorkerSpec {
        InferenceWorkerSpec {
            id: "worker_abc".into(),
            intent: Lifecycle::Running,
            image: "vllm/vllm-openai:latest".into(),
            model_repo: "org/model".into(),
            vllm_args: vec!["--model".into(), "org/model".into()],
            vcpus: 8,
            memory_mib: 32768,
            disk_gib: 120,
            gpu_local_ids: vec![],
            gpu_node: None,
            port: 8000,
            budget_secs: None,
        }
    }

    #[tokio::test]
    async fn a_create_that_fails_after_the_clone_removes_the_clone() {
        let mock = Mock::start(|method, path, _| {
            if let Some(r) = task_ok(path) {
                return r;
            }
            match (method, path) {
                ("GET", "/cluster/resources?type=vm") => (200, serde_json::json!([])),
                ("GET", "/nodes") => (200, serde_json::json!([{"node": "n1", "status": "online"}])),
                // A node that holds nothing yet, as the live check asks it (PROVIDER-5).
                ("GET", "/nodes/n1/qemu") => (200, serde_json::json!([])),
                ("GET", "/cluster/nextid") => (200, serde_json::json!("321")),
                ("POST", p) if p.ends_with("/clone") => (200, serde_json::json!("UPID:n1:clone")),
                ("POST", "/nodes/n1/qemu/321/config") => (200, serde_json::Value::Null),
                ("PUT", "/nodes/n1/qemu/321/resize") => (500, serde_json::Value::Null),
                ("POST", "/nodes/n1/qemu/321/status/stop") => (200, serde_json::json!("UPID:n1:stop")),
                ("DELETE", "/nodes/n1/qemu/321") => (200, serde_json::json!("UPID:n1:del")),
                _ => (404, serde_json::Value::Null),
            }
        })
        .await;
        let root = std::env::temp_dir().join(format!("onv-worker-create-{}", std::process::id()));
        let dir = root.join("snippets");
        std::fs::create_dir_all(&dir).unwrap();

        let result = mock
            .client()
            .ensure_inference_worker(9000, "local", dir.to_str().unwrap(), &spec(), "https://api.example.com")
            .await;
        assert!(result.is_err(), "the resize failed and the create reported success");
        assert!(mock.called("DELETE", "/nodes/n1/qemu/321"), "the half-built worker was left to be started");
        let calls = mock.calls.lock().unwrap();
        let first_config = calls.iter().position(|c| c.path == "/nodes/n1/qemu/321/config").expect("configured");
        assert!(calls[first_config].body.starts_with("tags="), "the first write after the clone was not the claim");
        drop(calls);
        assert!(crate::pending::list(&crate::pending::dir(dir.to_str().unwrap())).is_empty());
        std::fs::remove_dir_all(&root).unwrap();
    }
}

#[cfg(test)]
mod a_dead_reporter_is_not_believed {
    //! PROVIDER-15: the staleness store existed, tested, and was never asked.
    use crate::pvemock::Mock;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    /// **Through the read the agent actually makes.** The same file, four
    /// times: believed until its uptime has not moved for three reads, then
    /// reported as unknown. It moves again and is believed again. And a
    /// deleted worker's history goes with it.
    #[tokio::test]
    async fn a_report_whose_uptime_stopped_arrives_as_unknown() {
        let uptime = Arc::new(AtomicU64::new(100));
        let up = uptime.clone();
        let mock = Mock::start(move |_, path, _| {
            if path.starts_with("/nodes/n1/qemu/700/agent/file-read") {
                let report = serde_json::json!({
                    "workload_id": "w1", "uptime_s": up.load(Ordering::SeqCst), "health": "serving",
                    "model": null, "gpus": [], "serving": null, "observed": []
                });
                return (200, serde_json::json!({ "content": report.to_string() }));
            }
            (404, serde_json::Value::Null)
        })
        .await;
        let client = mock.client();
        let read = || client.workload_telemetry("n1", 700);
        assert!(read().await.is_some(), "the first report was not believed");
        assert!(read().await.is_some());
        assert!(read().await.is_some());
        assert!(read().await.is_none(), "a report whose uptime stopped was still believed");
        uptime.store(160, Ordering::SeqCst);
        assert!(read().await.is_some(), "a reporter that moved again was not believed");

        client.workload.forget("w1");
        uptime.store(160, Ordering::SeqCst);
        assert!(read().await.is_some(), "a forgotten worker's history still counted");
    }
}
