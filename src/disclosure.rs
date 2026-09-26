//! **Honest disclosure** (lifecycle phase 11, decision D10): what the owner's
//! own guests take out of the slice this provider contributes.
//!
//! Core sells a node's reported capacity less `committed_*` less what it has
//! already sold, and sells nothing on a node whose disclosure is missing or
//! older than two polls. So `committed_*` must be the part of the owner's use
//! that falls *inside* the contributed slice. The whole host's own guests,
//! which is what the agent measured until 26 September 2026, exceed the slice
//! on both production hosts and would have made both unsellable.
//!
//! **What `committed_*` means now.** The owner contributes a slice and keeps
//! the rest of the host — `host total − reported` — for their own guests.
//! What those guests use beyond that is the intrusion, and the intrusion is
//! what is disclosed, never more than the slice itself:
//!
//! ```text
//! committed = min(reported, max(0, owner's use − (host total − reported)))
//! ```
//!
//! `reported` is the capacity the node reports, which is the contribution
//! already clamped to what is physically there. Which of the owner's guests
//! count, per resource (the allocation report, Part I §5.2, §5.8, gap 4b):
//!
//! ```text
//! vCPU     running and paused guests, VMs and containers: the hypervisor's own
//!          count, so a container with no core limit counts every host thread
//! memory   running and paused guests, VMs and containers: their configured
//!          maximum. A stopped guest has no process and holds none (§5.7); the
//!          pass after its owner starts it discloses it
//! disk     every guest, running or stopped, templates included, on the
//!          storages this node contributes: a stopped guest holds its disks
//! ```
//!
//! **Disk's host total is the contributed storages' total, and `reported` is
//! already free space** (`min(contributed, avail)`). So an owner's disk that
//! is already written is outside `reported` before this is worked out, and
//! the formula counts only what the free-space figure cannot see: configured
//! size not yet written, on a sparse pool, that can still grow into the slice.
//! On a thick pool it discloses zero, correctly, and never counts a disk twice.
//!
//! **Always on.** Disclosure is a condition of selling (D10), so it is not a
//! toggle; what it reveals is the owner's intrusion into their own offer, not
//! what they run, which is zero whenever the owner stays inside what they
//! kept. `guests` is still a count of the owner's guests, never an identity.
//!
//! **An incomplete survey discloses nothing.** One guest that cannot be read
//! — its listing, its configuration, its power state, a running guest's size —
//! and the node reports no commitment at all, so Core stops selling it after
//! two polls rather than reading "could not look" as "nothing there".

use std::collections::BTreeMap;

/// The owner's own guests on one node, as the hypervisor has configured them:
/// every VM and container the marketplace did not create. Raw, and never sent:
/// what leaves this process is `commitment`'s answer.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct OwnerUse {
    /// vCPUs of the running guests, as the hypervisor counts them.
    pub(crate) running_cores: u64,
    /// Configured memory of the running guests, in MiB.
    pub(crate) running_memory_mib: u64,
    /// Configured disk of every guest, running or stopped, per storage id, in GiB.
    pub(crate) disk_gib: BTreeMap<String, u64>,
    /// VMs, templates and containers, running or not.
    pub(crate) guests: u32,
}

/// One node's figures, as `discover` measured them.
pub(crate) struct Node {
    /// The host's threads, memory in MiB, and the total of the storages this
    /// node contributes, in GiB.
    pub(crate) host: (u64, u64, u64),
    /// What the node reports: the contribution clamped to what is there.
    pub(crate) reported: (u64, u64, u64),
}

impl OwnerUse {
    /// One guest of the owner's. `cpus` and `maxmem` are the hypervisor's own
    /// listing, which applies its defaults (a memory size a config leaves out,
    /// a container without a core limit); the disks come from `config`.
    pub(crate) fn observe(
        &mut self,
        status: Option<&str>,
        cpus: Option<&serde_json::Value>,
        maxmem: Option<&serde_json::Value>,
        config: &serde_json::Value,
    ) -> anyhow::Result<()> {
        let config = config.as_object().ok_or_else(|| anyhow::anyhow!("the configuration is not an object"))?;
        let running = match status {
            // Paused holds its memory, and resumes without asking anybody.
            Some("running" | "paused") => true,
            Some("stopped") => false,
            _ => anyhow::bail!("the power state is unobserved"),
        };
        if running {
            let cpus = cpus.and_then(number).filter(|c| c.is_finite() && *c >= 0.0)
                .ok_or_else(|| anyhow::anyhow!("a running guest's vCPUs are not listed"))?;
            let bytes = maxmem.and_then(number).filter(|m| m.is_finite() && *m >= 0.0)
                .ok_or_else(|| anyhow::anyhow!("a running guest's memory is not listed"))?;
            // Up, both: a fraction of a core or of a MiB is still taken.
            self.running_cores += cpus.ceil() as u64;
            self.running_memory_mib += (bytes / (1024.0 * 1024.0)).ceil() as u64;
        }
        for (storage, gib) in volumes(config) {
            *self.disk_gib.entry(storage.to_string()).or_default() += gib;
        }
        self.guests += 1;
        Ok(())
    }

    pub(crate) fn add(&mut self, other: OwnerUse) {
        self.running_cores += other.running_cores;
        self.running_memory_mib += other.running_memory_mib;
        for (storage, gib) in other.disk_gib {
            *self.disk_gib.entry(storage).or_default() += gib;
        }
        self.guests += other.guests;
    }
}

/// What a node discloses: the part of its owner's use inside the slice it
/// reports. `storages` are the ids it contributes — the owner's disks on any
/// other storage never touch the slice.
pub(crate) fn commitment(owner: &OwnerUse, node: &Node, storages: &[&str]) -> omnuv_protocol::HostCommitment {
    let disk: u64 = owner.disk_gib.iter().filter(|(s, _)| storages.contains(&s.as_str())).map(|(_, g)| g).sum();
    omnuv_protocol::HostCommitment {
        // The slice is a `u32` of cores, and the intrusion is never more.
        cpu_cores: intrusion(owner.running_cores, node.host.0, node.reported.0) as u32,
        memory_mib: intrusion(owner.running_memory_mib, node.host.1, node.reported.1),
        disk_gib: intrusion(disk, node.host.2, node.reported.2),
        guests: owner.guests,
    }
}

/// The part of `owner` that falls inside `reported`: whatever exceeds the room
/// the owner kept, `host − reported`, and never more than the slice itself.
pub(crate) fn intrusion(owner: u64, host: u64, reported: u64) -> u64 {
    owner.saturating_sub(host.saturating_sub(reported)).min(reported)
}

/// Every volume a guest's configuration gives a storage and a size: a VM's
/// disks on its four buses, a container's root and mount points. A bind mount,
/// a passed-through device and an empty drive have no `storage:volume`, and
/// are nobody's disk here.
fn volumes(config: &serde_json::Map<String, serde_json::Value>) -> Vec<(&str, u64)> {
    const NUMBERED: [&str; 5] = ["scsi", "virtio", "sata", "ide", "mp"];
    config
        .iter()
        .filter(|(k, _)| {
            k.as_str() == "rootfs"
                || NUMBERED.iter().any(|b| k.strip_prefix(b).is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit())))
        })
        .filter_map(|(_, v)| {
            let raw = v.as_str()?;
            let (storage, _) = raw.split(',').next()?.split_once(':')?;
            if storage.is_empty() || storage.starts_with('/') {
                return None;
            }
            Some((storage, crate::proxmox::size_gib(raw)?))
        })
        .collect()
}

/// Proxmox writes numbers as numbers or as strings, and `cpus` may be a
/// fraction for a container with a CPU limit.
fn number(v: &serde_json::Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str()?.trim().parse().ok())
}

/// Record, on the provider's own side, what was disclosed about this node.
///
/// The party giving something up should be able to see that they did, in
/// their own journal, without asking the marketplace; `audit::record` also
/// sends it up with the report, so neither side can quietly lose it. Once per
/// node, and again whenever the figure changes: disclosure is permanent now,
/// so the hourly reminder that it was switched on has nothing left to remind.
///
/// It records what was sent and nothing more — never the whole host's figures,
/// which do not leave this process.
pub(crate) fn noted(node: &str, c: &omnuv_protocol::HostCommitment) {
    use std::sync::Mutex;
    static LAST: Mutex<BTreeMap<String, omnuv_protocol::HostCommitment>> = Mutex::new(BTreeMap::new());

    let mut last = match LAST.lock() {
        Ok(l) => l,
        Err(e) => e.into_inner(),
    };
    if last.get(node) == Some(c) {
        return;
    }
    last.insert(node.to_string(), *c);
    crate::audit::record(
        "host.usage.disclosed",
        "agent",
        node,
        "ok",
        Some(&format!(
            "disclosed {} vCPU, {} MiB and {} GiB of this host's own use inside the slice it contributes \
             ({} guest(s) of its own)",
            c.cpu_cores, c.memory_mib, c.disk_gib, c.guests
        )),
    );
}

#[cfg(test)]
mod arithmetic {
    use super::*;
    use serde_json::json;

    /// The formula, at its three edges: inside the room the owner kept, past
    /// it, and past the whole slice.
    #[test]
    fn only_what_passes_the_room_the_owner_kept_is_an_intrusion() {
        // Titan's memory: 257024 MiB, 65536 of it offered.
        assert_eq!(intrusion(159_744, 257_024, 65_536), 0, "156 GiB fits in the 187 kept");
        assert_eq!(intrusion(191_488, 257_024, 65_536), 0, "exactly the room kept is not an intrusion");
        assert_eq!(intrusion(196_608, 257_024, 65_536), 5_120);
        assert_eq!(intrusion(400_000, 257_024, 65_536), 65_536, "never more than the slice");
        // A contribution larger than the host: it reports the host, the owner
        // kept nothing, and every running guest of theirs is inside the slice.
        assert_eq!(intrusion(10, 12, 12), 10);
        // Nothing reported, nothing to intrude on.
        assert_eq!(intrusion(10, 0, 0), 0);
    }

    /// **A disk already written is already outside the free-space figure**,
    /// so it is not counted a second time. What is counted is configured size
    /// that can still grow into the slice.
    #[test]
    fn a_written_disk_is_not_counted_twice_and_a_sparse_one_is_counted_once() {
        let owner = |gib| OwnerUse { disk_gib: BTreeMap::from([("pool".to_string(), gib)]), ..Default::default() };
        // Thick: 1000 GiB pool, 800 of it the owner's and written, 200 free.
        // The node reports 200 of the 500 offered; the owner's 800 is exactly
        // what lies outside it.
        let thick = Node { host: (0, 0, 1000), reported: (0, 0, 200) };
        assert_eq!(commitment(&owner(800), &thick, &["pool"]).disk_gib, 0);
        // Sparse: the same 800 configured and 100 of it written, so 900 free
        // and the node reports its whole 500. At full size the owner leaves
        // 200 of the pool, so 300 of the slice is theirs.
        let sparse = Node { host: (0, 0, 1000), reported: (0, 0, 500) };
        assert_eq!(commitment(&owner(800), &sparse, &["pool"]).disk_gib, 300);
        // And a pool this node does not offer is not in the sum at all.
        assert_eq!(commitment(&owner(800), &sparse, &["other"]).disk_gib, 0);
    }

    #[test]
    fn a_stopped_guest_holds_its_disks_and_nothing_else() {
        let mut o = OwnerUse::default();
        let config = json!({"memory": 131072, "scsi0": "tank:vm-1-disk-0,size=100G"});
        o.observe(Some("stopped"), Some(&json!(64)), Some(&json!(128u64 << 30)), &config).unwrap();
        assert_eq!((o.running_cores, o.running_memory_mib, o.guests), (0, 0, 1));
        assert_eq!(o.disk_gib, BTreeMap::from([("tank".to_string(), 100)]));
        o.observe(Some("paused"), Some(&json!(2)), Some(&json!(4u64 << 30)), &json!({})).unwrap();
        assert_eq!((o.running_cores, o.running_memory_mib), (2, 4096), "paused holds its memory");
    }

    /// A container's limit may be a fraction of a core, and Proxmox may quote
    /// any number. Up, never down: half a core is still taken.
    #[test]
    fn listed_sizes_are_read_quoted_or_not_and_rounded_up() {
        let mut o = OwnerUse::default();
        o.observe(Some("running"), Some(&json!("1.5")), Some(&json!("1073741825")), &json!({})).unwrap();
        assert_eq!((o.running_cores, o.running_memory_mib), (2, 1025));
    }

    #[test]
    fn a_guest_that_cannot_be_sized_is_refused_rather_than_read_as_zero() {
        let mut o = OwnerUse::default();
        assert!(o.observe(Some("running"), None, Some(&json!(1)), &json!({})).is_err());
        assert!(o.observe(Some("running"), Some(&json!(1)), None, &json!({})).is_err());
        assert!(o.observe(Some("running"), Some(&json!("many")), Some(&json!(1)), &json!({})).is_err());
        assert!(o.observe(Some("prelaunch"), Some(&json!(1)), Some(&json!(1)), &json!({})).is_err());
        assert!(o.observe(None, Some(&json!(1)), Some(&json!(1)), &json!({})).is_err());
        assert!(o.observe(Some("stopped"), None, None, &json!("not an object")).is_err());
        assert_eq!(o, OwnerUse::default(), "a refused guest left a partial count behind");
    }

    /// Positive and negative: every kind of volume a guest can be given a size
    /// on, and the nearest things that are not one.
    #[test]
    fn a_volume_is_a_storage_and_a_size() {
        let config = json!({
            "scsi0": "tank:vm-100-disk-0,iothread=1,size=32G",
            "virtio1": "tank:vm-100-disk-1,size=1T",
            "sata2": "other:vm-100-disk-2,size=10G",
            "ide3": "tank:vm-100-disk-3,size=512M",
            "rootfs": "tank:subvol-200-disk-0,size=8G",
            "mp0": "tank:subvol-200-disk-1,mp=/data,size=100G",
            // Not volumes, or not ones with a storage and a size.
            "ide2": "none,media=cdrom",
            "ide1": "local:iso/ubuntu.iso,media=cdrom",
            "mp1": "/srv/shared,mp=/shared",
            "scsi5": "/dev/disk/by-id/ata-DISK,size=100G",
            "scsi6": "/dev/disk/by-path/pci-0000:00:17.0-ata-1,size=100G",
            "unused0": "tank:vm-100-disk-9",
            "scsihw": "virtio-scsi-pci",
            "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0",
            "mpx": "tank:x,size=1G",
        });
        let mut got = volumes(config.as_object().unwrap());
        got.sort();
        assert_eq!(got, vec![("other", 10), ("tank", 0), ("tank", 8), ("tank", 32), ("tank", 100), ("tank", 1024)]);
    }
}

#[cfg(test)]
mod tests {
    //! Fixtures, not hardware. The hosts' shapes are `docs/assets.md`'s
    //! reading of 21 September 2026 — threads, memory, which guests exist, how
    //! much memory each has and whether it runs — and the contributions are
    //! `inventories/prod/hosts.yml`'s. What assets.md does not record is
    //! invented and marked so: most guests' vCPU counts, every disk size but
    //! the two boot disks it names, and the storages' totals.

    use omnuv_protocol::NodeInventory;
    use serde_json::{json, Value};
    use std::collections::HashSet;

    const GIB: u64 = 1024 * 1024 * 1024;

    #[derive(Clone)]
    struct Guest {
        vmid: u32,
        running: bool,
        cpus: u64,
        memory_gib: u64,
        /// Config lines of its volumes, `(key, value)`.
        volumes: Vec<(&'static str, &'static str)>,
        template: bool,
        tags: Option<&'static str>,
        /// The listing leaves `maxmem` out.
        memory_unlisted: bool,
    }

    fn guest(vmid: u32, running: bool, cpus: u64, memory_gib: u64, volumes: &[(&'static str, &'static str)]) -> Guest {
        Guest {
            vmid,
            running,
            cpus,
            memory_gib,
            volumes: volumes.to_vec(),
            template: false,
            tags: None,
            memory_unlisted: false,
        }
    }

    impl Guest {
        fn listing(&self) -> Value {
            let mut v = json!({
                "vmid": self.vmid,
                "status": if self.running { "running" } else { "stopped" },
                "cpus": self.cpus,
                "template": u8::from(self.template),
            });
            if !self.memory_unlisted {
                v["maxmem"] = json!(self.memory_gib * GIB);
            }
            if let Some(t) = self.tags {
                v["tags"] = json!(t);
            }
            v
        }

        fn config(&self) -> Value {
            let mut v = json!({"memory": self.memory_gib * 1024, "cores": self.cpus, "sockets": 1});
            for (k, val) in &self.volumes {
                v[*k] = json!(val);
            }
            v
        }
    }

    #[derive(Clone)]
    struct Host {
        node: &'static str,
        maxcpu: u64,
        maxmem_gib: u64,
        storages: Value,
        vms: Vec<Guest>,
        containers: Vec<Guest>,
        /// Paths answered with a server error.
        broken: HashSet<&'static str>,
    }

    impl Host {
        fn route(self) -> impl Fn(&str, &str, &str) -> (u16, Value) + Send + Sync + 'static {
            move |method, path, _| {
                if method != "GET" {
                    return (405, Value::Null);
                }
                if self.broken.contains(path) {
                    return (500, Value::Null);
                }
                let node = self.node;
                let find = |list: &[Guest], rest: &str| -> Option<Value> {
                    let vmid: u32 = rest.strip_suffix("/config")?.parse().ok()?;
                    list.iter().find(|g| g.vmid == vmid).map(Guest::config)
                };
                if path == "/nodes" {
                    return (200, json!([{"node": node, "status": "online",
                                         "maxcpu": self.maxcpu, "maxmem": self.maxmem_gib * GIB}]));
                }
                if path == "/cluster/mapping/pci" || path == "/cluster/sdn/zones" {
                    return (200, json!([]));
                }
                let Some(rest) = path.strip_prefix(&format!("/nodes/{node}/")) else {
                    return (404, Value::Null);
                };
                match rest {
                    "storage" => (200, self.storages.clone()),
                    "hardware/pci" => (200, json!([])),
                    "qemu" => (200, Value::Array(self.vms.iter().map(Guest::listing).collect())),
                    "lxc" => (200, Value::Array(self.containers.iter().map(Guest::listing).collect())),
                    _ => {
                        let found = rest.strip_prefix("qemu/").and_then(|r| find(&self.vms, r))
                            .or_else(|| rest.strip_prefix("lxc/").and_then(|r| find(&self.containers, r)));
                        match found {
                            Some(config) => (200, config),
                            None => (404, Value::Null),
                        }
                    }
                }
            }
        }
    }

    /// Titan: 128 threads and 251 GiB, contributing 16 vCPU, 64 GiB and
    /// 500 GiB of `zfs-fast`. Its guests' memory and power states are
    /// assets.md's: 128 + 16 + 12 + 16 + 12 GiB, 184 GiB in all, of which
    /// 156 GiB runs. Atlas's and vwindows-mon's vCPUs are invented (32 and 4);
    /// 9100's 16 and 9101's 8 are the plays'. `zfs-fast` is sparse (the
    /// macOS play says so), and its 7000 GiB total is invented.
    fn titan() -> Host {
        let template = Guest { template: true, ..guest(9000, false, 2, 2, &[("scsi0", "zfs-fast:base-9000-disk-0,size=4G"),
                                                                       ("ide2", "zfs-fast:vm-9000-cloudinit,media=cdrom")]) };
        Host {
            node: "Titan",
            maxcpu: 128,
            maxmem_gib: 251,
            storages: json!([
                {"storage": "zfs-fast", "type": "zfspool", "content": "images,rootdir", "active": 1,
                 "total": 7000 * GIB, "avail": 4700 * GIB, "used": 2300 * GIB},
                // An image storage this provider does not contribute: nothing
                // on it touches the slice.
                {"storage": "local-lvm", "type": "lvmthin", "content": "images,rootdir", "active": 1,
                 "total": 400 * GIB, "avail": 300 * GIB, "used": 100 * GIB},
                {"storage": "local", "type": "dir", "content": "iso,vztmpl,backup", "active": 1,
                 "total": 100 * GIB, "avail": 50 * GIB, "used": 50 * GIB},
            ]),
            vms: vec![
                // 3848 GB, which assets.md gives as its boot disk.
                guest(100, true, 32, 128, &[("scsi0", "zfs-fast:vm-100-disk-0,iothread=1,size=3584G")]),
                guest(101, false, 4, 16, &[("sata0", "zfs-fast:vm-101-disk-0,size=120G")]),
                template,
                guest(9100, true, 16, 12, &[("sata0", "zfs-fast:vm-9100-disk-0,size=256G")]),
                guest(9101, true, 8, 16, &[("virtio0", "zfs-fast:vm-9101-disk-1,size=256G"),
                                           ("scsi1", "local-lvm:vm-9101-disk-2,size=64G")]),
                guest(9102, false, 16, 12, &[("sata0", "zfs-fast:vm-9102-disk-0,size=128G")]),
            ],
            containers: Vec::new(),
            broken: HashSet::new(),
        }
    }

    fn titan_contributes() -> crate::config::Contribution {
        crate::config::Contribution {
            cpu_cores: 16,
            memory_mib: 65536,
            disk_gib: 500,
            storage: vec!["zfs-fast".into()],
            ..Default::default()
        }
    }

    /// Pluto: 128 threads and 251 GiB, contributing 64 vCPU, 96 GiB and
    /// 800 GiB of `local-zfs`. Its three guests — 128, 64 and 128 GiB, 320 in
    /// all — are stopped, as assets.md read them; their vCPUs, the templates'
    /// sizes and the storage's totals are invented.
    fn pluto() -> Host {
        let template = |vmid, gib: &'static str| Guest { template: true, ..guest(vmid, false, 4, 4, &[("scsi0", gib)]) };
        Host {
            node: "Pluto",
            maxcpu: 128,
            maxmem_gib: 251,
            storages: json!([
                {"storage": "local-zfs", "type": "zfspool", "content": "images,rootdir", "active": 1,
                 "total": 7000 * GIB, "avail": 2000 * GIB, "used": 5000 * GIB},
            ]),
            vms: vec![
                // 2750 GB and 1024 GB, assets.md's.
                guest(100, false, 64, 128, &[("scsi0", "local-zfs:vm-100-disk-0,size=2561G")]),
                guest(101, false, 16, 64, &[("sata0", "local-zfs:vm-101-disk-0,size=953G")]),
                guest(102, false, 32, 128, &[("scsi0", "local-zfs:vm-102-disk-0,size=953G")]),
                template(9000, "local-zfs:base-9000-disk-0,size=4G"),
                template(9001, "local-zfs:base-9001-disk-0,size=16G"),
                template(9002, "local-zfs:base-9002-disk-0,size=64G"),
            ],
            containers: Vec::new(),
            broken: HashSet::new(),
        }
    }

    fn pluto_contributes() -> crate::config::Contribution {
        crate::config::Contribution {
            cpu_cores: 64,
            memory_mib: 98304,
            disk_gib: 800,
            storage: vec!["local-zfs".into()],
            ..Default::default()
        }
    }

    async fn report(host: Host, contribution: &crate::config::Contribution) -> NodeInventory {
        let node = host.node;
        let mock = crate::pvemock::Mock::start(host.route()).await;
        let mut report = mock.client().discover(Some(node), contribution).await.expect("the fake host answers");
        assert_eq!(report.nodes.len(), 1);
        report.nodes.remove(0)
    }

    /// What Core may still sell on the node before anything of its own:
    /// capacity less `committed_*`, as `provider_node_free` computes it. Signed,
    /// so a commitment larger than the slice reads as the negative it is
    /// rather than as a panic. `None` is a node that did not disclose.
    fn sellable(n: &NodeInventory) -> Option<(i64, i64, i64)> {
        let c = n.committed?;
        Some((
            i64::from(n.cpu_cores) - i64::from(c.cpu_cores),
            n.memory_mib as i64 - c.memory_mib as i64,
            n.disk_gib as i64 - c.disk_gib as i64,
        ))
    }

    /// **A host whose own guests stay outside the slice sells all of it.**
    ///
    /// Titan's guests hold 184 GiB against a 64 GiB slice and Pluto's 320 GiB
    /// against 96, which is what the whole-host count reported. Titan's running
    /// 156 GiB fits in the 187 GiB its owner kept, and Pluto runs nothing; so
    /// neither intrudes, both disclose — zero, and how many guests — and both
    /// sell every vCPU, MiB and GiB they contribute.
    #[tokio::test]
    async fn a_host_whose_own_guests_fit_outside_the_slice_sells_all_of_it() {
        let titan = report(titan(), &titan_contributes()).await;
        assert_eq!((titan.cpu_cores, titan.memory_mib, titan.disk_gib), (16, 65536, 500));
        assert_eq!(
            titan.committed.map(|c| (c.cpu_cores, c.memory_mib, c.disk_gib, c.guests)),
            Some((0, 0, 0, 6)),
            "Titan disclosed {:?}",
            titan.committed
        );
        assert_eq!(sellable(&titan), Some((16, 65536, 500)));

        let pluto = report(pluto(), &pluto_contributes()).await;
        assert_eq!((pluto.cpu_cores, pluto.memory_mib, pluto.disk_gib), (64, 98304, 800));
        assert_eq!(
            pluto.committed.map(|c| (c.cpu_cores, c.memory_mib, c.disk_gib, c.guests)),
            Some((0, 0, 0, 6)),
            "Pluto disclosed {:?}",
            pluto.committed
        );
        assert_eq!(sellable(&pluto), Some((64, 98304, 800)));
    }

    /// **An owner whose running guests reach into the slice sells less, by
    /// exactly as much as they reach.**
    ///
    /// Titan with everything of its own started, and a container besides: a
    /// running one with 40 cores, 8 GiB and a 2200 GiB root disk, and a stopped
    /// one whose 8 GiB disk counts while its memory does not.
    ///
    /// ```text
    ///            owner kept           running / configured    intrudes   sells
    /// vCPU       128 − 16 = 112       32+4+16+8+16+40 = 116          4      12
    /// MiB        257024 − 65536       192 GiB = 196608            5120   60416
    ///              = 191488
    /// GiB disk   7000 − 500 = 6500    4348 + 2200 + 8 = 6556         56     444
    /// ```
    ///
    /// A bind mount has no storage and no size, so it is nobody's disk here.
    #[tokio::test]
    async fn an_owner_reaching_into_the_slice_takes_exactly_that_much_out_of_it() {
        let mut host = titan();
        for g in host.vms.iter_mut().filter(|g| !g.template) {
            g.running = true;
        }
        host.containers = vec![
            guest(200, true, 40, 8, &[("rootfs", "zfs-fast:subvol-200-disk-0,size=2200G"),
                                      ("mp0", "/srv/shared,mp=/shared")]),
            guest(201, false, 2, 4, &[("rootfs", "zfs-fast:subvol-201-disk-0,size=8G")]),
        ];
        let titan = report(host, &titan_contributes()).await;
        assert_eq!(
            titan.committed.map(|c| (c.cpu_cores, c.memory_mib, c.disk_gib, c.guests)),
            Some((4, 5120, 56, 8)),
            "disclosed {:?}",
            titan.committed
        );
        assert_eq!(sellable(&titan), Some((12, 60416, 444)));
    }

    /// **A survey that could not see every guest discloses nothing.** An
    /// unmeasured commitment must never read as zero, and Core reads a missing
    /// one as a node that sells nothing once two polls pass.
    ///
    /// Proved first against a host that *does* disclose, so this cannot pass
    /// by never disclosing at all; and a failure that is not a guest's — the
    /// PCI mappings, which only the cards need — still discloses.
    #[tokio::test]
    async fn a_survey_that_could_not_see_every_guest_discloses_nothing() {
        let with_container = || {
            let mut h = titan();
            h.containers = vec![guest(200, true, 4, 4, &[("rootfs", "zfs-fast:subvol-200-disk-0,size=8G")])];
            h
        };
        assert!(report(with_container(), &titan_contributes()).await.committed.is_some(),
                "the control: a host whose every guest was read must disclose");

        let blinded = |path: &'static str| {
            let mut h = with_container();
            h.broken.insert(path);
            h
        };
        for (why, host) in [
            ("the VM listing failed", blinded("/nodes/Titan/qemu")),
            ("one VM's configuration failed", blinded("/nodes/Titan/qemu/101/config")),
            ("the container listing failed", blinded("/nodes/Titan/lxc")),
            ("one container's configuration failed", blinded("/nodes/Titan/lxc/200/config")),
            ("a running guest's memory was not listed", {
                let mut h = with_container();
                h.vms[0].memory_unlisted = true;
                h
            }),
        ] {
            let n = report(host, &titan_contributes()).await;
            assert_eq!(n.committed, None, "{why}, and it still disclosed");
            assert_eq!((n.cpu_cores, n.memory_mib), (16, 65536), "{why}: the node itself is still reported");
        }

        let n = report(blinded("/cluster/mapping/pci"), &titan_contributes()).await;
        assert!(n.committed.is_some(), "the PCI mappings are the cards' business, not the guests'");
    }
}
