//! **Honest disclosure** (lifecycle phase 11, decision D10): what the owner's
//! own guests take out of the slice this provider contributes.
//!
//! Core sells a node's reported capacity less `committed_*` less what it has
//! already sold, and sells nothing on a node whose disclosure is missing or
//! older than two polls. So `committed_*` must be the part of the owner's use
//! that falls *inside* the contributed slice. The whole host's own guests,
//! which is what the agent measured until now, exceed the slice on both
//! production hosts and would have made both unsellable.

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
