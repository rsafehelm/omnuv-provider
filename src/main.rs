mod names;
mod snippets;
mod agent;
mod audit;
mod config;
mod images;
mod instance;
mod join;
mod diagnostics;
mod driver;
mod proxmox;
mod disclosure;
mod sdn;
mod tls;
mod tunnel;
mod console;
mod worker;
mod neighbours;
mod pending;
mod passwords;
mod reboots;
mod survey;
mod workload;
mod poison;
mod session;
mod restore;
mod lease;
mod hosttimer;
mod report;
mod teardown;
mod dur;
mod timings;
mod workload_config;
mod scrub;
#[cfg(test)]
mod pvemock;

const USAGE: &str = "\
onv-provider - Omnuv Provider Agent

USAGE:
    onv-provider join  --core <url> --token <token> [options]
    onv-provider leave [--dry-run] [--without-core] [--config PATH]
    onv-provider agent [--config /etc/onv/agent.yaml] [--secrets PATH]
    onv-provider check-config [--config /etc/onv/agent.yaml] [--secrets PATH]
    onv-provider run-lease-expire [--config /etc/onv/agent.yaml] [--secrets PATH] [--dry-run]
    onv-provider print-config
    onv-provider discover --provider <id> [--config <path>]

CONFIGURATION:
    --secrets defaults to agent-secrets.yaml beside --config: this provider's
    two credentials, mode 0600. `check-config` loads both files as `agent`
    would, prints the hash of the timings in force on stdout and the whole
    configuration, credentials redacted, on stderr; it exits 2 on a file that
    does not pass, naming the key. `print-config` prints the default timings.

    `run-lease-expire` is the host timer (onv-lease-expire.timer, every
    minute): when the agent's lease task is not running, it stops each machine
    in run-lease.json past its run lease, and only stops. `--dry-run` says
    what it would stop. It exits 0 when nothing is wrong, 1 when something was
    not done, and 2 when the file was refused.

JOIN OPTIONS:
    --region <name>       marketplace region                 (default eu-west)
    --cpu <n>             vCPU to sell                       (default 8)
    --memory-gb <n>       memory to sell, GiB                (default 16)
    --disk-gb <n>         storage to sell, GiB               (default 200)
    --storage <id>        Proxmox storage for marketplace disks
    --gpu <pci>           GPU to sell, repeatable (e.g. 0000:21:00.0)
    --dry-run             print every command without running it

`join` runs on your own machine and dials Omnuv outward. Omnuv never connects to
you: no inbound rule, no port forward, no SSH access, no public address. The
Proxmox token it creates stays on this host. It cannot change the host itself
(no Sys.Modify, no Permissions.Modify), and what manages a machine is granted
on the marketplace's two pools, the storage it writes, the card mappings and
the zones it attaches to. At / it holds reads alone, so it cannot start, stop,
change or delete a machine of yours that is outside those pools.

The agent is the real path: it runs on the provider host, keeps runtime
credentials local, and reports inventory and heartbeats to Core. `discover` is
a one-shot debugging command that prints a report instead of sending it.

Prints a normalized InventoryReport as JSON on stdout. Pipe it into core:

    onv-provider discover --provider my-proxmox | \\
        omnuv-core ingest --name my-proxmox --region eu-west

Credentials come from the environment, named by the provider's tokenEnv entry.
";

/// The configuration in force, as the journal shows it at start: the hash every
/// heartbeat carries, then every value with the credentials redacted, and a
/// warning while the credentials are still where `join` used to put them.
fn describe(cfg: &config::AgentConfig) -> String {
    let mut said = format!("configuration {}: {}", cfg.timings.hash(), cfg.effective());
    if cfg.credentials == config::CredentialSource::AgentYaml {
        said.push_str(
            "\nwarning: this provider's credentials are in agent.yaml; they belong in agent-secrets.yaml \
             beside it, mode 0600, which deploy-agent.yml and join now write",
        );
    }
    said
}

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // reqwest needs a process-wide default when built with `rustls-no-provider`.
    // Installing ring explicitly keeps one backend in the binary rather than
    // pulling in a second by accident.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let command = std::env::args().nth(1).unwrap_or_default();

    if command == "join" {
        let need = |name: &str| -> anyhow::Result<String> {
            arg(name).ok_or_else(|| anyhow::anyhow!("{name} is required"))
        };
        let num = |name: &str, default: u64| -> u64 {
            arg(name).and_then(|v| v.parse().ok()).unwrap_or(default)
        };
        let args: Vec<String> = std::env::args().collect();
        let gpus: Vec<String> = args
            .iter()
            .enumerate()
            .filter(|(_, a)| a.as_str() == "--gpu")
            .filter_map(|(i, _)| args.get(i + 1).cloned())
            .collect();

        audit::init(std::env::var("OMNUV_AUDIT_LOG").ok().as_deref());
        return join::run(join::JoinArgs {
            core: need("--core")?,
            token: need("--token")?.into(),
            region: arg("--region").unwrap_or_else(|| "eu-west".into()),
            cpu_cores: num("--cpu", 8) as u32,
            memory_mib: num("--memory-gb", 16) * 1024,
            disk_gib: num("--disk-gb", 200),
            storage: arg("--storage"),
            gpus,
            dry_run: args.iter().any(|a| a == "--dry-run"),
        });
    }

    if command == "leave" {
        let args: Vec<String> = std::env::args().collect();
        let config = arg("--config").unwrap_or_else(|| "/etc/onv/agent.yaml".into());
        return join::leave(
            args.iter().any(|a| a == "--dry-run"),
            args.iter().any(|a| a == "--without-core"),
            &config,
        )
        .await;
    }

    // The defaults of every timing, from this binary: `deploy-agent.yml` writes
    // them out with the inventory's overrides, so the defaults live in one
    // place and the file on the host still carries every key.
    if command == "print-config" {
        #[derive(serde::Serialize)]
        struct Defaults {
            timings: timings::Timings,
        }
        print!("{}", serde_yaml_ng::to_string(&Defaults { timings: timings::Timings::default() })?);
        return Ok(());
    }

    let path = arg("--config").unwrap_or_else(|| "/etc/onv/agent.yaml".into());
    let secrets = arg("--secrets").unwrap_or_else(|| config::secrets_beside(&path));

    // What `deploy-agent.yml` runs on the files it is about to install, before
    // anything restarts. stdout is the result and nothing else — the hash the
    // running agent will report — and stderr is everything a person reads.
    if command == "check-config" {
        match config::load_agent_with(&path, &secrets) {
            Ok(cfg) => {
                eprintln!("{}", describe(&cfg));
                println!("{}", cfg.timings.hash());
                return Ok(());
            }
            Err(e) => {
                eprintln!("check-config: {e:#}");
                std::process::exit(2);
            }
        }
    }

    // **The host timer** (lifecycle phase 12): a separate, minimal entry
    // point, run by onv-lease-expire.timer. No Core, no tunnel, no reconcile:
    // the lease file, its lock, and a stop.
    if command == "run-lease-expire" {
        let dry_run = std::env::args().any(|a| a == "--dry-run");
        std::process::exit(hosttimer::main(&path, &secrets, dry_run).await);
    }

    if command == "agent" {
        // Audit before anything else, so even a failed start is on the record.
        // It came after the config load until 24 September 2026, so the one
        // failure this line promises to record, a bad configuration, never was.
        audit::init(std::env::var("OMNUV_AUDIT_LOG").ok().as_deref());
        let cfg = match config::load_agent_with(&path, &secrets) {
            Ok(cfg) => cfg,
            Err(e) => {
                // The reason goes to the journal with the returned error, not
                // here: a parser's message can quote a value, and a token in
                // the wrong field would then sit in the audit file.
                audit::record("agent.start", "agent", &path, "failed", Some("the configuration could not be loaded"));
                return Err(e);
            }
        };
        audit::set_backlog(cfg.timings.audit_backlog as usize);
        eprintln!("onv-provider agent starting (config {path})");
        eprintln!("{}", describe(&cfg));
        eprintln!("audit log policy: {}", audit::REDACTION_POLICY);
        return agent::run(cfg).await;
    }

    if command != "discover" {
        eprint!("{USAGE}");
        std::process::exit(2);
    }

    let path = arg("--config").unwrap_or_else(|| "config/development.providers.local.yaml".into());
    let targets = config::load(&path)?;

    let Some(id) = arg("--provider") else {
        eprintln!("--provider is required. Available targets in {path}:");
        for t in &targets {
            eprintln!("  {:<12} {:<28} {}", t.id, t.api_url, if t.enabled { "enabled" } else { "disabled" });
        }
        std::process::exit(2);
    };

    let target = config::select(&targets, &id)?;
    eprintln!("discovering {} ({})", target.name(), target.api_url);

    let client = proxmox::Client::connect(target)?;
    let report = client.discover(target.node.as_deref(), &target.contribute).await?;

    eprintln!(
        "  {} node(s), {} vCPU, {} GiB RAM, {} GiB disk, {} GPU(s)",
        report.nodes.len(),
        report.total_cpu_cores(),
        report.total_memory_mib() / 1024,
        report.total_disk_gib(),
        report.gpu_count()
    );

    // The report deliberately carries no name or region: those are marketplace
    // concepts, not things a provider gets to declare about itself. The dev
    // inventory knows them, so print the command rather than making the
    // operator retype them.
    eprintln!(
        "  pipe into core with: --name \"{}\" --region {}",
        target.name(),
        target.region
    );

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
