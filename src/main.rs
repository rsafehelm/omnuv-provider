mod agent;
mod audit;
mod config;
mod gateway;
mod instance;
mod join;
mod driver;
mod proxmox;
mod sdn;
mod tls;
mod tunnel;
mod console;
mod worker;

const USAGE: &str = "\
omnu-provider - Omnu Provider Agent

USAGE:
    omnu-provider join  --core <url> --token <token> [options]
    omnu-provider leave [--dry-run]
    omnu-provider agent [--config /etc/omnu/agent.yaml]
    omnu-provider discover --provider <id> [--config <path>]

JOIN OPTIONS:
    --region <name>       marketplace region                 (default eu-west)
    --cpu <n>             vCPU to sell                       (default 8)
    --memory-gb <n>       memory to sell, GiB                (default 16)
    --disk-gb <n>         storage to sell, GiB               (default 200)
    --storage <id>        Proxmox storage for marketplace disks
    --gpu <pci>           GPU to sell, repeatable (e.g. 0000:21:00.0)
    --dry-run             print every command without running it

`join` runs on your own machine and dials Omnu outward. Omnu never connects to
you: no inbound rule, no port forward, no SSH access, no public address. The
Proxmox token it creates is restricted and stays on this host.

The agent is the real path: it runs on the provider host, keeps runtime
credentials local, and reports inventory and heartbeats to Core. `discover` is
a one-shot debugging command that prints a report instead of sending it.

Prints a normalized InventoryReport as JSON on stdout. Pipe it into core:

    omnu-provider discover --provider pve-titan | \\
        omnu-core ingest --name Titan --region eu-west

Credentials come from the environment, named by the provider's tokenEnv entry.
";

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

        audit::init(std::env::var("OMNU_AUDIT_LOG").ok().as_deref());
        return join::run(join::JoinArgs {
            core: need("--core")?,
            token: need("--token")?,
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
        return join::leave(std::env::args().any(|a| a == "--dry-run"));
    }

    if command == "agent" {
        let path = arg("--config").unwrap_or_else(|| "/etc/omnu/agent.yaml".into());
        let cfg = config::load_agent(&path)?;
        // Audit before anything else, so even a failed start is on the record.
        audit::init(std::env::var("OMNU_AUDIT_LOG").ok().as_deref());
        eprintln!("omnu-provider agent starting (config {path})");
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
