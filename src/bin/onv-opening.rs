//! `onv-opening`, the provider opening's applier (omnuv's modular design,
//! A3): run as root by onv-opening.service, at boot and whenever the agent
//! rewrites its ports. It links `onv_hostnet` and nothing of the agent, and
//! holds no credential: it reads agent.yaml's `opening` block and
//! `proxmox.snippetDir`, and the ports in opening.json, and never Core's
//! token or Proxmox's. One nft transaction, or no table.

const USAGE: &str = "\
onv-opening - the Omnuv provider opening's applier

USAGE:
    onv-opening [--config /etc/onv/agent.yaml] [--state PATH] [--print]

Run as root by onv-opening.service, woken when the agent's opening.json
changes: it reads the `opening` block of --config and the ports the agent
gave, never a credential, and replaces nftables table inet onv_opening whole,
or removes it when the opening is off or anything cannot be trusted. It exits
0 when the kernel holds what the files say, 1 when it fell back to no table,
and 2 when the configuration was refused. `--print` shows the rules and
changes nothing. The opening is off unless the inventory's onv_opening turns
it on; deploy-agent.yml writes it, never a hand edit.
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return;
    }
    let mut config = "/etc/onv/agent.yaml".to_string();
    let mut state = None;
    let mut print = false;
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--print" => print = true,
            "--config" | "--state" => {
                let Some(v) = it.next() else {
                    eprintln!("onv-opening: {a} needs a path");
                    std::process::exit(2);
                };
                if a == "--config" { config = v } else { state = Some(v) }
            }
            other => {
                eprint!("onv-opening: unknown argument {other:?}\n\n{USAGE}");
                std::process::exit(2);
            }
        }
    }
    std::process::exit(onv_hostnet::opening::apply_main(&config, state.as_deref(), print));
}
