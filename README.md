# omnuv-provider

The **Omnuv Provider Agent**: marketplace-owned software that runs inside a
provider's own environment, reconciles that provider's runtime toward the state
Omnuv asks for, and reports back what is actually true.

It is open source for one reason. This program can create virtual machines,
attach your GPUs, configure your networking and read your inventory, on your
hardware. You should be able to read it before you run it, and you should not
have to take anyone's word for what it does.

## What it does, and what it refuses to do

```text
authenticate as this provider          report normalized inventory
receive normalized desired state       reconcile the runtime toward it
report what is actually running        maintain an audit log you own
```

Three refusals are as important as the work:

- **It never listens.** Every connection is outbound, to Core. Nothing needs an
  inbound firewall rule on your hypervisor.
- **Your hypervisor credentials never leave the machine.** The agent holds a
  restricted, least-privilege token locally; Core is told normalized inventory
  and is never told how to reach your hypervisor.
- **While Core is unreachable it maintains and does not decide.** It restarts a
  machine that was meant to be running and has crashed, and creates or destroys
  nothing, because the instructions in hand are stale and may be wrong.

## What it tells Omnuv about your own guests

You contribute a slice of your host (`contribute` in `agent.yaml`) and keep the
rest for yourself. Omnuv sells the slice, less whatever of it your own guests
are using. So every inventory report says how far your guests reach into the
slice, and nothing about them beyond that:

```text
committed = what your guests use beyond (host total − the slice), at most the slice
```

- **vCPU and memory** count your running and paused guests, VMs and containers,
  at their configured size. A stopped guest holds neither, and is counted on
  the next report after you start it.
- **Disk** counts every guest's volumes on the storages you contribute, running
  or not. Space already written is outside the free space the agent reports,
  so what is counted is only size that can still grow into the slice.
- **How many guests you have** is sent as a count. Never a name, an id or a
  configuration.

If your guests stay inside what you kept, the three figures are zero and the
whole slice is sold. The agent records each figure it sends in your audit log as
`host.usage.disclosed`, once, and again whenever it changes.

This is not optional. A node that does not report it sells nothing (Omnuv's
decision D10), because a slice nobody can check is one that may already be
full. For the same reason, a report that could not read every guest sends no
figure at all rather than a partial one. The last figure stands for two of
Omnuv's polls; after that the node stops selling until a complete report
arrives. The inventory is reported at least twice per poll, so one failed read
costs nothing.

## The audit log

`/var/log/omnuv/audit.log`, append-only JSON lines, written before an action is
attempted and again with its outcome, so an action that crashed halfway still
leaves a trace. It records what was asked, of which resource, by whom, when,
and how it ended.

It never records API tokens, your hypervisor credential, cloud-init contents, or
buyer request and response bodies. A tenant's payload passing through your
machine must not be written to your disk by us.

A bounded subset travels up to Core so the marketplace can show you the same
record in its own console. Your copy stays authoritative for you.

## Runtimes

Proxmox VE is the reference implementation and the one in production. The driver
layer exists so that K3s with KubeVirt, OpenStack and others fit behind the same
contract without the marketplace learning anything about them.

## Installing

```bash
sudo apt install ./onv-provider_<version>_amd64.deb
sudo onv-provider join --core <https://your-core> --token <your enrolment token>
```

The package installs the binary, a systemd unit and an unprivileged service
account. It **does not** require Proxmox, or any other hypervisor: the driver
layer exists so that a second runtime can arrive, and a package that checks for
one at install time cannot be installed on a provider running something else.
What kind of host this is, is a question for `join`, not for the packager.

Your configuration is not a packaged file. `join` writes it, which means an
upgrade can never ask you what to do about a file you did not edit.

It is two files. `/etc/onv/agent.yaml` holds everything but the two
credentials, including a `timings` section with every interval, timeout and
limit the agent keeps (`onv-provider print-config` prints their defaults).
`/etc/onv/agent-secrets.yaml`, mode 0600, holds the credentials alone, and the
agent refuses one anybody but its owner can read. After an edit,
`onv-provider check-config` loads both as the agent would, prints the hash the
agent will report with every heartbeat, and names any key it refuses; a change
takes effect when the service restarts. An `agent.yaml` from before the split,
credentials inside, still loads, with a warning.

Removing the package takes away the software. Purging takes the configuration
too. Neither touches `/var/log/omnuv`: that is your record of what this
marketplace did on your hardware, and it is not ours to delete.

## Building

```bash
cargo build --release            # the agent
./packaging/build-deb.sh 0.1.0   # the package, in a container
```

The wire contract lives in a separate crate,
[omnuv-protocol](https://github.com/rsafehelm/omnuv-protocol), which both this
agent and the marketplace depend on. Neither imports the other's source.

## Licence

GNU General Public License, version 3 or later.

Copyleft rather than permissive, deliberately. This program runs on hardware you
own and can create machines, attach your GPUs and configure your networking on
it. If somebody ships you a modified build of it, you should be able to read
what they changed, for exactly the reason you can read this one.
