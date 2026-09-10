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

## Building

```bash
cargo build --release
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
