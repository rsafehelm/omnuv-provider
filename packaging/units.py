#!/usr/bin/env python3
"""The package's units hold their sandboxing (omnuv's modular design, A3).

    packaging/units.py <root>        the units under <root>/lib/systemd/system
    packaging/units.py --self-test   the checker, against units that break it

Every unit's sandbox was copied by hand and nothing asserted one, so a line
lost in an edit was a privilege regained in silence. This reads each service
the package installs, from the extracted package, and holds it to the table
below: the lines it must carry, the lines it must not, and the binary its
ExecStart names, which must be in the package.

Each of the three host binaries holds only its own credential:

    onv-provider      the agent: agent-secrets.yaml, read by itself. Never the
                      host timer's token
    onv-lease-expire  its own Proxmox token, through LoadCredential=. Never the
                      agent's file, Core's token among it
    onv-opening       root, two capabilities, and no credential at all: both
                      files out of its view, CAP_DAC_READ_SEARCH or not

A unit the table does not name fails the check: a new unit is held to a
sandbox in the change that adds it. `--self-test` drops each required line and
adds each forbidden one, one at a time, and every such unit must fail; the
units as written must pass.
"""

import pathlib
import sys
import tempfile

# Every service, whatever it does.
COMMON = [
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "PrivateTmp=yes",
    "PrivateDevices=yes",
    "ProtectControlGroups=yes",
    "RestrictSUIDSGID=yes",
    "LockPersonality=yes",
]

AGENT_SECRETS = "/etc/onv/agent-secrets.yaml"
LEASE_SECRETS = "/etc/onv/lease-secrets.yaml"

UNITS = {
    "onv-provider.service": {
        "binary": "onv-provider",
        "require": COMMON + [
            "ExecStart=/usr/bin/onv-provider agent --config /etc/onv/agent.yaml",
            "User=onv",
            "Group=onv",
            "ProtectKernelTunables=yes",
            f"InaccessiblePaths=-{LEASE_SECRETS}",
        ],
        "forbid_prefix": ["LoadCredential", "SetCredential", "ImportCredential", "AmbientCapabilities"],
    },
    "onv-lease-expire.service": {
        "binary": "onv-lease-expire",
        "require": COMMON + [
            "ExecStart=/usr/bin/onv-lease-expire --config /etc/onv/agent.yaml",
            "User=onv",
            "Group=onv",
            f"LoadCredential=lease:{LEASE_SECRETS}",
            f"InaccessiblePaths=-{AGENT_SECRETS}",
            "CapabilityBoundingSet=",
            "ProtectKernelTunables=yes",
            "ProtectKernelModules=yes",
            "RestrictNamespaces=yes",
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK",
        ],
        # Its token and nothing else: one LoadCredential line, the one above.
        "only_one": ["LoadCredential"],
        "forbid_prefix": ["SetCredential", "ImportCredential", "AmbientCapabilities"],
    },
    "onv-opening.service": {
        "binary": "onv-opening",
        "require": COMMON + [
            "ExecStart=/usr/bin/onv-opening --config /etc/onv/agent.yaml",
            "CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH",
            f"InaccessiblePaths=-{AGENT_SECRETS} -{LEASE_SECRETS}",
            "RestrictAddressFamilies=AF_NETLINK AF_UNIX AF_INET",
        ],
        "forbid_prefix": ["LoadCredential", "SetCredential", "ImportCredential", "AmbientCapabilities"],
    },
}


def service_lines(text):
    """The [Service] section's settings, as written, comments dropped."""
    out, section = [], None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line
            continue
        if section == "[Service]":
            out.append(line)
    return out


def check(root):
    """Every failure under `root`, in words; empty when every unit passes."""
    root = pathlib.Path(root)
    units = root / "lib/systemd/system"
    bad = []
    found = sorted(p.name for p in units.glob("*.service"))
    for name in found:
        if name not in UNITS:
            bad.append(f"{name}: a service this check does not know; give it a sandbox in UNITS")
    for name, want in UNITS.items():
        path = units / name
        if not path.is_file():
            bad.append(f"{name}: not in the package")
            continue
        lines = service_lines(path.read_text())
        for line in want["require"]:
            if line not in lines:
                bad.append(f"{name}: lacks {line!r}")
        for line in lines:
            key = line.split("=", 1)[0]
            if key in want.get("forbid_prefix", []):
                bad.append(f"{name}: holds {line!r}, which it must not")
        for key in want.get("only_one", []):
            n = sum(1 for line in lines if line.split("=", 1)[0] == key)
            if n != 1:
                bad.append(f"{name}: holds {n} {key} lines, not one")
        binary = root / "usr/bin" / want["binary"]
        if not binary.is_file():
            bad.append(f"{name}: runs /usr/bin/{want['binary']}, which the package does not hold")
    return bad


def self_test(here):
    """The units as written pass; each one broken by one line fails."""
    source = pathlib.Path(here).parent / "deb/lib/systemd/system"
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)

        def build(edit=None):
            units = tmp / "root/lib/systemd/system"
            if (tmp / "root").exists():
                import shutil
                shutil.rmtree(tmp / "root")
            units.mkdir(parents=True)
            (tmp / "root/usr/bin").mkdir(parents=True)
            for want in UNITS.values():
                (tmp / "root/usr/bin" / want["binary"]).write_text("")
            for p in source.iterdir():
                (units / p.name).write_text(p.read_text())
            if edit:
                edit(units)
            return tmp / "root"

        said = check(build())
        if said:
            failures.append(f"the units as written fail: {said}")
        cases = 0
        for name, want in UNITS.items():
            for line in want["require"]:
                def drop(units, name=name, line=line):
                    p = units / name
                    p.write_text("\n".join(l for l in p.read_text().splitlines() if l.strip() != line) + "\n")
                cases += 1
                if not check(build(drop)):
                    failures.append(f"{name} without {line!r} passed")
            for key in want.get("forbid_prefix", []) + want.get("only_one", []):
                def add(units, name=name, key=key):
                    p = units / name
                    p.write_text(p.read_text().replace("[Service]\n", f"[Service]\n{key}=x:/etc/onv/agent-secrets.yaml\n"))
                cases += 1
                if not check(build(add)):
                    failures.append(f"{name} with an added {key} line passed")

            def no_binary(units, want=want):
                (units.parent.parent.parent / "usr/bin" / want["binary"]).unlink()
            cases += 1
            if not check(build(no_binary)):
                failures.append(f"{name} passed with /usr/bin/{want['binary']} absent")

        def stray(units):
            (units / "onv-stray.service").write_text("[Service]\nExecStart=/bin/true\n")
        cases += 1
        if not check(build(stray)):
            failures.append("an unknown service passed")
    return cases, failures


def main(argv):
    if argv[1:] == ["--self-test"]:
        cases, failures = self_test(__file__)
        for f in failures:
            print(f"units self-test: {f}", file=sys.stderr)
        if failures:
            return 1
        print(f"units self-test: the units pass, and each of {cases} broken copies fails")
        return 0
    if len(argv) != 2:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    bad = check(argv[1])
    for b in bad:
        print(f"units: {b}", file=sys.stderr)
    if bad:
        return 1
    print(f"units: {len(UNITS)} services hold their sandboxing, and each runs a binary the package holds")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
