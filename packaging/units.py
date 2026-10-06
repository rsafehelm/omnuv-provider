#!/usr/bin/env python3
"""The package's units hold their sandboxing (omnuv's modular design, A3).

    packaging/units.py <root>        the units under <root>/lib/systemd/system
    packaging/units.py --self-test   the checker, against units that break it

Every unit's sandbox was copied by hand and nothing asserted one, so a line
lost in an edit was a privilege regained in silence. This reads each service
the package installs, from the extracted package, and holds it to the table
below, the way systemd applies it rather than the way it reads:

    a later line wins          ProtectSystem=no after ProtectSystem=strict,
                               User=root after User=onv
    an empty line resets       InaccessiblePaths= empties the list before it
    list lines merge           a second CapabilityBoundingSet= or
                               ReadWritePaths= widens the first

So a key the table requires must appear **exactly once**, with the value
given: a second line of it, an empty reset included, fails. A key the table
neither requires nor names as free fails too, so a new directive is decided
in the change that adds it. Credential and ambient-capability keys are
refused by prefix, so LoadCredentialEncrypted= and SetCredentialEncrypted=
are refused with the plain forms. A drop-in directory in the package fails:
it would apply after the unit and is read by nothing here.

Each of the three host binaries holds only its own credential:

    onv-provider      the agent: agent-secrets.yaml, read by itself. Never the
                      host timer's token
    onv-lease-expire  its own Proxmox token, through LoadCredential=. Never the
                      agent's file, Core's token among it
    onv-opening       root, two capabilities, and no credential at all: both
                      files out of its view, CAP_DAC_READ_SEARCH or not

Not covered: a drop-in an operator writes under /etc/systemd/system on the
host. That is the host's configuration, not the package's.

`--self-test` drops each required line, appends a second line of each
required key (empty, and with another value), adds each forbidden key and an
unknown one, and every such unit must fail; the units as written must pass,
and so must one whose free key is changed.
"""

import pathlib
import shutil
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

# Keys refused by prefix wherever the table does not require them: any form of
# a credential handed in by systemd, and a capability raised for a non-root
# user.
CREDENTIAL_PREFIXES = ["LoadCredential", "SetCredential", "ImportCredential", "AmbientCapabilities"]

UNITS = {
    "onv-provider.service": {
        "binary": "onv-provider",
        "require": COMMON + [
            "ExecStart=/usr/bin/onv-provider agent --config /etc/onv/agent.yaml",
            "User=onv",
            "Group=onv",
            "ProtectKernelTunables=yes",
            "ReadWritePaths=/var/lib/onv /var/log/onv",
            f"InaccessiblePaths=-{LEASE_SECRETS}",
            "UMask=0027",
            # A4's supervision (tests/supervision_units.rs asserts the why).
            "Restart=always",
            "RestartPreventExitStatus=3",
            "MemoryMax=1G",
        ],
        "free": ["Type", "RestartSec", "TimeoutStopSec", "StateDirectory"],
        "forbid_prefix": CREDENTIAL_PREFIXES,
    },
    "onv-lease-expire.service": {
        "binary": "onv-lease-expire",
        "require": COMMON + [
            "ExecStart=/usr/bin/onv-lease-expire --config /etc/onv/agent.yaml",
            "User=onv",
            "Group=onv",
            f"LoadCredential=lease:{LEASE_SECRETS}",
            f"InaccessiblePaths=-{AGENT_SECRETS}",
            "ReadWritePaths=/var/lib/onv /var/log/onv",
            "UMask=0027",
            "CapabilityBoundingSet=",
            "ProtectKernelTunables=yes",
            "ProtectKernelModules=yes",
            "ProtectKernelLogs=yes",
            "ProtectClock=yes",
            "RestrictNamespaces=yes",
            "RestrictRealtime=yes",
            "SystemCallArchitectures=native",
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK",
        ],
        "free": ["Type", "TimeoutStartSec"],
        # Its token and nothing else: the LoadCredential line above, once.
        "forbid_prefix": CREDENTIAL_PREFIXES,
    },
    "onv-opening.service": {
        "binary": "onv-opening",
        "require": COMMON + [
            "ExecStart=/usr/bin/onv-opening --config /etc/onv/agent.yaml",
            "CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH",
            f"InaccessiblePaths=-{AGENT_SECRETS} -{LEASE_SECRETS}",
            "RestrictAddressFamilies=AF_NETLINK AF_UNIX AF_INET",
        ],
        "free": ["Type", "TimeoutStartSec"],
        "forbid_prefix": CREDENTIAL_PREFIXES,
    },
}


def key_of(line):
    return line.split("=", 1)[0].strip()


def service_lines(text):
    """The [Service] section's settings, in order, comments dropped."""
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


def check_unit(name, want, lines):
    bad = []
    required = {}
    for line in want["require"]:
        required.setdefault(key_of(line), []).append(line)
    for key, wanted in required.items():
        held = [l for l in lines if key_of(l) == key]
        if len(wanted) != 1:
            raise SystemExit(f"units.py: {name} requires {key} twice in its table")
        if held != wanted:
            if not held:
                bad.append(f"{name}: lacks {wanted[0]!r}")
            elif len(held) > 1:
                bad.append(f"{name}: holds {len(held)} {key} lines {held!r}; exactly {wanted[0]!r} is required, "
                           "since a later line overrides, resets or widens it")
            else:
                bad.append(f"{name}: holds {held[0]!r}, not {wanted[0]!r}")
    free = set(want.get("free", []))
    for line in lines:
        key = key_of(line)
        if key in required:
            continue
        if any(key.startswith(p) for p in want.get("forbid_prefix", [])):
            bad.append(f"{name}: holds {line!r}, which it must not")
        elif key not in free:
            bad.append(f"{name}: holds {line!r}, a key this check does not know; require it or name it free in UNITS")
    for key in free:
        n = sum(1 for l in lines if key_of(l) == key)
        if n > 1:
            bad.append(f"{name}: holds {n} {key} lines; one is the most it may hold")
    return bad


def check(root):
    """Every failure under `root`, in words; empty when every unit passes."""
    root = pathlib.Path(root)
    units = root / "lib/systemd/system"
    bad = []
    for p in sorted(units.iterdir()) if units.is_dir() else []:
        if p.is_dir():
            bad.append(f"{p.name}: a drop-in directory in the package; it would override the units checked here")
        elif p.suffix == ".service" and p.name not in UNITS:
            bad.append(f"{p.name}: a service this check does not know; give it a sandbox in UNITS")
    for name, want in UNITS.items():
        path = units / name
        if not path.is_file():
            bad.append(f"{name}: not in the package")
            continue
        bad += check_unit(name, want, service_lines(path.read_text()))
        binary = root / "usr/bin" / want["binary"]
        if not binary.is_file():
            bad.append(f"{name}: runs /usr/bin/{want['binary']}, which the package does not hold")
    return bad


def append_to_service(text, line):
    """`line` as the last setting of [Service], where systemd applies it last."""
    out, inside, done = [], False, False
    for raw in text.splitlines():
        s = raw.strip()
        if s.startswith("[") and s.endswith("]"):
            if inside and not done:
                out.append(line)
                done = True
            inside = s == "[Service]"
        out.append(raw)
    if inside and not done:
        out.append(line)
        done = True
    assert done, "no [Service] section"
    return "\n".join(out) + "\n"


# The overrides measured to pass the line-presence check this replaced, each
# appended as the unit's last [Service] line (review of wp/A3).
OVERRIDES = {
    "onv-lease-expire.service": [
        "ProtectSystem=no",
        "CapabilityBoundingSet=CAP_SYS_ADMIN",
        "User=root",
        "ReadWritePaths=/etc",
        f"LoadCredentialEncrypted=agent:{AGENT_SECRETS}",
    ],
    "onv-opening.service": [
        "InaccessiblePaths=",
        "User=root",
        f"LoadCredentialEncrypted=lease:{LEASE_SECRETS}",
    ],
    "onv-provider.service": [
        "InaccessiblePaths=",
        f"LoadCredentialEncrypted=lease:{LEASE_SECRETS}",
        f"SetCredentialEncrypted=lease:{LEASE_SECRETS}",
        "ReadWritePaths=/etc",
    ],
}


def self_test(here):
    """The units as written pass; each one broken by one line fails."""
    source = pathlib.Path(here).parent / "deb/lib/systemd/system"
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)

        def build(edit=None):
            if (tmp / "root").exists():
                shutil.rmtree(tmp / "root")
            units = tmp / "root/lib/systemd/system"
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

        def must_fail(what, edit):
            nonlocal cases
            cases += 1
            if not check(build(edit)):
                failures.append(f"{what} passed")

        def appended(name, line):
            def edit(units):
                p = units / name
                p.write_text(append_to_service(p.read_text(), line))
            return edit

        for name, want in UNITS.items():
            for line in want["require"]:
                def drop(units, name=name, line=line):
                    p = units / name
                    p.write_text("\n".join(l for l in p.read_text().splitlines() if l.strip() != line) + "\n")
                must_fail(f"{name} without {line!r}", drop)
                key = key_of(line)
                must_fail(f"{name} with {key}= (a reset) appended", appended(name, f"{key}="))
                must_fail(f"{name} with {key}=onv-other appended", appended(name, f"{key}=onv-other"))
            for prefix in want["forbid_prefix"]:
                for form in (prefix, prefix + "Encrypted"):
                    must_fail(f"{name} with an added {form} line", appended(name, f"{form}=x:{AGENT_SECRETS}"))
            for line in OVERRIDES.get(name, []):
                must_fail(f"{name} with {line!r} appended", appended(name, line))
            must_fail(f"{name} with an unknown ExecStartPre", appended(name, "ExecStartPre=/bin/sh -c true"))
            for key in want.get("free", []):
                must_fail(f"{name} with a second {key} line", appended(name, f"{key}=onv-other"))

            def no_binary(units, want=want):
                (units.parent.parent.parent / "usr/bin" / want["binary"]).unlink()
            must_fail(f"{name} with /usr/bin/{want['binary']} absent", no_binary)

            # The nearest thing it must accept: a free key's value changed.
            def retimed(units, name=name, want=want):
                p = units / name
                key = want["free"][-1]
                text = "\n".join(f"{key}=onv-other" if key_of(l.strip()) == key else l
                                 for l in p.read_text().splitlines()) + "\n"
                p.write_text(text)
            said = check(build(retimed))
            if said:
                failures.append(f"{name} with its free key changed fails: {said}")

        def stray(units):
            (units / "onv-stray.service").write_text("[Service]\nExecStart=/bin/true\n")
        must_fail("an unknown service", stray)

        def dropin(units):
            (units / "onv-provider.service.d").mkdir()
            (units / "onv-provider.service.d/x.conf").write_text("[Service]\nUser=root\n")
        must_fail("a drop-in directory", dropin)
    return cases, failures


def main(argv):
    if argv[1:] == ["--self-test"]:
        cases, failures = self_test(__file__)
        for f in failures:
            print(f"units self-test: {f}", file=sys.stderr)
        if failures:
            return 1
        print(f"units self-test: the units pass, a changed free key passes, and each of {cases} broken copies fails")
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
