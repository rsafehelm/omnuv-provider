#!/usr/bin/env python3
"""The package version moves with what the package is built from, and only
with that (omnuv's modular design, A5).

    tests/packaging/version_test.py <dep-info>...

Given the dep-info files a release build wrote (build-deb.sh's four), this
copies the tree's files, tracked and untracked, to a scratch root and asks
packaging/version.py for the version as each one thing changes:

    kept    a file under tests/ edited, one added; a #[cfg(test)] module's
            own file (src/agent_goldens.rs) edited
    moved   a source file the agent is compiled from, a unit file, a
            maintainer script, Cargo.lock, a crate's Cargo.toml, README.md
    refused an input the dep-info names that the tree lacks

The dep-info parser is held to a fixture, not a build: an escaped space, a
continuation line, a registry path and a generated file under target/, which
no real build here produced.
"""

import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.dont_write_bytecode = True  # no __pycache__ left in packaging/
sys.path.insert(0, str(REPO / "packaging"))
import version  # noqa: E402

failed = 0


def check(what: str, cond: bool, detail: str = "") -> None:
    global failed
    print(("ok    " if cond else "FAIL  ") + what + ("" if cond else f": {detail}"))
    if not cond:
        failed += 1


def tree_copy(dst: pathlib.Path) -> None:
    out = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        check=True, capture_output=True).stdout
    for rel in filter(None, out.decode().split("\0")):
        src = REPO / rel
        if src.is_file():
            (dst / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst / rel)


def run_version(root: pathlib.Path, depinfos: list[pathlib.Path]) -> tuple[int, str]:
    p = subprocess.run([sys.executable, str(REPO / "packaging/version.py"), str(root), *map(str, depinfos)],
                       capture_output=True, text=True)
    return p.returncode, (p.stdout if p.returncode == 0 else p.stderr).strip()


def main(argv: list[str]) -> None:
    depinfos = [pathlib.Path(a).resolve() for a in argv]
    if not depinfos:
        sys.exit(__doc__.split("\n\n")[1])

    # The parser, on a fixture.
    fixture = ("/w/target/release/onv-x: /w/src/a\\ b.rs /w/src/c.rs \\\n"
               " /usr/local/cargo/registry/src/x/lib.rs /w/target/release/build/y/out/gen.rs\n"
               "\n/w/src/a\\ b.rs:\n")
    paths = version.dep_paths(fixture)
    check("the parser unescapes a space and joins a continued line",
          "/w/src/a b.rs" in paths and "/w/src/c.rs" in paths and "/usr/local/cargo/registry/src/x/lib.rs" in paths,
          repr(paths))
    with tempfile.TemporaryDirectory() as t:
        root = pathlib.Path(t)
        for rel in ["src/a b.rs", "src/c.rs", "Cargo.lock", "Cargo.toml", "packaging/build-deb.sh",
                    "README.md", "LICENSE", "packaging/deb/DEBIAN/postinst"]:
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(rel)
        d = root / "fixture.d"
        d.write_text(fixture)
        listed = version.inputs(root, [d])
        check("a registry path and a generated file under target/ are not inputs",
              "src/a b.rs" in listed and not any(r.startswith("target/") or r.startswith("/") for r in listed),
              repr(listed))

    with tempfile.TemporaryDirectory() as t:
        root = pathlib.Path(t)
        tree_copy(root)
        rc, base = run_version(root, depinfos)
        check("the copied tree has a version", rc == 0 and "+c" in base, base)
        if rc != 0:
            sys.exit(1)
        rc, real = run_version(REPO, depinfos)
        check("the copy's version is the tree's", rc == 0 and real == base, f"{real} against {base}")
        crate = version.crate_version(root)
        check("the version is <crate>+c<12 hex>",
              base.startswith(crate + "+c") and len(base) == len(crate) + 14
              and all(ch in "0123456789abcdef" for ch in base[len(crate) + 2:]), base)
        listed = version.inputs(root, depinfos)
        check("nothing under tests/ is an input", not any(r.startswith("tests/") for r in listed),
              ", ".join(r for r in listed if r.startswith("tests/")))
        check("onv-opening's source and unit are inputs",
              "src/bin/onv-opening.rs" in listed and "packaging/deb/lib/systemd/system/onv-opening.service" in listed)

        def edited(rel: str, kept: bool, what: str) -> None:
            f = root / rel
            before = f.read_bytes() if f.exists() else None
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes((before or b"") + b"\n// a change for version_test.py\n")
            rc, v = run_version(root, depinfos)
            if kept:
                check(f"{what} keeps the version", rc == 0 and v == base, f"{v} against {base}")
            else:
                check(f"{what} moves the version", rc == 0 and v != base, f"{v}")
            if before is None:
                f.unlink()
            else:
                f.write_bytes(before)

        test_file = next(r for r in sorted((root / "tests").rglob("*.rs")))
        edited(test_file.relative_to(root).as_posix(), True, f"an edit to {test_file.relative_to(root)}")
        edited("tests/version_test_added.rs", True, "a new file under tests/")
        if (root / "src/agent_goldens.rs").exists() and "src/agent_goldens.rs" not in listed:
            edited("src/agent_goldens.rs", True, "an edit to a #[cfg(test)] module's file (src/agent_goldens.rs)")
        else:
            check("src/agent_goldens.rs is a test module's file and no input", False, "it is listed, or gone")
        for rel, what in [
            ("src/bin/onv-opening.rs", "an edit to onv-opening's source"),
            ("src/agent.rs", "an edit to the agent's source"),
            ("crates/onv-hostnet/src/lib.rs", "an edit to a crate the binaries link"),
            ("packaging/deb/lib/systemd/system/onv-opening.service", "an edit to a unit file"),
            ("packaging/deb/DEBIAN/postinst", "an edit to the postinst"),
            ("Cargo.lock", "an edit to Cargo.lock"),
            ("crates/onv-opening-free/Cargo.toml", "a new crate's Cargo.toml"),
            ("README.md", "an edit to the shipped README"),
        ]:
            edited(rel, False, what)

        gone = root / "src/opening.rs"
        saved = gone.read_bytes()
        gone.unlink()
        rc, msg = run_version(root, depinfos)
        check("an input the dep-info names but the tree lacks is refused",
              rc != 0 and "src/opening.rs" in msg, msg)
        gone.write_bytes(saved)

    if failed:
        print(f"version: {failed} cases failed")
        sys.exit(1)
    print("version: every case passed")


if __name__ == "__main__":
    main(sys.argv[1:])
