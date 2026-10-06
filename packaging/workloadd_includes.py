#!/usr/bin/env python3
"""The files onv-workloadd compiles from outside its own crate (A2).

    packaging/workloadd_includes.py <crate src dir>

Prints `include <path> <sha256>` for each file a `#[path = "..."]` attribute
in the crate's sources names outside that crate, the path relative to the
workspace root (the current directory), sorted. cargo tree cannot see these,
so packaging/baselines.sh's closure appends them to what it records.

Refuses, naming the file:
  - a `#[path]` naming a file that does not exist;
  - an `include!`-family macro in the crate's sources or an included file, or
    an out-of-line `mod x;` in an included file: each compiles a further file
    this list would not name.
"""
import hashlib
import os
import re
import sys

# `#[path = "x"]`, the attribute only: the doc comments that mention
# "`#[path]`" carry no `=` and a string, so they are not matched.
PATH_ATTR = re.compile(r'#\[\s*path\s*=\s*"([^"]+)"\s*\]')
# include!, include_str!, include_bytes!.
INCLUDE = re.compile(r'\binclude(?:_str|_bytes)?!\s*\(')
# `mod x;` with no body; `mod x {` is inline and pulls nothing in.
OUT_OF_LINE_MOD = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*;', re.M)


def strip_comments(text):
    """Line comments removed, so prose cannot trip the refusals."""
    return re.sub(r'//[^\n]*', '', text)


def main():
    if len(sys.argv) != 2:
        print('usage: workloadd_includes.py <crate src dir>', file=sys.stderr)
        return 2
    src = sys.argv[1]
    crate = os.path.normpath(os.path.join(src, '..'))
    root = os.getcwd()
    problems = []
    found = {}
    sources = sorted(
        os.path.join(d, f) for d, _, fs in os.walk(src) for f in fs if f.endswith('.rs'))
    if not sources:
        print(f'workloadd_includes: no sources under {src}', file=sys.stderr)
        return 1
    for path in sources:
        text = open(path, encoding='utf-8').read()
        code = strip_comments(text)
        if INCLUDE.search(code):
            problems.append(f'{path}: an include! macro compiles a file the closure does not name')
        for target in PATH_ATTR.findall(code):
            # A #[path] on a module declared in main.rs resolves against
            # main.rs's own directory; every source here is such a file.
            resolved = os.path.normpath(os.path.join(os.path.dirname(path), target))
            rel = os.path.relpath(resolved, root)
            if not os.path.isfile(resolved):
                problems.append(f'{path}: #[path] names {rel}, which does not exist')
                continue
            if os.path.commonpath([os.path.abspath(resolved), os.path.abspath(crate)]) == os.path.abspath(crate):
                continue  # inside the crate: its own source
            found[rel] = resolved
    lines = []
    for rel in sorted(found):
        data = open(found[rel], 'rb').read()
        code = strip_comments(data.decode('utf-8'))
        if INCLUDE.search(code):
            problems.append(f'{rel}: an include! macro compiles a file the closure does not name')
        if OUT_OF_LINE_MOD.search(code):
            problems.append(f'{rel}: an out-of-line mod compiles a file the closure does not name')
        lines.append(f'include {rel} {hashlib.sha256(data).hexdigest()}')
    if problems:
        for p in problems:
            print(f'workloadd_includes: {p}', file=sys.stderr)
        return 1
    if not lines:
        print(f'workloadd_includes: no #[path] file outside {crate}', file=sys.stderr)
    print('\n'.join(lines))
    return 0


if __name__ == '__main__':
    sys.exit(main())
