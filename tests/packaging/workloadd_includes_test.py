#!/usr/bin/env python3
"""packaging/workloadd_includes.py against fixture trees: fixtures, not the
real crate. A right tree must list its #[path] file by sha256; each wrong one
must be refused for its own reason, and the nearest things the patterns must
ignore (a doc comment naming `#[path]`, an inline `mod tests {`, a `#[path]`
inside the crate) must not change the answer.

    tests/packaging/workloadd_includes_test.py

Ends with `includes: every case passed`, or exits 1 naming each failure.
"""
import hashlib
import os
import subprocess
import sys
import tempfile

HELPER = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'packaging', 'workloadd_includes.py'))

LIB = '//! Shared through `#[path]`: the crate has no library.\npub fn f() {}\n#[cfg(test)]\nmod tests {\n}\n'
MAIN = '#[path = "../../lib/src/dur.rs"]\nmod dur;\nfn main() {}\n'


def tree(files):
    d = tempfile.mkdtemp()
    for rel, text in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'w') as f:
            f.write(text)
    return d


def run(d):
    r = subprocess.run([sys.executable, HELPER, 'crates/w/src'], cwd=d, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


failed = 0


def case(name, ok):
    global failed
    print(f'{"ok" if ok else "FAILED"}  {name}')
    failed += not ok


# Right: one file outside the crate, listed by path and sha256, despite the
# doc comment naming `#[path]` and the inline test module.
d = tree({'crates/lib/src/dur.rs': LIB, 'crates/w/src/main.rs': MAIN})
rc, out, err = run(d)
want = f'include crates/lib/src/dur.rs {hashlib.sha256(LIB.encode()).hexdigest()}\n'
case('right tree listed by sha256', rc == 0 and out == want)

# Negative for the attribute: a #[path] inside the crate is its own source.
d = tree({'crates/lib/src/dur.rs': LIB,
          'crates/w/src/main.rs': MAIN + '#[path = "inner.rs"]\nmod inner;\n',
          'crates/w/src/inner.rs': 'pub fn g() {}\n'})
rc, out, err = run(d)
case('a #[path] inside the crate is not listed', rc == 0 and out == want)

# Negative for the attribute: a commented-out one is not compiled.
d = tree({'crates/lib/src/dur.rs': LIB,
          'crates/w/src/main.rs': MAIN + '// #[path = "../../lib/src/gone.rs"]\n'})
rc, out, err = run(d)
case('a commented-out #[path] is ignored', rc == 0 and out == want)

# The file edited: the line moves.
d = tree({'crates/lib/src/dur.rs': LIB + 'pub fn h() {}\n', 'crates/w/src/main.rs': MAIN})
rc, out, err = run(d)
case('an edit moves the sha256', rc == 0 and out.startswith('include crates/lib/src/dur.rs ') and out != want)

# The file moved and the attribute with it: the path moves.
d = tree({'crates/core/src/dur.rs': LIB,
          'crates/w/src/main.rs': MAIN.replace('../../lib/', '../../core/')})
rc, out, err = run(d)
case('a move moves the path', rc == 0 and out.startswith('include crates/core/src/dur.rs '))

# The file moved and the attribute left behind.
d = tree({'crates/core/src/dur.rs': LIB, 'crates/w/src/main.rs': MAIN})
rc, out, err = run(d)
case('a #[path] to a missing file is refused', rc == 1 and 'does not exist' in err)

# A further file pulled in by the included one.
d = tree({'crates/lib/src/dur.rs': LIB + 'mod more;\n', 'crates/lib/src/more.rs': '',
          'crates/w/src/main.rs': MAIN})
rc, out, err = run(d)
case('an out-of-line mod in an included file is refused', rc == 1 and 'out-of-line mod' in err)

d = tree({'crates/lib/src/dur.rs': LIB + 'pub(crate) mod more;\n', 'crates/lib/src/more.rs': '',
          'crates/w/src/main.rs': MAIN})
rc, out, err = run(d)
case('a pub(crate) out-of-line mod is refused', rc == 1 and 'out-of-line mod' in err)

d = tree({'crates/lib/src/dur.rs': LIB + 'const X: &str = include_str!("x.txt");\n',
          'crates/w/src/main.rs': MAIN})
rc, out, err = run(d)
case('an include_str! in an included file is refused', rc == 1 and 'include!' in err)

d = tree({'crates/lib/src/dur.rs': LIB,
          'crates/w/src/main.rs': MAIN + 'include!("../../lib/src/x.rs");\n'})
rc, out, err = run(d)
case('an include! in the crate is refused', rc == 1 and 'include!' in err)

# Negative for include!: prose naming it in a comment.
d = tree({'crates/lib/src/dur.rs': LIB + '// never include!(...) here\n', 'crates/w/src/main.rs': MAIN})
rc, out, err = run(d)
case('include! in a comment is ignored', rc == 0 and out.startswith('include crates/lib/src/dur.rs '))

if failed:
    print(f'includes: {failed} case(s) failed')
    sys.exit(1)
print('includes: every case passed')
