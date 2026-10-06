#!/usr/bin/env python3
"""The guest's certificate fetch (crates/onv-generators/guest/onv-certificate.sh), run for real
against a fake Core over TLS.

    python3 tests/guest/onv_certificate_test.py

**Fixtures, not a machine and not Core.** The fake answers as omnuv's
web_certificates.rs does (its routes, its status codes, its JSON), from an
authority this run makes with openssl; the script runs as a process with its
paths moved into a temporary directory. omnuv's tests/web_certificate_binaries.py
runs the same script against the real Core.

Each case names what it proves; every one runs the script, and each refusal
is a case where the script must exit non-zero and leave what it held alone.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "crates" / "onv-generators" / "guest" / "onv-certificate.sh"
BOOTSTRAP = "cbt_" + "ab" * 32


def openssl(*args: str, cwd: Path) -> None:
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


class Authority:
    """A root, the fake Core's own certificate for 127.0.0.1, and leaves for a
    project's wildcard, each with its key."""

    def __init__(self, d: Path):
        self.d = d
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=onvt guest root", cwd=d)
        self.ca = d / "ca.pem"
        self.server_cert, self.server_key = self.leaf("core", None, ip="127.0.0.1")

    def leaf(self, name: str, domain: str | None, ip: str | None = None, days: int = 90) -> tuple[Path, Path]:
        key, csr, crt, ext = (f"{name}.key", f"{name}.csr", f"{name}.pem", f"{name}.ext")
        san = f"IP:{ip}" if ip else f"DNS:{domain}"
        (self.d / ext).write_text(f"subjectAltName={san}\n")
        openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", key, "-out", csr, "-subj", "/", cwd=self.d)
        openssl("x509", "-req", "-in", csr, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
                "-out", crt, "-days", str(days), "-extfile", ext, cwd=self.d)
        # PKCS#8, as Core hands it over.
        openssl("pkcs8", "-topk8", "-nocrypt", "-in", key, "-out", f"{name}.p8", cwd=self.d)
        return self.d / crt, self.d / f"{name}.p8"


def fingerprint(cert: Path) -> str:
    der = subprocess.run(["openssl", "x509", "-in", str(cert), "-outform", "DER"],
                         check=True, capture_output=True).stdout
    return hashlib.sha256(der).hexdigest()


class FakeCore:
    """Core's two machine routes, and what a test makes them say."""

    def __init__(self, auth: Authority):
        self.bootstrap_live = True
        self.tokens: set[str] = set()
        self.issued: dict | None = None
        self.revoked = False
        self.seen: list[str] = []
        self.minted = 0
        core = self

        class H(http.server.BaseHTTPRequestHandler):
            def bearer(self) -> str:
                return (self.headers.get("authorization") or "").removeprefix("Bearer ").strip()

            def answer(self, status: int, body: dict | None = None):
                raw = json.dumps(body).encode() if body is not None else b""
                self.send_response(status)
                if raw:
                    self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                core.seen.append(f"POST {self.path}")
                if self.path != "/v1/machine/certificate/exchange":
                    return self.answer(404)
                if core.revoked or not core.bootstrap_live or self.bearer() != BOOTSTRAP:
                    return self.answer(401, {"error": "unauthorized"})
                core.minted += 1
                token = f"cmt_{core.minted:064d}"
                core.tokens = {token}  # a new trade replaces the last
                self.answer(200, {"token": token})

            def do_GET(self):
                core.seen.append(f"GET {self.path}")
                url = urllib.parse.urlparse(self.path)
                if url.path != "/v1/machine/certificate":
                    return self.answer(404)
                if core.revoked or self.bearer() not in core.tokens:
                    return self.answer(401, {"error": "unauthorized"})
                core.bootstrap_live = False  # the first fetch spends it
                if core.issued is None:
                    return self.answer(404, {"code": "certificate_not_issued", "error": "none yet"})
                have = urllib.parse.parse_qs(url.query).get("have", [""])[0]
                if have == core.issued["fingerprint"]:
                    return self.answer(204)
                self.answer(200, core.issued)

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(auth.server_cert, auth.server_key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        # A refused handshake is a case under test, not an error to print.
        self.httpd.handle_error = lambda *a: None
        self.url = f"https://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def issue(self, cert: Path, key: Path, fp: str | None = None):
        self.issued = {
            "domain": "*.p.cloud.test",
            "fingerprint": fp or fingerprint(cert),
            "not_after": "2099-01-01T00:00:00Z",
            "chain_pem": cert.read_text(),
            "key_pem": key.read_text(),
        }


class GuestFetch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ("bash", "curl", "openssl", "python3"):
            if not shutil.which(tool):
                raise unittest.SkipTest(f"no {tool}")
        cls.tmp = Path(tempfile.mkdtemp(prefix="onvt-guest-cert-"))
        cls.auth = Authority(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.core = FakeCore(self.auth)
        self.root = Path(tempfile.mkdtemp(dir=self.tmp))
        self.conf = self.root / "pull.env"
        self.conf.write_text(f"ONV_CORE_URL={self.core.url}/\nONV_BOOTSTRAP={BOOTSTRAP}\n")
        self.state, self.live, self.hooks = self.root / "state", self.root / "live", self.root / "hooks.d"
        self.hooks.mkdir()
        self.marker = self.root / "hook-ran"
        hook = self.hooks / "50-front"
        hook.write_text(f"#!/bin/sh\necho ran >> {self.marker}\n[ ! -e {self.root}/hook-fails ]\n")
        hook.chmod(0o755)

    def tearDown(self):
        self.core.httpd.shutdown()

    def run_fetch(self) -> subprocess.CompletedProcess:
        env = dict(os.environ, ONV_CERT_CONF=str(self.conf), ONV_CERT_STATE=str(self.state),
                   ONV_CERT_LIVE=str(self.live), ONV_CERT_HOOKS=str(self.hooks),
                   ONV_CERT_CACERT=str(self.auth.ca))
        p = subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=60)
        out = p.stdout + p.stderr
        # Nothing a run prints carries a credential or a key.
        self.assertNotIn(BOOTSTRAP, out)
        self.assertNotIn("cmt_", out)
        self.assertNotIn("PRIVATE KEY", out)
        return p

    def hook_runs(self) -> int:
        return len(self.marker.read_text().splitlines()) if self.marker.exists() else 0

    def test_not_issued_yet_trades_the_bootstrap_and_waits(self):
        p = self.run_fetch()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("no certificate issued", p.stdout)
        token = self.state / "token"
        self.assertEqual(oct(token.stat().st_mode & 0o777), "0o600")
        self.assertIn(token.read_text().strip(), self.core.tokens)
        self.assertFalse((self.live / "privkey.pem").exists())
        self.assertEqual(self.hook_runs(), 0)

    def test_an_issued_certificate_is_installed_once_and_its_hook_run(self):
        cert, key = self.auth.leaf("w1", "*.p.cloud.test")
        self.core.issue(cert, key)
        p = self.run_fetch()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual((self.live / "fullchain.pem").read_text(), cert.read_text())
        self.assertEqual((self.live / "privkey.pem").read_text(), key.read_text())
        self.assertEqual(oct((self.live / "privkey.pem").stat().st_mode & 0o777), "0o600")
        self.assertEqual((self.live / "fingerprint").read_text().strip(), fingerprint(cert))
        self.assertEqual(self.hook_runs(), 1)
        # Asked again with what it holds: 204, and nothing runs.
        p = self.run_fetch()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("is current", p.stdout)
        self.assertEqual(self.hook_runs(), 1)
        self.assertEqual(self.core.seen.count("POST /v1/machine/certificate/exchange"), 1, "traded twice")

    def test_a_renewal_replaces_what_is_held(self):
        cert, key = self.auth.leaf("r1", "*.p.cloud.test")
        self.core.issue(cert, key)
        self.assertEqual(self.run_fetch().returncode, 0)
        new_cert, new_key = self.auth.leaf("r2", "*.p.cloud.test")
        self.core.issue(new_cert, new_key)
        p = self.run_fetch()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual((self.live / "privkey.pem").read_text(), new_key.read_text())
        self.assertEqual((self.live / "fingerprint").read_text().strip(), fingerprint(new_cert))
        self.assertEqual(self.hook_runs(), 2)

    def test_a_key_that_is_not_the_certificates_is_refused_and_nothing_replaced(self):
        cert, key = self.auth.leaf("k1", "*.p.cloud.test")
        self.core.issue(cert, key)
        self.assertEqual(self.run_fetch().returncode, 0)
        new_cert, _ = self.auth.leaf("k2", "*.p.cloud.test")
        _, stranger = self.auth.leaf("k3", "*.p.cloud.test")
        self.core.issue(new_cert, stranger)
        p = self.run_fetch()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("not the certificate's", p.stderr)
        self.assertEqual((self.live / "privkey.pem").read_text(), key.read_text(), "the held key was replaced")
        self.assertEqual(self.hook_runs(), 1)

    def test_a_certificate_other_than_the_one_named_is_refused(self):
        cert, key = self.auth.leaf("f1", "*.p.cloud.test")
        self.core.issue(cert, key, fp="00" * 32)
        p = self.run_fetch()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("not the one Core named", p.stderr)
        self.assertFalse((self.live / "privkey.pem").exists())

    def test_an_ended_certificate_is_refused(self):
        cert, key = self.auth.leaf("e1", "*.p.cloud.test", days=0)
        self.core.issue(cert, key)
        p = self.run_fetch()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("has ended", p.stderr)

    def test_a_token_core_forgot_is_traded_again_while_the_bootstrap_lives(self):
        self.assertEqual(self.run_fetch().returncode, 0)  # traded; not issued
        self.core.tokens = set()                        # placed again: token withdrawn
        self.core.bootstrap_live = True                 # ...and a new bootstrap armed
        cert, key = self.auth.leaf("t1", "*.p.cloud.test")
        self.core.issue(cert, key)
        p = self.run_fetch()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("trading the bootstrap again", p.stdout)
        self.assertTrue((self.live / "privkey.pem").exists())

    def test_a_revoked_machine_fails_loudly_and_keeps_what_it_held(self):
        cert, key = self.auth.leaf("v1", "*.p.cloud.test")
        self.core.issue(cert, key)
        self.assertEqual(self.run_fetch().returncode, 0)
        self.core.revoked = True
        p = self.run_fetch()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("refused this machine's bootstrap", p.stderr)
        self.assertEqual((self.live / "privkey.pem").read_text(), key.read_text())

    def test_a_failed_hook_is_run_again_by_the_next_run(self):
        cert, key = self.auth.leaf("h1", "*.p.cloud.test")
        self.core.issue(cert, key)
        (self.root / "hook-fails").touch()
        p = self.run_fetch()
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse((self.live / "fingerprint").exists(), "a failed hook's certificate was marked held")
        (self.root / "hook-fails").unlink()
        p = self.run_fetch()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.hook_runs(), 2)
        self.assertEqual((self.live / "fingerprint").read_text().strip(), fingerprint(cert))

    def test_only_an_https_origin_is_asked_and_no_configuration_is_nothing_to_do(self):
        self.conf.write_text(f"ONV_CORE_URL={self.core.url.replace('https', 'http')}\nONV_BOOTSTRAP={BOOTSTRAP}\n")
        p = self.run_fetch()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("not an https:// origin", p.stderr)
        self.assertEqual(self.core.seen, [])
        self.conf.unlink()
        p = self.run_fetch()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("fetches no certificate", p.stdout)

    def test_a_core_that_cannot_be_trusted_is_not_asked_twice(self):
        # The system's roots, not this run's authority: the handshake fails.
        env = dict(os.environ, ONV_CERT_CONF=str(self.conf), ONV_CERT_STATE=str(self.state),
                   ONV_CERT_LIVE=str(self.live), ONV_CERT_HOOKS=str(self.hooks))
        p = subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=60)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("answered 000", p.stderr)
        self.assertFalse((self.state / "token").exists())


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False, verbosity=2).result.wasSuccessful() else 1)
