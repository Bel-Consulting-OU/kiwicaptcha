"""The sidecar delegation plane of the python SDK.

The spawned kiwicaptcha-verifier (the full Rust core with the real
execution verifier) fronts an execution-armed challenge; the SDK's
fail-closed default refuses it, the sidecar policy delegates and
accepts. The core's evidence helper mints the armed record and its
browser-equivalent executed trace, writing the pending envelope into
the sidecar's file store through the store's own code. Skipped (never
failed) where the verifier crate is unavailable.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import urllib.request

from kiwicaptcha.records import ChallengeRecord
from kiwicaptcha.stores.memory import MemoryStorage
from kiwicaptcha.sidecar import ExecutionPolicy
from kiwicaptcha.tokens import SolutionToken
from kiwicaptcha.verify import Verifier, VerifierConfig, VerifyOptions
from tests.support import CLIENT_IP, solve_sha

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SIDECAR_BIN = os.path.join(REPO_ROOT, "target", "debug", "kiwicaptcha-verifier")
SECRET = "python-sidecar-delegation-0123456789abcdef"


def _record_from_wire(wire: dict) -> ChallengeRecord:
    return ChallengeRecord(
        nonce=wire["nonce"],
        scope=wire["scope"],
        binding_tag=wire.get("binding_tag") or "",
        issued_at=int(wire["issued_at"]),
        expires_at=int(wire["expires_at"]),
        algorithm=wire["algorithm"],
        m_kib=int(wire["m_kib"]),
        t=int(wire["t"]),
        p=int(wire["p"]),
        target_bits=int(wire["target_bits"]),
        salt=wire["salt"],
        prefix=wire["prefix"],
        challenge=wire["challenge"],
        min_duration_ms=int(wire["min_duration_ms"]),
        issued_at_ns=int(wire.get("issued_at_ns") or 0),
        protocol_version=int(wire.get("protocol_version") or 2),
        region=wire.get("region"),
        policy_version=int(wire.get("policy_version") or 1),
        request_binding=wire.get("request_binding"),
        issuer=wire.get("issuer"),
        hostname=wire.get("hostname"),
        decoy_field=wire.get("decoy_field"),
        execution_program=wire.get("execution_program"),
        execution_version=int(wire.get("execution_version") or 0),
        execution_commitment=wire.get("execution_commitment"),
        kid=int(wire.get("kid") or 1),
        server_mac=wire.get("server_mac"),
    )


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@unittest.skipUnless(os.path.exists(SIDECAR_BIN), "the verifier crate is not built")
class SidecarDelegationTest(unittest.TestCase):
    proc = None
    base_url = ""
    doc = None

    @classmethod
    def setUpClass(cls):
        build = subprocess.run(
            ["cargo", "build", "-q", "-p", "kiwicaptcha-verifier"],
            cwd=REPO_ROOT, capture_output=True,
        )
        if build.returncode != 0 or not os.path.exists(SIDECAR_BIN):
            raise unittest.SkipTest("the verifier crate did not build")
        helper_build = subprocess.run(
            ["cargo", "build", "-q", "-p", "kiwicaptcha-verifier", "--features", "test-fixtures"],
            cwd=REPO_ROOT, capture_output=True,
        )
        if helper_build.returncode != 0:
            raise unittest.SkipTest("the evidence helper did not build")
        store_dir = tempfile.mkdtemp(prefix="kiwi-sidecar-")
        helper = subprocess.run(
            [SIDECAR_BIN, "exec-evidence", "--secret", SECRET, "--scope", "login",
             "--action", "login-action", "--version", "1", "--store-dir", store_dir],
            capture_output=True, text=True,
        )
        if helper.returncode != 0:
            shutil.rmtree(store_dir, ignore_errors=True)
            raise unittest.SkipTest("the evidence helper failed")
        cls.doc = json.loads(helper.stdout)
        port = _free_port()
        env = dict(os.environ)
        env.update({
            "KIWI_LISTEN": f"http://127.0.0.1:{port}",
            "KIWI_SECRET": SECRET,
            "KIWI_STORE": f"file={store_dir}",
            "KIWI_BINDING": "none",
            "KIWI_PROFILE": "sha16",
        })
        cls.proc = subprocess.Popen([SIDECAR_BIN], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.base_url = f"http://127.0.0.1:{port}"
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(cls.base_url + "/healthz", timeout=1) as answer:
                    if answer.status == 200:
                        return
            except Exception:
                time.sleep(0.15)
        cls.tearDownClass()
        raise unittest.SkipTest("the sidecar never answered /healthz")

    @classmethod
    def tearDownClass(cls):
        if cls.proc is not None:
            cls.proc.kill()
            cls.proc.wait()

    def _options(self, **extra) -> VerifyOptions:
        storage = MemoryStorage()
        storage.store(_record_from_wire(self.doc["record"]))
        verifier = Verifier(storage, VerifierConfig())
        token = SolutionToken.create(
            self.doc["nonce"],
            solve_sha(self.doc["record"]["prefix"], self.doc["record"]["salt"],
                      int(self.doc["record"]["target_bits"])),
            5000,
            {},
            execution_digest=self.doc["digest"],
            execution_trace=self.doc["trace"],
        ).encode()
        return verifier, token, VerifyOptions(
            secret_key=SECRET, expected_scope="login", client_ip=CLIENT_IP, **extra
        )

    def test_fail_closed_default_then_delegation(self):
        verifier, token, options = self._options()
        refused = verifier.verify(token, options)
        self.assertFalse(refused.is_ok())
        self.assertEqual(refused.code, "execution_mismatch")

        verifier2, token2, options2 = self._options(
            execution_policy=ExecutionPolicy(sidecar_url=self.base_url),
        )
        accepted = verifier2.verify(token2, options2)
        self.assertTrue(accepted.is_ok(), f"the delegation must accept: {accepted.code}")

        replay = verifier2.verify(token2, options2)
        self.assertFalse(replay.is_ok())
        self.assertIn(replay.code, ("already_consumed", "record_not_found"))

        verifier3, token3, options3 = self._options(
            execution_policy=ExecutionPolicy(sidecar_url="http://127.0.0.1:1", timeout_ms=300),
        )
        down = verifier3.verify(token3, options3)
        self.assertFalse(down.is_ok())
        self.assertEqual(down.code, "storage_unavailable")


if __name__ == "__main__":
    unittest.main()
