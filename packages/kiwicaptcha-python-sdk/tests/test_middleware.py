"""The middleware shells over duck-typed framework objects, with no
framework import required."""

import io
import json
import sys
import unittest
import urllib.parse

sys.path.insert(0, ".")

from tests.support import ISSUED_AT, NOW, SECRET, mint_v2_record, solve_sha

from kiwicaptcha import SolutionToken
from kiwicaptcha.middleware import (
    DjangoMiddleware,
    FastApiKiwiDependency,
    FlaskKiwiCaptcha,
    WsgiKiwiCaptcha,
)
from kiwicaptcha.stores import MemoryStorage
from kiwicaptcha.verify import Verifier, VerifierConfig


def make_verifier():
    storage = MemoryStorage(now=lambda: NOW)
    return Verifier(storage, VerifierConfig(now_provider=lambda: NOW))


def issue_token(**mint):
    record = mint_v2_record(**mint)
    counter = solve_sha(record.prefix, record.salt, record.target_bits)
    token = SolutionToken.create(record.nonce, counter, 5000, {}).encode()
    return record, token


class WsgiHarness:
    """A minimal wsgi harness: environ from a method, path, headers."""

    def __init__(self, app):
        self.app = app
        self.status = None
        self.headers = None
        self.body = b""

    def start_response(self, status, headers):
        self.status = status
        self.headers = headers

    def request(self, method="GET", path="/api/submit", token=None,
                form=None, query=None, remote_addr="203.0.113.7"):
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "SCRIPT_NAME": "",
            "QUERY_STRING": query or "",
            "REMOTE_ADDR": remote_addr,
            "CONTENT_TYPE": "application/x-www-form-urlencoded" if form else "",
            "wsgi.input": io.BytesIO(
                urllib.parse.urlencode(form).encode() if form else b""
            ),
        }
        if form:
            environ["CONTENT_LENGTH"] = str(len(environ["wsgi.input"].getvalue()))
        if token:
            environ["HTTP_X_KIWI_TOKEN"] = token
        self.status = None
        self.headers = None
        self.body = b"".join(self.app(environ, self.start_response))
        return self


class WsgiMiddlewareTest(unittest.TestCase):
    def test_valid_token_passes(self):
        verifier = make_verifier()
        record, token = issue_token()
        verifier.storage.store(record)

        captured = {}

        def target_app(environ, start_response):
            captured["decision"] = environ["kiwi.decision"]
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"ok"]

        app = WsgiKiwiCaptcha(target_app, verifier, SECRET, expected_scope="login")
        harness = WsgiHarness(app)
        harness.request(token=token)
        self.assertEqual("200 OK", harness.status)
        self.assertTrue(captured["decision"].ok)

    def test_missing_token_403(self):
        verifier = make_verifier()
        app = WsgiKiwiCaptcha(lambda e, s: s("200 OK", []) or [], verifier, SECRET, "login")
        harness = WsgiHarness(app)
        harness.request()
        self.assertEqual("403 Forbidden", harness.status)
        self.assertEqual({"ok": False, "error": "malformed_token"},
                         json.loads(harness.body))

    def test_bad_token_403_and_burned(self):
        verifier = make_verifier()
        record, token = issue_token()
        verifier.storage.store(record)
        app = WsgiKiwiCaptcha(
            lambda e, s: s("200 OK", []) or [b""], verifier, SECRET, "login"
        )
        harness = WsgiHarness(app)
        harness.request(token=token, query="kiwi_token=" + urllib.parse.quote(token))
        # Header absent, query present: the query token verifies.
        self.assertEqual("200 OK", harness.status)

    def test_form_token_and_scope_predicate(self):
        verifier = make_verifier()
        record, token = issue_token()
        verifier.storage.store(record)
        called = []

        def target_app(environ, start_response):
            called.append(environ["PATH_INFO"])
            start_response("200 OK", [])
            return [b"ok"]

        app = WsgiKiwiCaptcha(
            target_app, verifier, SECRET,
            expected_scope="login",
            scope_predicate=lambda path: path.startswith("api/"),
        )
        harness = WsgiHarness(app)
        # Unprotected path: passes without any token.
        harness.request(path="/health")
        self.assertEqual("200 OK", harness.status)
        self.assertEqual(["/health"], called)
        # Protected path with a form token.
        harness.request(path="/api/submit", form={"kiwi_token": token})
        self.assertEqual("200 OK", harness.status)

    def test_wrong_ip_403(self):
        verifier = make_verifier()
        record, token = issue_token(binding_ip="203.0.113.7")
        verifier.storage.store(record)
        app = WsgiKiwiCaptcha(lambda e, s: s("200 OK", []) or [b""], verifier, SECRET, "login")
        harness = WsgiHarness(app)
        harness.request(token=token, remote_addr="198.51.100.1")
        self.assertEqual("403 Forbidden", harness.status)
        self.assertEqual("ip_mismatch", json.loads(harness.body)["error"])


class _DuckRequest:
    def __init__(self, path="/api/submit", token=None, form=None, query=None,
                 remote_addr="203.0.113.7"):
        self.path = path
        self.headers = {**({"x-kiwi-token": token} if token else {})}
        self.META = {"REMOTE_ADDR": remote_addr}
        self.POST = form or {}
        self.GET = query or {}


class DjangoMiddlewareTest(unittest.TestCase):
    def test_protected_path_flow(self):
        verifier = make_verifier()
        record, token = issue_token()
        verifier.storage.store(record)
        marker = {}

        def get_response(request):
            marker["decision"] = getattr(request, "kiwi_decision", None)
            return "RESPONSE"

        middleware = DjangoMiddleware.from_settings(
            get_response, verifier, SECRET,
            protected_scopes=("api",), expected_scope="login",
        )
        response = middleware(_DuckRequest(token=token))
        self.assertEqual("RESPONSE", response)
        self.assertTrue(marker["decision"].ok)
        # Missing token on a protected path: the fallback response.
        response2 = middleware(_DuckRequest())
        self.assertEqual(403, response2.status_code)
        # Unprotected path passes without a token.
        response3 = middleware(_DuckRequest(path="/health"))
        self.assertEqual("RESPONSE", response3)
        self.assertIsNone(marker["decision"])


class FlaskExtensionTest(unittest.TestCase):
    def test_guard_flow_with_injected_request(self):
        verifier = make_verifier()
        record, token = issue_token()
        verifier.storage.store(record)

        class DuckFlaskRequest:
            endpoint = "submit"
            headers = {}
            form = {}
            args = {}
            remote_addr = "203.0.113.7"

        class DuckResponse:
            def __init__(self, **payload):
                self.payload = payload
                self.status_code = 200

        request_holder = {}
        extension = FlaskKiwiCaptcha(
            verifier=verifier,
            secret_key=SECRET,
            request_getter=lambda: request_holder["request"],
            jsonify_factory=lambda **payload: DuckResponse(**payload),
        )
        extension._protected["submit"] = "login"

        # A protected view without a token: 403.
        request_holder["request"] = DuckFlaskRequest()
        response = extension._guard()
        self.assertEqual(403, response.status_code)

        # With a header token: passes (None means continue).
        DuckFlaskRequest.headers = {"x-kiwi-token": token}
        request_holder["request"] = DuckFlaskRequest()
        self.assertIsNone(extension._guard())

        # A consumed token: 403 already_consumed.
        DuckFlaskRequest.headers = {"x-kiwi-token": token}
        request_holder["request"] = DuckFlaskRequest()
        response = extension._guard()
        self.assertEqual(403, response.status_code)
        self.assertEqual("already_consumed", response.payload["error"])

    def test_unprotected_endpoint_passes(self):
        class DuckFlaskRequest:
            endpoint = "health"
            headers = {}
            form = {}
            args = {}
            remote_addr = "203.0.113.7"

        extension = FlaskKiwiCaptcha(
            request_getter=lambda: DuckFlaskRequest(),
            jsonify_factory=lambda **payload: None,
        )
        self.assertIsNone(extension._guard())


class FastApiDependencyTest(unittest.TestCase):
    def test_dependency_flow(self):
        verifier = make_verifier()
        record, token = issue_token()
        verifier.storage.store(record)

        class DuckClient:
            host = "203.0.113.7"

        class DuckState:
            pass

        class DuckRequest:
            client = DuckClient()
            state = DuckState()
            headers = {"x-forwarded-for": "203.0.113.7"}
            query_params = {}

        guard = FastApiKiwiDependency(
            verifier, SECRET, expected_scope="login",
            on_failure=lambda status, code: _DuckHTTPException(status, code),
        )
        request = DuckRequest()
        decision = guard(request=request, x_kiwi_token=token)
        self.assertTrue(decision.ok)
        self.assertTrue(request.state.kiwi_decision.ok)
        # A replay raises through the factory.
        try:
            guard(request=request, x_kiwi_token=token)
            self.fail("the replay must raise")
        except _DuckHTTPException as exc:
            self.assertEqual(403, exc.status)
            self.assertEqual("already_consumed", exc.code)
        # A missing token raises malformed_token.
        try:
            guard(request=DuckRequest())
            self.fail("a missing token must raise")
        except _DuckHTTPException as exc:
            self.assertEqual("malformed_token", exc.code)

    def test_default_failure_factory_without_fastapi(self):
        guard = FastApiKiwiDependency(make_verifier(), SECRET, "login")
        error = guard._default_failure(403, "malformed_token")
        self.assertIsInstance(error, RuntimeError)


class _DuckHTTPException(Exception):
    def __init__(self, status, code):
        super().__init__(f"{status}: {code}")
        self.status = status
        self.code = code


if __name__ == "__main__":
    unittest.main()
