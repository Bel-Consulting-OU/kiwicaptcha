"""Framework middleware: one verification pipeline, four shells.

``WsgiKiwiCaptcha`` is the framework-neutral core over any wsgi call
chain. ``KiwiCaptchaMiddleware`` is the Django middleware class (with
``DjangoMiddleware`` as the short alias), ``FlaskKiwiCaptcha`` is the
Flask extension, and ``FastApiKiwiDependency`` is the FastAPI
dependency. Each shell resolves the token from a request field, calls
the verifier, and renders failures through injectable response and
exception factories, so no framework import happens at module import
time.

The contract per shell: a request carrying a valid, unconsumed token
proceeds; anything else is answered with ``403 Forbidden`` carrying the
machine-readable error code, and a retry disposition (a storage outage
or capacity exhaustion) answers with ``503 Service Unavailable``. The
token source order is the ``x-kiwi-token`` header, then the
``kiwi_token`` form field, then the ``kiwi_token`` query parameter.
"""

import json
from typing import Any, Callable, Dict, Iterable, Optional, Sequence, Tuple

from .clientip import resolve_client_ip
from .decision import VerifyDecision
from .verify import VerifyOptions, Verifier

TOKEN_HEADER = "x-kiwi-token"
TOKEN_FIELD = "kiwi_token"

_STATUS_TEXT = {403: "Forbidden", 503: "Service Unavailable"}


def _status_for_disposition(disposition: str) -> int:
    return 503 if disposition == "retry" else 403


def _json_body(code: str) -> bytes:
    return json.dumps(
        {"ok": False, "error": code}, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pick_token(
    header: Optional[str],
    form: Optional[Dict[str, Any]],
    query: Optional[Dict[str, Any]],
) -> Optional[str]:
    if header:
        return header
    if form is not None and form.get(TOKEN_FIELD):
        return form[TOKEN_FIELD]
    if query is not None and query.get(TOKEN_FIELD):
        return query[TOKEN_FIELD]
    return None


def _client_ip(
    remote_addr: Optional[str],
    forwarded_for: Optional[str],
    trusted_proxies: Optional[Sequence[str]] = None,
    real_ip: Optional[str] = None,
) -> Optional[str]:
    """The canonical client IP per the shared trusted-proxy contract.

    The socket peer wins unless the peer is trusted; the forwarded
    chain is then walked right to left through the trusted hops (see
    :mod:`kiwicaptcha.clientip`). An empty trust list never honors a
    forwarding header.
    """
    return resolve_client_ip(remote_addr, forwarded_for, real_ip, trusted_proxies)


def _verify_once(
    verifier: Verifier, secret_key: str, token: str, expected_scope: str,
    client_ip: Optional[str],
) -> VerifyDecision:
    outcome = verifier.verify(
        token,
        VerifyOptions(
            secret_key=secret_key,
            expected_scope=expected_scope,
            client_ip=client_ip,
        ),
    )
    return VerifyDecision.from_outcome(outcome)


class WsgiKiwiCaptcha:
    """The wsgi middleware over a verifier.

    ``scope_predicate`` receives the request path (stripped of its
    leading slash) and answers whether the path needs a captcha; paths
    that fail the predicate pass through untouched. Without a predicate
    every request must carry a token. ``trusted_proxies`` is the
    trusted-proxy CIDR list: empty (the default) means forwarding
    headers are ignored and the socket peer is the client IP.
    """

    def __init__(
        self,
        app: Callable,
        verifier: Verifier,
        secret_key: str,
        expected_scope: str,
        scope_predicate: Optional[Callable[[str], bool]] = None,
        trusted_proxies: Optional[Sequence[str]] = None,
    ) -> None:
        self.app = app
        self.verifier = verifier
        self.secret_key = secret_key
        self.scope_predicate = scope_predicate
        self.expected_scope = expected_scope
        self.trusted_proxies = tuple(trusted_proxies or ())

    @staticmethod
    def _form_field(environ: Dict[str, Any]) -> Optional[str]:
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        content_type = environ.get("CONTENT_TYPE", "")
        if length <= 0 or "application/x-www-form-urlencoded" not in content_type:
            return None
        body = environ["wsgi.input"].read(length)
        from urllib.parse import parse_qs

        fields = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
        values = fields.get(TOKEN_FIELD)
        return values[0] if values else None

    @staticmethod
    def _query_field(environ: Dict[str, Any]) -> Optional[str]:
        from urllib.parse import parse_qs

        fields = parse_qs(
            environ.get("QUERY_STRING", ""), keep_blank_values=True
        )
        values = fields.get(TOKEN_FIELD)
        return values[0] if values else None

    def _respond(self, start_response: Callable, status: int, code: str) -> List[bytes]:
        body = _json_body(code)
        reason = _STATUS_TEXT.get(status, "Error")
        start_response(
            f"{status} {reason}",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
            ],
        )
        return [body]

    def __call__(self, environ: Dict[str, Any], start_response: Callable) -> List[bytes]:
        path_scope = environ.get("PATH_INFO", "").strip("/") or "default"
        if self.scope_predicate is not None and not self.scope_predicate(path_scope):
            return self.app(environ, start_response)
        token = (
            environ.get("HTTP_X_KIWI_TOKEN")
            or self._form_field(environ)
            or self._query_field(environ)
        )
        if token is None:
            return self._respond(start_response, 403, "malformed_token")
        client_ip = _client_ip(
            environ.get("REMOTE_ADDR"),
            environ.get("HTTP_X_FORWARDED_FOR"),
            self.trusted_proxies,
            environ.get("HTTP_X_REAL_IP"),
        )
        decision = _verify_once(
            self.verifier, self.secret_key, token, self.expected_scope, client_ip
        )
        if decision.ok:
            environ["kiwi.decision"] = decision
            return self.app(environ, start_response)
        return self._respond(
            start_response,
            _status_for_disposition(decision.disposition),
            decision.error or "invalid",
        )


class KiwiCaptchaMiddleware:
    """The Django middleware class (the new-style ``__init__`` hook).

    Build it through :meth:`from_settings` inside a Django settings
    factory, wiring the verifier, the secret and the protected path
    prefixes. Framework imports stay lazy: without Django installed the
    denial falls back to a plain response stand-in, which keeps the
    middleware testable without the framework.
    """

    verifier: Verifier
    secret_key: str = ""
    protected_scopes: Tuple[str, ...] = ()
    expected_scope: str = ""
    trusted_proxies: Tuple[str, ...] = ()

    def __init__(self, get_response: Callable) -> None:
        self.get_response = get_response

    @classmethod
    def from_settings(
        cls,
        get_response: Callable,
        verifier: Verifier,
        secret_key: str,
        expected_scope: str,
        protected_scopes: Sequence[str] = (),
        trusted_proxies: Sequence[str] = (),
    ) -> "KiwiCaptchaMiddleware":
        middleware = cls(get_response)
        middleware.verifier = verifier
        middleware.secret_key = secret_key
        middleware.protected_scopes = tuple(protected_scopes)
        middleware.expected_scope = expected_scope
        middleware.trusted_proxies = tuple(trusted_proxies)
        return middleware

    def __call__(self, request: Any) -> Any:
        path = request.path.lstrip("/")
        protected = any(
            path == prefix or path.startswith(prefix + "/")
            for prefix in self.protected_scopes
        )
        if not protected:
            return self.get_response(request)
        form = getattr(request, "POST", None)
        query = getattr(request, "GET", None)
        token = _pick_token(
            request.headers.get(TOKEN_HEADER),
            form,
            query,
        )
        if token is None:
            return self._denied(request, 403, "malformed_token")
        client_ip = _client_ip(
            request.META.get("REMOTE_ADDR"),
            request.META.get("HTTP_X_FORWARDED_FOR"),
            self.trusted_proxies,
            request.META.get("HTTP_X_REAL_IP"),
        )
        decision = _verify_once(
            self.verifier, self.secret_key, token, self.expected_scope, client_ip
        )
        if decision.ok:
            request.kiwi_decision = decision
            return self.get_response(request)
        return self._denied(
            request,
            _status_for_disposition(decision.disposition),
            decision.error or "invalid",
        )

    @staticmethod
    def _denied(request: Any, status: int, code: str) -> Any:
        try:
            from django.http import JsonResponse

            return JsonResponse({"ok": False, "error": code}, status=status)
        except Exception:
            return _FallbackResponse(status, code)


DjangoMiddleware = KiwiCaptchaMiddleware


class _FallbackResponse:
    """The response stand-in used when a framework module is absent:
    a plain iterable with the status code, keeping every middleware
    shell testable without its framework installed."""

    def __init__(self, status_code: int, code: str) -> None:
        self.status_code = status_code
        self.body = _json_body(code)

    def __iter__(self) -> Iterable[bytes]:
        return iter([self.body])


class FlaskKiwiCaptcha:
    """The Flask extension.

    ``FlaskKiwiCaptcha(app, verifier, secret_key)`` installs a
    before_request guard; view functions registered through
    ``@captcha.protected`` demand a token. An optional per-endpoint
    scope overrides the extension-wide ``expected_scope``.
    """

    def __init__(
        self,
        app: Any = None,
        verifier: Optional[Verifier] = None,
        secret_key: str = "",
        expected_scope: str = "",
        request_getter: Optional[Callable[[], Any]] = None,
        jsonify_factory: Optional[Callable[..., Any]] = None,
        trusted_proxies: Optional[Sequence[str]] = None,
    ) -> None:
        self.verifier = verifier
        self.secret_key = secret_key
        self.expected_scope = expected_scope
        self.trusted_proxies = tuple(trusted_proxies or ())
        self._protected: Dict[str, Optional[str]] = {}
        self._request_getter = request_getter
        self._jsonify_factory = jsonify_factory
        if app is not None:
            if verifier is None:
                raise ValueError("FlaskKiwiCaptcha needs a verifier")
            self.init_app(app, verifier, secret_key, expected_scope)

    def init_app(
        self,
        app: Any,
        verifier: Verifier,
        secret_key: str,
        expected_scope: str = "",
        trusted_proxies: Optional[Sequence[str]] = None,
    ) -> None:
        self.verifier = verifier
        self.secret_key = secret_key
        self.expected_scope = expected_scope
        if trusted_proxies is not None:
            self.trusted_proxies = tuple(trusted_proxies)
        app.before_request(self._guard)

    def protected(self, endpoint_scope: Optional[str] = None) -> Callable:
        def decorator(fn: Callable) -> Callable:
            self._protected[fn.__name__] = endpoint_scope
            fn._kiwi_protected = True
            return fn

        return decorator

    def _guard(self) -> Any:
        if self._request_getter is not None:
            request = self._request_getter()
        else:
            try:
                from flask import request
            except Exception:
                return None
        if request is None:
            return None
        name = request.endpoint.rsplit(".", 1)[-1] if request.endpoint else ""
        view = self._view_function(request.endpoint)
        marked = getattr(view, "_kiwi_protected", False)
        if name not in self._protected and not marked:
            return None
        form = None
        try:
            form = request.form
        except Exception:
            form = None
        token = _pick_token(
            request.headers.get(TOKEN_HEADER),
            form,
            request.args,
        )
        if token is None:
            return self._json(403, "malformed_token")
        assert self.verifier is not None
        decision = _verify_once(
            self.verifier,
            self.secret_key,
            token,
            self._protected.get(name) or self.expected_scope,
            _client_ip(
                request.remote_addr,
                request.headers.get("x-forwarded-for"),
                self.trusted_proxies,
                request.headers.get("x-real-ip"),
            ),
        )
        if decision.ok:
            request.kiwi_decision = decision
            return None
        return self._json(
            _status_for_disposition(decision.disposition),
            decision.error or "invalid",
        )

    @staticmethod
    def _view_function(endpoint: Optional[str]) -> Any:
        if endpoint is None:
            return None
        try:
            import flask

            return flask.current_app.view_functions.get(endpoint)
        except Exception:
            return None

    def _json(self, status: int, code: str) -> Any:
        if self._jsonify_factory is not None:
            response = self._jsonify_factory(ok=False, error=code)
            response.status_code = status
            return response
        try:
            from flask import jsonify

            response = jsonify(ok=False, error=code)
            response.status_code = status
            return response
        except Exception:
            return _FallbackResponse(status, code)


class FastApiKiwiDependency:
    """The FastAPI dependency.

    Wrap one instance in ``Depends`` and the guarded route resolves
    a decision. The token arrives through the ``x_kiwi_token`` or
    ``kiwi_token`` parameters FastAPI binds from the header or the
    form/query field, and failures raise the injectable ``on_failure``
    exception factory, defaulting to a lazily imported
    ``fastapi.HTTPException``.
    """

    def __init__(
        self,
        verifier: Verifier,
        secret_key: str,
        expected_scope: str,
        on_failure: Optional[Callable[[int, str], Exception]] = None,
        trusted_proxies: Optional[Sequence[str]] = None,
    ) -> None:
        self.verifier = verifier
        self.secret_key = secret_key
        self.expected_scope = expected_scope
        self.trusted_proxies = tuple(trusted_proxies or ())
        self.on_failure = on_failure or self._default_failure

    @staticmethod
    def _default_failure(status: int, code: str) -> Exception:
        try:
            from fastapi import HTTPException

            return HTTPException(
                status_code=status, detail={"ok": False, "error": code}
            )
        except Exception:
            return RuntimeError(f"kiwicaptcha rejected the request: {code} ({status})")

    def __call__(
        self,
        request: Any = None,
        kiwi_token: Optional[str] = None,
        x_kiwi_token: Optional[str] = None,
    ) -> VerifyDecision:
        token = x_kiwi_token or kiwi_token
        if token is None and request is not None:
            token = request.query_params.get(TOKEN_FIELD)
        if token is None:
            raise self.on_failure(403, "malformed_token")
        client_ip = None
        if request is not None:
            client_ip = _client_ip(
                request.client.host if request.client is not None else None,
                request.headers.get("x-forwarded-for"),
                self.trusted_proxies,
                request.headers.get("x-real-ip"),
            )
        decision = _verify_once(
            self.verifier, self.secret_key, token, self.expected_scope, client_ip
        )
        if not decision.ok:
            raise self.on_failure(
                _status_for_disposition(decision.disposition),
                decision.error or "invalid",
            )
        if request is not None:
            try:
                request.state.kiwi_decision = decision
            except Exception:
                pass
        return decision
