"""A minimal RESP client for the red-team infrastructure campaigns.

stdlib only. Just enough of the protocol for the storage-plane attack
legs: GET, SET, DEL, KEYS, TTL, PING, WAIT, ROLE. One connection per
RedisRole instance; every reply parsed per the RESP2 wire.

Also: the backend-neutral record tamper surface. The pending record of
every storage backend is one JSON document; the driver fetches it,
applies its mutation, stores it back, and drives the deployment's real
verify endpoint against the tampered state.
"""

from __future__ import annotations

import json
import os
import socket


class RedisMini:
    """One RESP2 connection with the handful of commands the legs need."""

    def __init__(self, host: str = "127.0.0.1", port: int = 6379, timeout: float = 10.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.file = self.sock.makefile("rb")

    def _send(self, *args: bytes) -> None:
        out = bytearray(b"*%d\r\n" % len(args))
        for arg in args:
            out += b"$%d\r\n%s\r\n" % (len(arg), arg)
        self.sock.sendall(out)

    def _read(self):
        line = self.file.readline()
        if not line:
            raise ConnectionError("empty reply")
        kind, payload = line[:1], line[1:-2]
        if kind == b"+":
            return payload.decode()
        if kind == b"-":
            return RedisError(payload.decode())
        if kind == b":":
            return int(payload)
        if kind == b"$":
            length = int(payload)
            if length == -1:
                return None
            data = self.file.read(length)
            self.file.read(2)
            return data
        if kind == b"*":
            count = int(payload)
            if count == -1:
                return None
            return [self._read() for _ in range(count)]
        raise ProtocolError("unknown reply kind %r" % kind)

    def cmd(self, *args) -> object:
        encoded = [a if isinstance(a, bytes) else str(a).encode() for a in args]
        self._send(*encoded)
        reply = self._read()
        if isinstance(reply, RedisError):
            raise reply
        return reply

    def get(self, key: str):
        return self.cmd("GET", key)

    def set(self, key: str, value: str) -> None:
        self.cmd("SET", key, value)

    def delete(self, *keys: str) -> None:
        if keys:
            self.cmd("DEL", *keys)

    def keys(self, pattern: str) -> list:
        return [k.decode() for k in (self.cmd("KEYS", pattern) or [])]

    def ttl(self, key: str) -> int:
        return self.cmd("TTL", key)

    def ping(self) -> bool:
        return self.cmd("PING") == "PONG"

    def wait(self, replicas: int, timeout_ms: int) -> int:
        return self.cmd("WAIT", replicas, timeout_ms)

    def role(self) -> list:
        return self.cmd("ROLE")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class RedisError(Exception):
    pass


class ProtocolError(Exception):
    pass


def redis_url_parts(url: str) -> tuple:
    """redis://host:port -> ('host', port)."""
    rest = url.split("://", 1)[1]
    host, port = rest.rsplit(":", 1)
    return host, int(port)


class RecordStore:
    """Backend-neutral pending-record access for the tamper legs."""

    def __init__(self, backend: str, redis_url: str = "", sqlite_path: str = "",
                 files_dir: str = ""):
        self.backend = backend
        self.redis_url = redis_url
        self.sqlite_path = sqlite_path
        self.files_dir = files_dir
        self._redis = None
        self._sqlite = None

    def _r(self) -> RedisMini:
        if self._redis is None:
            host, port = redis_url_parts(self.redis_url)
            self._redis = RedisMini(host, port)
        return self._redis

    def key(self, nonce: str) -> str:
        return "kiwicaptcha:" + nonce

    def get_record(self, nonce: str) -> str | None:
        if self.backend in ("redis", "sentinel"):
            raw = self._r().get(self.key(nonce))
            return raw.decode() if raw is not None else None
        if self.backend == "sqlite":
            cur = self._s().execute(
                "SELECT record_json FROM kiwicaptcha_challenge_records WHERE nonce = ?",
                (nonce,),
            )
            row = cur.fetchone()
            return row[0] if row else None
        if self.backend == "files":
            path = self._files_path(nonce)
            if not path:
                return None
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    envelope = json.load(handle)
            except (OSError, ValueError):
                return None
            # The files adapter wraps the record in a runtime envelope
            # (state, consumed_result, retained_until); the tamper legs
            # operate on the bare record document, so unwrap here and
            # rewrap on write.
            inner = envelope.get("record") if isinstance(envelope, dict) else None
            return json.dumps(inner) if isinstance(inner, dict) else None
        raise ValueError("unknown backend %s" % self.backend)

    def put_record(self, nonce: str, raw: str) -> None:
        """Write one record document back (tamper legs) or inject it
        fresh (the forged-injection leg): upsert semantics on every
        backend, preserving the runtime envelope each adapter keeps."""
        doc = json.loads(raw)
        if self.backend in ("redis", "sentinel"):
            self._r().set(self.key(nonce), raw)
        elif self.backend == "sqlite":
            self._s().execute(
                "INSERT INTO kiwicaptcha_challenge_records"
                " (nonce, record_json, state, consumed_result_json, operation_identity,"
                "  resume_owner, resume_until, retained_until)"
                " VALUES (?, ?, 'pending', NULL, NULL, NULL, NULL, ?)"
                " ON CONFLICT(nonce) DO UPDATE SET record_json = excluded.record_json",
                (nonce, raw, int(doc.get("expires_at", 0)) + 60),
            )
            self._s().commit()
        elif self.backend == "files":
            path = self._files_path(nonce)
            envelope = None
            if path and os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as handle:
                        envelope = json.load(handle)
                except (OSError, ValueError):
                    envelope = None
            if not isinstance(envelope, dict):
                envelope = {
                    "record": None,
                    "state": "pending",
                    "consumed_result": None,
                    "operation_identity": None,
                    "retained_until": int(doc.get("expires_at", 0)) + 60,
                }
            envelope["record"] = doc
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(envelope))
        else:
            raise ValueError("unknown backend %s" % self.backend)

    def state(self, nonce: str) -> str:
        """The runtime state of one record, wherever the backend keeps
        it: a field on redis, a column on sqlite, the envelope on the
        filesystem adapter."""
        if self.backend == "sqlite":
            cur = self._s().execute(
                "SELECT state FROM kiwicaptcha_challenge_records WHERE nonce = ?",
                (nonce,),
            )
            row = cur.fetchone()
            return str(row[0]) if row else ""
        if self.backend == "files":
            path = self._files_path(nonce)
            if not path:
                return ""
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    return str(json.load(handle).get("state", ""))
            except (OSError, ValueError):
                return ""
        raw = self.get_record(nonce)
        if not raw:
            return ""
        try:
            return str(json.loads(raw).get("state", ""))
        except ValueError:
            return ""

    def snapshot(self, nonce: str) -> str | None:
        return self.get_record(nonce)

    def restore(self, nonce: str, raw: str) -> None:
        self.put_record(nonce, raw)

    def _s(self):
        import sqlite3

        if self._sqlite is None:
            self._sqlite = sqlite3.connect(self.sqlite_path, timeout=10)
        return self._sqlite

    def _files_path(self, nonce: str) -> str:
        """The adapter's own path derivation: sha256 over its record
        namespace plus the nonce, sharded by the first two hex digits,
        one json file per record. Deterministic, so the injection leg
        can create a record file exactly where the adapter reads."""
        import hashlib
        import os

        digest = hashlib.sha256(("kiwicaptcha:record:v1:" + nonce).encode()).hexdigest()
        candidate = os.path.join(self.files_dir, "records", "records", digest[:2], digest[2:] + ".json")
        if os.path.exists(candidate):
            return candidate
        found = self._files_path_by_scan(nonce)
        return found or candidate

    def _files_path_by_scan(self, nonce: str) -> str:
        """Content scan fallback: match the nonce inside the stored
        document (both the bare record and the envelope shapes)."""
        import json
        import os

        root = self.files_dir
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                path = os.path.join(dirpath, name)
                try:
                    with open(path, "r", encoding="utf-8") as handle:
                        doc = json.load(handle)
                except (OSError, ValueError):
                    continue
                if not isinstance(doc, dict):
                    continue
                if doc.get("nonce") == nonce:
                    return path
                inner = doc.get("record")
                if isinstance(inner, dict) and inner.get("nonce") == nonce:
                    return path
        return ""

    def close(self) -> None:
        if self._redis is not None:
            self._redis.close()


def _mac_tail(doc: dict) -> str:
    """The record MAC as the deployment serializes it: either the
    dedicated field of the newer core, or the hex tail after the dot
    of the signed challenge string."""
    mac = doc.get("server_mac")
    if isinstance(mac, str) and len(mac) >= 8:
        return mac
    challenge = str(doc.get("challenge", ""))
    _, _, tail = challenge.rpartition(".")
    if len(tail) >= 8:
        return tail
    return ""


def _replace_mac(doc: dict, value: str, drop: bool = False) -> dict:
    out = dict(doc)
    if "server_mac" in out:
        if drop:
            del out["server_mac"]
        else:
            out["server_mac"] = value
        return out
    challenge = str(out.get("challenge", ""))
    head, sep, _tail = challenge.rpartition(".")
    if drop:
        out["challenge"] = head
        if "prefix" in out:
            out["prefix"] = str(out["prefix"]).rpartition(".")[0]
    else:
        out["challenge"] = head + sep + value
        if "prefix" in out:
            phead, psep, _ptail = str(out["prefix"]).rpartition(".")
            out["prefix"] = phead + psep + value
    return out


def tamper_variants(record_a: str, record_b: str | None) -> dict:
    """The infrastructure mutation set over one pending record.

    Every variant returns (label, mutated_json). The deployment must
    reject a token whose stored record carries any of these. The set
    covers both record serializations in the tree (the dedicated MAC
    field and the MAC tail of the signed challenge string).
    """
    doc = json.loads(record_a)
    variants: dict = {}

    mac = _mac_tail(doc)
    if mac:
        flipped = _replace_mac(doc, ("0" if mac[0] != "0" else "1") + mac[1:])
        variants["mac-bit-flip"] = json.dumps(flipped)
        variants["mac-strip"] = json.dumps(_replace_mac(doc, "", drop=True))
        if record_b:
            other_mac = _mac_tail(json.loads(record_b))
            if other_mac:
                variants["mac-transplant"] = json.dumps(_replace_mac(doc, other_mac))

    policy = dict(doc)
    policy["policy_version"] = int(policy["policy_version"]) + 7
    variants["policy-epoch-bump"] = json.dumps(policy)

    proto = dict(doc)
    proto["protocol_version"] = int(proto["protocol_version"]) + 1
    variants["protocol-version-bump"] = json.dumps(proto)

    if "state" in doc:
        consumed = dict(doc)
        consumed["state"] = "consumed"
        variants["state-consumed-rewrite"] = json.dumps(consumed)

    skew_past = dict(doc)
    skew_past["expires_at"] = int(skew_past["expires_at"]) - 600
    skew_past["issued_at"] = int(skew_past["issued_at"]) - 600
    variants["clock-skew-minus-10min"] = json.dumps(skew_past)

    skew_future = dict(doc)
    skew_future["expires_at"] = int(skew_future["expires_at"]) + 600
    skew_future["issued_at"] = int(skew_future["issued_at"]) + 600
    variants["clock-skew-plus-10min"] = json.dumps(skew_future)

    body = dict(doc)
    prefix = str(body["prefix"])
    body["prefix"] = ("A" if prefix[0] != "A" else "B") + prefix[1:]
    variants["challenge-byte-flip"] = json.dumps(body)

    scope_swap = dict(doc)
    scope_swap["scope"] = "signup" if scope_swap["scope"] != "signup" else "login"
    variants["scope-rewrite"] = json.dumps(scope_swap)

    return variants
