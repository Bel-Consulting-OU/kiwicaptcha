"""The D3.12 parser surface probe set against the deployment."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rtclient as rt  # noqa: E402

BASE = os.environ["KIWI_RT_BASE"]


def main() -> int:
    rows = [
        ("duplicate json key", rt.verify(BASE, None, raw_body=b'{"token":"a","token":"b"}'),
         400, "DUPLICATE_JSON_KEY"),
        ("query pollution", rt.post_json(BASE + "/verify?scope=login", {"token": "x"}),
         400, "QUERY_NOT_ALLOWED"),
        ("unknown field", rt.verify(BASE, None, raw_body=b'{"token":"a","weird":1}'),
         422, "UNKNOWN_FIELDS"),
        ("nesting bomb", rt.verify(BASE, None, raw_body=b'{"token":' + b"[" * 64 + b"]" * 64 + b"}"),
         400, "JSON_NESTING_TOO_DEEP"),
        ("oversized body", rt.verify(BASE, None, raw_body=b'{"token":"' + b"A" * 20000 + b'"}'),
         413, "BODY_TOO_LARGE"),
        ("wrong type", rt.post_json(BASE + "/verify", {"token": {"nested": 1}}),
         (200, 422), "malformed_token"),
        ("wrong content type", rt.post_json(BASE + "/verify", {"token": "x"},
                                            headers={"content-type": "text/plain"}),
         415, "INVALID_CONTENT_TYPE"),
        ("gzip encoding", rt.post_json(BASE + "/verify", {"token": "x"},
                                       headers={"content-encoding": "gzip"}),
         415, "UNSUPPORTED_CONTENT_ENCODING"),
        ("unicode key homoglyph", rt.verify(BASE, None, raw_body='{"tοken":"a"}'.encode("utf-8")),
         422, "UNKNOWN_FIELDS"),
        ("escaped key duplicate", rt.verify(BASE, None, raw_body=b'{"token":"a","\\u0074oken":"b"}'),
         400, "DUPLICATE_JSON_KEY"),
    ]
    bad = 0
    for what, resp, want_status, want_code in rows:
        code = resp.code or resp.error_code
        want = want_status if isinstance(want_status, tuple) else (want_status,)
        ok = resp.status in want and code == want_code and not resp.ok
        print("ASSERT: %s parser: %s -> %s/%s"
              % ("PASS" if ok else "FAIL", what, resp.status, code))
        bad += 0 if ok else 1

    # The bad content-length probe: the http library recomputes the
    # header, so the malformed declaration goes on a raw socket, the
    # way an attacker would send it.
    import socket

    host, port = BASE.replace("http://", "").split(":")
    raw = (
        "POST /verify HTTP/1.1\r\nHost: t\r\ncontent-type: application/json\r\n"
        "content-length: abc\r\nconnection: close\r\n\r\n" '{"token":"x"}'
    ).encode()
    try:
        sock = socket.create_connection((host, int(port)), timeout=5)
        sock.sendall(raw)
        data = b""
        sock.settimeout(5)
        try:
            while len(data) < 65536:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        sock.close()
        answer = data.decode("utf8", "replace")
    except OSError:
        answer = ""
    first_line = answer.splitlines()[0] if answer else "connection closed without a response"
    # Fail-closed is the requirement: the malformed declaration is
    # either refused with a code or the connection is closed before
    # any request executes; it is never an accepted verify.
    ok = '"ok":true' not in answer and " 200 " not in (first_line + " ")
    print("ASSERT: %s parser: raw bad content-length -> %s"
          % ("PASS" if ok else "FAIL", first_line))
    bad += 0 if ok else 1

    same = rt.post_json(BASE + "/challenge?scope=login", {"scope": "login"})
    ok = same.status == 400 and same.error_code == "QUERY_NOT_ALLOWED"
    print("ASSERT: %s parser: challenge query pollution -> %s/%s"
          % ("PASS" if ok else "FAIL", same.status, same.error_code))
    bad += 0 if ok else 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
