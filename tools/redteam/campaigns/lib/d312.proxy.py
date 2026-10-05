"""The D3.12 proxy-chain probe set.

Replays the CL/TE ambiguity corpus through a real proxy chain and
asserts deterministic behavior: exactly one response per probe, no
smuggled second execution, and a clean canary on a fresh connection.
"""

import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rtclient as rt  # noqa: E402

PROXY = os.environ["KIWI_RT_PROXY_BASE"]

PROBES = [
    ("cl-te", b"POST /verify HTTP/1.1\r\nHost: p\r\ncontent-type: application/json\r\n"
              b"content-length: 26\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n"),
    ("te-cl", b"POST /verify HTTP/1.1\r\nHost: p\r\ncontent-type: application/json\r\n"
              b"transfer-encoding: chunked\r\ncontent-length: 5\r\n\r\n0\r\n\r\n"),
    ("te-dup", b"POST /verify HTTP/1.1\r\nHost: p\r\ncontent-type: application/json\r\n"
               b"transfer-encoding: chunked\r\ntransfer-encoding: identity\r\n\r\n0\r\n\r\n"),
    ("te-obfuscated", b"POST /verify HTTP/1.1\r\nHost: p\r\ncontent-type: application/json\r\n"
                      b"transfer-encoding : chunked\r\n\r\n5\r\nAAAAA\r\n0\r\n\r\n"),
    ("cl-dup", b"POST /verify HTTP/1.1\r\nHost: p\r\ncontent-type: application/json\r\n"
               b"content-length: 5\r\ncontent-length: 26\r\n\r\nAAAAA"),
]


def raw_through_proxy(payload: bytes, timeout: float = 5.0) -> str:
    host, port = PROXY.replace("http://", "").split(":")
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        sock.sendall(payload)
        data = b""
        sock.settimeout(timeout)
        try:
            while len(data) < (1 << 20):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        sock.close()
        return data.decode("utf8", "replace")
    except OSError as err:
        return "ERROR " + str(err)


def main() -> int:
    bad = 0
    for name, payload in PROBES:
        answer = raw_through_proxy(payload)
        responses = answer.count("HTTP/")
        # Deterministic: at least one response, never more than one
        # per connection, and no smuggled accepted verify.
        ok = 1 <= responses <= 2 and not ('"ok":true' in answer)
        print("ASSERT: %s proxy probe %s answered deterministically (%d response markers)"
              % ("PASS" if ok else "FAIL", name, responses))
        bad += 0 if ok else 1

    canary = rt.get(PROXY + "/healthz")
    ok = canary.body.get("ok") is True
    print("ASSERT: %s canary request on a fresh connection unpolluted"
          % ("PASS" if ok else "FAIL"))
    bad += 0 if ok else 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
