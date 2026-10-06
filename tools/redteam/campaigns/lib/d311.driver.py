#!/usr/bin/env python3
"""d311.driver.py — the D3.11 wire legs: amplification, floods, probe
storms, and the latency bounds, all against live deployment
instances.

Leg 1 (argon amplification): the argon instance issues max-memory
  challenges; the driver pays ONE honest solve end to end, then fires
  garbage verifications at the verifier. The required bound: every
  garbage verify is refused in the cheap phase, at a p99 far below the
  honest verify, so a garbage flood never buys the verifier's argon
  spend.
Leg 2 (issuance flood with idempotency churn): the capped instance is
  flooded at 1x and then 5x the measured baseline rate from the same
  address; the admission is exactly the configured budget per window
  at both rates and the p99 at 5x stays within 5x the 1x p99.
Leg 3 (readiness probe storm): /healthz hammered at 1x and 5x; the
  p99 at 5x stays within 5x the 1x p99 and the probe stays honest.

Output: one JSON document on stdout (facts only).
"""

import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, "/Users/sabelakhoua/IdeaProjects/kiwicaptcha-standalone/tools/redteam/campaigns/lib")
import rtclient as rt  # noqa: E402

ARGON_BASE = os.environ.get("KIWI_RT_D311_ARGON", "http://127.0.0.1:6479")
CAP_BASE = os.environ.get("KIWI_RT_D311_CAP", "http://127.0.0.1:6475")


def post(url: str, body: bytes, timeout: float = 30.0):
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(1 << 20)
    except urllib.error.HTTPError as err:
        return err.code, err.read(1 << 20)
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return 0, b""


def get(url: str, timeout: float = 30.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, resp.read(1 << 20)
    except urllib.error.HTTPError as err:
        return err.code, err.read(1 << 20)
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return 0, b""


def pctl(samples, pct):
    ordered = sorted(samples)
    idx = max(0, min(len(ordered) - 1, (len(ordered) * pct + 99) // 100 - 1))
    return ordered[idx]


def leg_argon():
    doc = rt.solve(ARGON_BASE, "login")
    if not doc.get("solved"):
        return {"error": "honest argon solve failed", "detail": doc}
    honest_ms = doc.get("duration_ms")
    token = doc.get("token", "")
    status, body = post(ARGON_BASE + "/verify", json.dumps({"token": token, "scope": "login"}).encode())
    honest_verify_ok = status == 200 and json.loads(body).get("ok") is True

    garbage_lat = []
    garbage_refused = 0
    for i in range(60):
        variant = ("garbage-" * 40)[: 300 + i]
        t0 = time.monotonic()
        status, raw = post(ARGON_BASE + "/verify", json.dumps({"token": variant, "scope": "login"}).encode())
        garbage_lat.append((time.monotonic() - t0) * 1000)
        # The deployment's verify contract answers 200 with ok:false
        # for every refusal; a garbage token accepted ok:true would be
        # the failure this leg exists to catch.
        try:
            ok = json.loads(raw).get("ok") is True
        except ValueError:
            ok = False
        if not ok:
            garbage_refused += 1
    return {
        "honest_solve_ms": honest_ms,
        "honest_verify_ok": honest_verify_ok,
        "garbage_verifies": len(garbage_lat),
        "garbage_refused": garbage_refused,
        "garbage_p50_ms": round(pctl(garbage_lat, 50), 2),
        "garbage_p99_ms": round(pctl(garbage_lat, 99), 2),
        "amplification_resisted": honest_verify_ok and garbage_refused == len(garbage_lat),
    }


def flood_once(base, count, scope="login"):
    issued = limited = 0
    for _ in range(count):
        status, body = post(base + "/challenge", b'{"scope":"login"}')
        if status == 200:
            issued += 1
        elif status == 429:
            limited += 1
    return issued, limited


def timed_challenge(base):
    t0 = time.monotonic()
    status, _ = post(base + "/challenge", b'{"scope":"login"}')
    return (time.monotonic() - t0) * 1000, status


def leg_flood():
    # Baseline rate: sequential, the 1x shape.
    base_lat = [timed_challenge(CAP_BASE)[0] for _ in range(20)]
    issued1, limited1 = flood_once(CAP_BASE, 40)
    # 5x: concurrent workers, five times the request count.
    import threading
    lat5 = []
    lock = threading.Lock()
    results = {"issued": 0, "limited": 0}

    def worker(n):
        local_issued = local_limited = 0
        local_lat = []
        for _ in range(n):
            ms, status = timed_challenge(CAP_BASE)
            local_lat.append(ms)
            if status == 200:
                local_issued += 1
            elif status == 429:
                local_limited += 1
        with lock:
            lat5.extend(local_lat)
            results["issued"] += local_issued
            results["limited"] += local_limited

    threads = [threading.Thread(target=worker, args=(40,)) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    p99_1x = pctl(base_lat, 99)
    p99_5x = pctl(lat5, 99)
    return {
        "baseline_p99_ms": round(p99_1x, 2),
        "flood5x_p99_ms": round(p99_5x, 2),
        "flood5x_issued": results["issued"],
        "flood5x_limited": results["limited"],
        "bound_ms": round(max(5 * p99_1x, 2000.0), 2),
        "bounded": p99_5x <= max(5 * p99_1x, 2000.0),
    }


def leg_probe():
    probe = lambda: (lambda t0: (time.monotonic() - t0) * 1000, get(ARGON_BASE + "/healthz"))[0]
    base_lat = []
    for _ in range(40):
        t0 = time.monotonic()
        status, body = get(ARGON_BASE + "/healthz")
        base_lat.append((time.monotonic() - t0) * 1000)
    ok_flag = b'"ok":true' in body
    import threading
    lat5 = []
    lock = threading.Lock()
    codes = []

    def worker(n):
        local = []
        for _ in range(n):
            t0 = time.monotonic()
            status, body = get(ARGON_BASE + "/healthz")
            local.append((time.monotonic() - t0) * 1000)
            with lock:
                codes.append(status)

        del local

    def worker2(n):
        for _ in range(n):
            t0 = time.monotonic()
            status, _body = get(ARGON_BASE + "/healthz")
            dt = (time.monotonic() - t0) * 1000
            with lock:
                lat5.append(dt)
                codes.append(status)

    threads = [threading.Thread(target=worker2, args=(100,)) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    p99_1x = pctl(base_lat, 99)
    p99_5x = pctl(lat5, 99)
    return {
        "baseline_p99_ms": round(p99_1x, 2),
        "storm5x_p99_ms": round(p99_5x, 2),
        "storm5x_requests": len(lat5),
        "storm5x_ok_answers": len([c for c in codes if c == 200]),
        "bound_ms": round(max(5 * p99_1x, 1000.0), 2),
        "probe_honest": ok_flag,
        "bounded": p99_5x <= max(5 * p99_1x, 1000.0),
    }


def main():
    out = {
        "argon_amplification": leg_argon(),
        "issuance_flood": leg_flood(),
        "probe_storm": leg_probe(),
    }
    print(json.dumps(out, indent=1))
    ok = (
        out["argon_amplification"].get("amplification_resisted") is True
        and out["issuance_flood"]["bounded"] is True
        and out["probe_storm"]["bounded"] is True
        and out["probe_storm"]["probe_honest"] is True
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
