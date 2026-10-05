"""Bot detection telemetry scorer, mirroring the Rust score_telemetry.

Returns True when the telemetry is characteristic of a bot. The check
is deliberately conservative: only discrete event timings count, and a
slow solve with zero interaction is never a signal, because the widget
auto-solves with widget-local listeners.
"""

from __future__ import annotations

import math
from typing import Any, Dict

_DURATION_CEILING_MS = 300_000
_MEAN_INTERVAL_FLOOR_MS = 8.0
_CV_CEILING = 0.02
_MIN_DIFFS = 23


def _bool_field(telemetry: Dict[str, Any], key: str) -> bool:
    return isinstance(telemetry.get(key), bool) and bool(telemetry.get(key))


def score(telemetry: Dict[str, Any], duration_ms: int) -> bool:
    """True when the telemetry looks bot generated.

    Three hard signals: the webdriver flag, a solve beyond 300
    seconds, and a run of at least 23 discrete event intervals whose
    mean is at least 8 ms with a coefficient of variation below 0.02.
    Perfectly uniform simulated intervals are the tell; a burst of
    sub-frame events that rounds to identical timestamps never trips.
    """
    if _bool_field(telemetry, "wd"):
        return True

    if duration_ms < 0:
        duration_ms = 0
    if duration_ms > _DURATION_CEILING_MS:
        return True

    events = telemetry.get("et")
    if isinstance(events, list):
        diffs = []
        for i in range(1, len(events)):
            t1 = events[i]
            t0 = events[i - 1]
            if (
                isinstance(t1, int) and not isinstance(t1, bool)
                and isinstance(t0, int) and not isinstance(t0, bool)
                and t1 >= 0 and t0 >= 0 and t1 >= t0
            ):
                diffs.append(t1 - t0)
        if len(diffs) >= _MIN_DIFFS:
            mean = sum(diffs) / len(diffs)
            if mean >= _MEAN_INTERVAL_FLOOR_MS:
                variance = 0.0
                for d in diffs:
                    delta = d - mean
                    variance += delta * delta
                variance /= len(diffs)
                if math.sqrt(variance) / mean < _CV_CEILING:
                    return True
    return False
