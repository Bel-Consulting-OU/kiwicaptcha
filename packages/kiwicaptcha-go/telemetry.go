package kiwicaptcha

import "math"

// Bot detection telemetry scoring, mirroring the Rust score_telemetry.
// The check is deliberately conservative: only discrete event timings
// count, and a slow solve with zero interaction is never a signal,
// because the widget auto-solves with widget-local listeners.
const (
	telemetryDurationCeilingMs = 300_000
	telemetryMeanFloorMs       = 8.0
	telemetryCVCeiling         = 0.02
	telemetryMinDiffs          = 23
)

// ScoreTelemetry reports whether the telemetry looks bot generated.
// Three hard signals: the webdriver flag, a solve beyond 300 seconds,
// and a run of at least 23 discrete event intervals whose mean is at
// least 8 ms with a coefficient of variation below 0.02. Perfectly
// uniform simulated intervals are the tell; a burst of sub-frame
// events that rounds to identical timestamps never trips.
func ScoreTelemetry(telemetry *JSONObject, durationMs int) bool {
	if telemetry != nil {
		if wd, ok := telemetry.Get("wd"); ok {
			if flag, isBool := wd.(bool); isBool && flag {
				return true
			}
		}
	}
	if durationMs < 0 {
		durationMs = 0
	}
	if durationMs > telemetryDurationCeilingMs {
		return true
	}
	if telemetry == nil {
		return false
	}
	eventsValue, ok := telemetry.Get("et")
	if !ok {
		return false
	}
	events, ok := eventsValue.([]interface{})
	if !ok {
		return false
	}
	diffs := make([]int, 0, len(events))
	for i := 1; i < len(events); i++ {
		current, ok1 := events[i].(jsonNumber)
		previous, ok2 := events[i-1].(jsonNumber)
		if !ok1 || !ok2 {
			continue
		}
		currentValue, err1 := parseNonNegativeInt(string(current))
		previousValue, err2 := parseNonNegativeInt(string(previous))
		if err1 != nil || err2 != nil || currentValue < previousValue {
			continue
		}
		diffs = append(diffs, currentValue-previousValue)
	}
	if len(diffs) < telemetryMinDiffs {
		return false
	}
	var sum float64
	for _, diff := range diffs {
		sum += float64(diff)
	}
	mean := sum / float64(len(diffs))
	if mean < telemetryMeanFloorMs {
		return false
	}
	var variance float64
	for _, diff := range diffs {
		delta := float64(diff) - mean
		variance += delta * delta
	}
	variance /= float64(len(diffs))
	return math.Sqrt(variance)/mean < telemetryCVCeiling
}

func parseNonNegativeInt(raw string) (int, error) {
	value := 0
	for _, by := range []byte(raw) {
		if by < '0' || by > '9' {
			return 0, &DecodeError{Code: DecodeErrInvalidCounter}
		}
		value = value*10 + int(by-'0')
		if value > 1<<31 {
			return 0, &DecodeError{Code: DecodeErrInvalidCounter}
		}
	}
	return value, nil
}
