package com.kiwicaptcha;

import java.util.List;

/**
 * Bot detection telemetry scoring, mirroring the Rust
 * score_telemetry. The check is deliberately conservative: only
 * discrete event timings count, and a slow solve with zero interaction
 * is never a signal, because the widget auto-solves with widget-local
 * listeners.
 */
public final class Telemetry {
    private Telemetry() {}

    private static final long TELEMETRY_DURATION_CEILING_MS = 300_000;
    private static final double TELEMETRY_MEAN_FLOOR_MS = 8.0;
    private static final double TELEMETRY_CV_CEILING = 0.02;
    private static final int TELEMETRY_MIN_DIFFS = 23;

    /**
     * Reports whether the telemetry looks bot generated. Three hard
     * signals: the webdriver flag, a solve beyond 300 seconds, and a
     * run of at least 23 discrete event intervals whose mean is at
     * least 8 ms with a coefficient of variation below 0.02. Perfectly
     * uniform simulated intervals are the tell; a burst of sub-frame
     * events that rounds to identical timestamps never trips.
     */
    public static boolean scoreTelemetry(JsonObject telemetry, long durationMs) {
        if (telemetry != null) {
            Object wd = telemetry.get("wd");
            if (wd instanceof Boolean flag && flag) {
                return true;
            }
        }
        long duration = Math.max(durationMs, 0);
        if (duration > TELEMETRY_DURATION_CEILING_MS) {
            return true;
        }
        if (telemetry == null) {
            return false;
        }
        Object eventsValue = telemetry.get("et");
        if (!(eventsValue instanceof List<?> rawEvents)) {
            return false;
        }
        long[] diffs = new long[Math.max(0, rawEvents.size() - 1)];
        int count = 0;
        for (int i = 1; i < rawEvents.size(); i++) {
            Long current = parseNonNegative(rawEvents.get(i));
            Long prior = parseNonNegative(rawEvents.get(i - 1));
            if (current == null || prior == null || current < prior) {
                continue;
            }
            diffs[count++] = current - prior;
        }
        if (count < TELEMETRY_MIN_DIFFS) {
            return false;
        }
        double sum = 0;
        for (int i = 0; i < count; i++) {
            sum += diffs[i];
        }
        double mean = sum / count;
        if (mean < TELEMETRY_MEAN_FLOOR_MS) {
            return false;
        }
        double variance = 0;
        for (int i = 0; i < count; i++) {
            double delta = diffs[i] - mean;
            variance += delta * delta;
        }
        variance /= count;
        return Math.sqrt(variance) / mean < TELEMETRY_CV_CEILING;
    }

    /** Parses one event literal as a non negative integer, or null. */
    private static Long parseNonNegative(Object raw) {
        if (!(raw instanceof JsonNumber number)) {
            return null;
        }
        String text = number.raw;
        long value = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < '0' || c > '9') {
                return null;
            }
            value = value * 10 + (c - '0');
            if (value > (1L << 31)) {
                return null;
            }
        }
        return value;
    }
}
