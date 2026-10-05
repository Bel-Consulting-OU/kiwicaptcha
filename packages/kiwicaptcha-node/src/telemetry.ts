/**
 * The opt-in telemetry bot-signal gate, mirroring the PHP Telemetry
 * score and the Rust arithmetic exactly. Three bot classes, deliberately
 * conservative: webdriver, a solve beyond 300 seconds, and uniform
 * discrete event intervals (perfect coefficient of variation).
 */

export function scoreTelemetry(telemetry: Record<string, unknown>, durationMs: number): boolean {
  if (telemetry['wd'] === true) {
    return true;
  }
  // A negative duration cannot arrive over the wire (the token decoder
  // accepts canonical digit strings only), but clamp for parity.
  const duration = durationMs < 0 ? 0 : durationMs;
  if (duration > 300_000) {
    return true;
  }
  const events = telemetry['et'];
  if (!Array.isArray(events)) {
    return false;
  }
  const diffs: number[] = [];
  for (let i = 1; i < events.length; i++) {
    const t1 = events[i];
    const t0 = events[i - 1];
    // Only non-negative integers count; floats, strings and negatives
    // break the pair chain exactly as serde_json's u64 coercion would.
    if (
      typeof t1 === 'number' && Number.isInteger(t1) && t1 >= 0 &&
      typeof t0 === 'number' && Number.isInteger(t0) && t0 >= 0 &&
      t1 >= t0
    ) {
      diffs.push(t1 - t0);
    }
  }
  if (diffs.length < 23) {
    return false;
  }
  let sum = 0;
  for (const d of diffs) {
    sum += d;
  }
  const mean = sum / diffs.length;
  if (mean < 8.0) {
    return false;
  }
  let variance = 0;
  for (const d of diffs) {
    const diff = d - mean;
    variance += diff * diff;
  }
  variance /= diffs.length;
  const cv = Math.sqrt(variance) / mean;
  return cv < 0.02;
}
