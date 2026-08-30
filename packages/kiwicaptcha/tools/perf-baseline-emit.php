<?php

declare(strict_types=1);

/**
 * Machine-readable baseline emission for the perf tools.
 *
 * The five timing tools (perf-bench.php, perf-bench-risk.php,
 * perf-load.php, perf-wait.php and perf-wait-replica.php) share this
 * helper. Each tool accepts --baseline-out with a target path and
 * merges its measured values into the committed record
 * tools/perf-baselines.json, the single source of truth for the
 * performance-analysis document. The merge is section-scoped: a tool
 * replaces only its own subtree and preserves every other section, so
 * running the five tools in sequence after a deliberate change
 * regenerates the record in place. The write is atomic (a temp file in
 * the same directory plus a rename), so an interrupted run never
 * leaves a truncated record. The record is updated only by hand on a
 * clean local machine with --baseline-out; the CI timing steps never
 * write it.
 */

function perf_baseline_read(string $file): array
{
    if (!is_file($file)) {
        return [];
    }
    $raw = (string) file_get_contents($file);
    if (trim($raw) === '') {
        return [];
    }
    try {
        $data = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        throw new RuntimeException(sprintf('perf-baseline: %s is not valid JSON', $file));
    }

    return is_array($data) ? $data : [];
}

/**
 * Merge the measured values into the record at the given path and
 * write the file back atomically. The path is a nested key list; the
 * values replace the whole subtree at that path. The generated stamp
 * is refreshed on every write.
 *
 * @param list<string> $path
 */
function perf_baseline_emit(string $file, array $path, array $values): void
{
    $data = perf_baseline_read($file);
    $cursor = &$data;
    foreach ($path as $key) {
        if (!isset($cursor[$key]) || !is_array($cursor[$key])) {
            $cursor[$key] = [];
        }
        $cursor = &$cursor[$key];
    }
    $cursor = $values;
    unset($cursor);
    $data['generated'] = date('Y-m-d');
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)."\n";
    $tmp = $file.'.tmp'.getmypid();
    if (file_put_contents($tmp, $json) === false) {
        throw new RuntimeException(sprintf('perf-baseline: cannot write %s', $tmp));
    }
    if (!rename($tmp, $file)) {
        @unlink($tmp);
        throw new RuntimeException(sprintf('perf-baseline: cannot replace %s', $file));
    }
}
