<?php

declare(strict_types=1);

/**
 * CLI smoke of the solve helper's execution-armed refusal: solve.php
 * must refuse an execution-armed challenge document (one carrying an
 * execution_program field) with exit code 1 and a refusal message,
 * never mint a token that verification would reject as an execution
 * mismatch. The document is otherwise a canonical sha256 challenge,
 * so the execution_program field is the only refusal trigger.
 *
 * Usage: php deploy/smoke-solve-refusal.php   (from the repository
 * root or anywhere; paths resolve from this file's location)
 */

$repo = dirname(__FILE__);
$solve = $repo.'/app/solve.php';
if (!is_file($solve)) {
    fwrite(STDERR, "smoke: cannot find the solve helper at $solve\n");
    exit(1);
}

$challenge = [
    'nonce' => base64_encode(random_bytes(32)),
    'challenge' => 'smoke',
    'salt' => base64_encode(random_bytes(16)),
    'prefix' => 'smoke',
    'targetBits' => 8,
    'algorithm' => 'sha256',
    'execution_program' => ['version' => 1, 'ops' => []],
];
$tmp = tempnam(sys_get_temp_dir(), 'kiwi-solve-smoke');
if ($tmp === false) {
    fwrite(STDERR, "smoke: cannot create a temp file\n");
    exit(1);
}
file_put_contents($tmp, json_encode($challenge, JSON_UNESCAPED_SLASHES));

$descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
$process = proc_open([PHP_BINARY, $solve, $tmp], $descriptors, $pipes);
if (!is_resource($process)) {
    fwrite(STDERR, "smoke: cannot run the solve helper\n");
    unlink($tmp);
    exit(1);
}
fclose($pipes[0]);
$stdout = stream_get_contents($pipes[1]);
$stderr = stream_get_contents($pipes[2]);
fclose($pipes[1]);
fclose($pipes[2]);
$exit = proc_close($process);
unlink($tmp);

if ($exit !== 1) {
    fwrite(STDERR, sprintf("smoke: expected exit code 1, got %d (stdout: %s)\n", $exit, var_export($stdout, true)));
    exit(1);
}
if (!is_string($stderr) || !str_contains($stderr, 'cannot solve execution-armed')) {
    fwrite(STDERR, sprintf("smoke: expected the execution-armed refusal on stderr, got %s\n", var_export($stderr, true)));
    exit(1);
}
if (is_string($stdout) && trim($stdout) !== '') {
    fwrite(STDERR, "smoke: the refusal must not print a token (got stdout output)\n");
    exit(1);
}
echo "smoke: solve.php refuses execution-armed challenges (exit 1, no token)\n";
exit(0);
