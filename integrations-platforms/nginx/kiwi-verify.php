<?php

/**
 * Deploy shim: the canonical shared gateway endpoint lives at
 * integrations-platforms/kiwi-verify.php — one copy, no drift.
 *
 * In a repository checkout this shim loads the canonical endpoint so
 * in-tree paths keep working. In a deployment, copy the CANONICAL
 * file (integrations-platforms/kiwi-verify.php) to your web root as
 * kiwi-verify.php; do not copy this shim alone, or the require below
 * will not find the endpoint and the gate fails closed with 500.
 */

declare(strict_types=1);

$kiwi_canonical = dirname(__DIR__).'/kiwi-verify.php';
if (!is_file($kiwi_canonical)) {
    http_response_code(500);
    header('Content-Type: text/plain');
    echo "kiwi-verify.php: the canonical endpoint is missing.\n";
    echo "Copy integrations-platforms/kiwi-verify.php here.\n";
    exit(1);
}
require $kiwi_canonical;
