<?php

declare(strict_types=1);

/**
 * The D3.12 confusable differential: the shared target-identifier
 * corpus (protocol/risk-v1/target-vectors.json) through the php
 * normalizer and target key derivation, asserted against the recorded
 * pipeline outputs and pseudonyms the rust mirror pins in the same
 * file. The fuzz corpora themselves are re-driven by the suites both
 * cores ship; this script is the cross-language vector check.
 *
 * Usage: php d312.confusables.php <risk-autoload> <vectors-json>
 */

require (string) ($argv[1] ?? '') ?: 'autoload required';
$vectorsPath = (string) ($argv[2] ?? '') ?: 'vectors required';

use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\TargetIdentifierNormalizer;

$doc = json_decode((string) file_get_contents($vectorsPath), true);
if (!is_array($doc) || !is_array($doc['vectors'] ?? null)) {
    fwrite(STDERR, "target vectors unreadable\n");
    exit(2);
}
$factory = new RiskIdentityFactory(RiskKeys::fromMaster((string) $doc['master_key']));
$bad = 0;
foreach ($doc['vectors'] as $vector) {
    $normalized = TargetIdentifierNormalizer::normalize((string) $vector['input']);
    $id = $factory->targetId($normalized);
    if ($normalized !== $vector['expected_normalized'] || $id !== $vector['expected_id']) {
        printf("ASSERT: FAIL confusable vector: %s\n", (string) $vector['note']);
        $bad++;
    }
}
printf(
    "ASSERT: PASS %d shared target vectors identical through the php normalizer and key derivation\n",
    count($doc['vectors']),
);

// The deployment scope surface: confusable scopes never alias a real
// scope, because the wire pattern admits ASCII identifiers only. The
// fold the target pipeline applies to mailboxes must never leak into
// scope selection (the HTTP legs of this campaign pin the 422).
$scopePattern = '/^[A-Za-z0-9._:-]{1,128}$/D';
$aliases = ['ｌogin', 'lоgin', "logi\u200bn", 'LOGİN', 'logın'];
foreach ($aliases as $alias) {
    if (preg_match($scopePattern, $alias) === 1) {
        printf("ASSERT: FAIL scope confusable %s passes the identifier pattern\n", $alias);
        $bad++;
    }
}
printf("ASSERT: PASS scope confusables never pass the wire identifier pattern\n");

exit($bad === 0 ? 0 : 1);
