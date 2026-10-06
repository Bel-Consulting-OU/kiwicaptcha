#!/usr/bin/env bash
# stepup-store-status.sh — the repro of the step-up store's strict
# reply comparison. The store accepts only the exact string 'OK' or
# boolean true from SET NX; a real Predis client answers a
# Predis\Response\Status object whose string form is 'OK', so every
# create() on a real deployment client throws and every step-up begin
# fails closed. The bundle's own tests pass only because the fake
# client returns the literal string.
#
# Deterministic transcript: fixed challenge id, the key is deleted
# first, and the output is a single stable json line.

set -u
RT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
REPO_ROOT=$(cd "$RT_DIR/../.." && pwd)

redis-cli -p 6476 del '{kiwi:rt37repro}:stepup:challenge:fixedReproId0000000000' >/dev/null 2>&1

REPLY=$(php -r '
require "'"$REPO_ROOT"'/tools/redteam/campaigns/lib/rt-risk-prelude.php";
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\RedisStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use Symfony\Component\HttpFoundation\Request;
$client = new Predis\Client("redis://127.0.0.1:6476", ["timeout" => 2.0]);
$store = new RedisStepUpChallengeStore($client, "{kiwi:rt37repro}:stepup:");
$handler = new TotpStepUpHandler(
    $store,
    new StepUpTicket("d37mast3rd37mast3rd37mast3rd37mast3r"),
    new StepUpCompletionCredit(new SpyOutcomeReporter(), "d37mast3rd37mast3rd37mast3rd37mast3r"),
    "sha1", 6, 1, 300, 5, 100, 900, "/kiwi/step-up/complete",
    static fn (): int => 1700000000,
);
$principal = str_repeat("3", 32);
$handler->enroll($principal);
try {
    $response = $handler->begin(Request::create("https://captcha.example.com/kiwi/step-up/begin"), new StepUpContext($principal, str_repeat("a", 32), "login", null, "post_solve_step_up_required"));
    echo json_encode(["begin_status" => $response->getStatusCode()]), "\n";
} catch (Throwable $e) {
    echo json_encode(["begin_status" => "exception", "message" => $e->getMessage()]), "\n";
}
')

redis-cli -p 6476 del '{kiwi:rt37repro}:stepup:challenge:fixedReproId0000000000' >/dev/null 2>&1

printf '%s\n' "$REPLY"
printf '%s\n' "$REPLY" | python3 -c '
import json, sys
doc = json.load(sys.stdin)
if doc["begin_status"] == 429 or doc["begin_status"] == "exception":
    verdict = "REPRODUCED"
else:
    verdict = "REFUTED"
print(json.dumps({"class": "stepup-store-status-refusal", "verdict": verdict, "detail": doc}))
'
