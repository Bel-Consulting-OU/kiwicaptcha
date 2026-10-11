<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

use KiwiCaptcha\Risk\Network\NetworkFlags;

/**
 * Inputs of one risk assessment.
 */
final class RiskContext
{
    public function __construct(
        public readonly int $scope,
        public readonly string $sourceIp,
        public readonly ?string $sessionId,
        public readonly ?string $principalId,
        public readonly RiskEventKind $event,
        public readonly NetworkFlags $networkFlags,
        public readonly ResourcePressure $resources,
        /**
         * The raw trusted-device cookie value (32 lowercase hex chars), or
         * null when the request presents none. The engine derives the keyed
         * device pseudonym itself (buildObservation); like the session
         * value, the raw bytes never reach storage.
         */
        public readonly ?string $deviceId = null,
    ) {
    }
}
