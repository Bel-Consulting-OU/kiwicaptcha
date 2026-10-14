<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * 13 fixed-point signal fields (each 0..1000), in the exact contract order.
 *
 * JSON key order in the fixtures and `toArray()` must match:
 *   source_fast, source_slow, subnet_fast, issue_debt, bad_proof, malformed,
 *   replay, action_failure, scope_switch, global_pressure, network_risk,
 *   trust_credit, principal_credit
 */
final class SignalVector
{
    public function __construct(
        public readonly int $sourceFast,
        public readonly int $sourceSlow,
        public readonly int $subnetFast,
        public readonly int $issueDebt,
        public readonly int $badProof,
        public readonly int $malformed,
        public readonly int $replay,
        public readonly int $actionFailure,
        public readonly int $scopeSwitch,
        public readonly int $globalPressure,
        public readonly int $networkRisk,
        public readonly int $trustCredit,
        public readonly int $principalCredit,
    ) {
        foreach (get_object_vars($this) as $value) {
            if ($value < 0 || $value > 1000) {
                throw new \InvalidArgumentException(
                    sprintf('Signal values must be within 0..1000 (got %d)', $value)
                );
            }
        }
    }

    public static function zero(): self
    {
        return new self(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    /**
     * Accepts snake_case keys per the fixtures; a missing key defaults
     * to 0. The decode is integer-only, exactly like the Rust twin's
     * serde decode and like {@see RiskWeights::fromArray()}. A float, a
     * numeric string or an array would otherwise be silently cast here
     * while the Rust parser rejects it. The canonical fixture hash,
     * whose number formatting differs between the languages, would then
     * diverge. The 0..1000 range stays the constructor's own contract.
     */
    public static function fromArray(array $data): self
    {
        $int = static function (array $row, string $key): int {
            if (!\array_key_exists($key, $row)) {
                return 0;
            }
            $value = $row[$key];
            if (!\is_int($value)) {
                throw new \InvalidArgumentException(sprintf(
                    'Signal vector field %s must be an integer (got %s); floats, numeric strings and arrays are not admissible because the canonical fixture hash must be identical in PHP and Rust',
                    $key,
                    get_debug_type($value),
                ));
            }

            return $value;
        };

        return new self(
            sourceFast: $int($data, 'source_fast'),
            sourceSlow: $int($data, 'source_slow'),
            subnetFast: $int($data, 'subnet_fast'),
            issueDebt: $int($data, 'issue_debt'),
            badProof: $int($data, 'bad_proof'),
            malformed: $int($data, 'malformed'),
            replay: $int($data, 'replay'),
            actionFailure: $int($data, 'action_failure'),
            scopeSwitch: $int($data, 'scope_switch'),
            globalPressure: $int($data, 'global_pressure'),
            networkRisk: $int($data, 'network_risk'),
            trustCredit: $int($data, 'trust_credit'),
            principalCredit: $int($data, 'principal_credit'),
        );
    }

    /** Snake_case keys in contract order. */
    public function toArray(): array
    {
        return [
            'source_fast' => $this->sourceFast,
            'source_slow' => $this->sourceSlow,
            'subnet_fast' => $this->subnetFast,
            'issue_debt' => $this->issueDebt,
            'bad_proof' => $this->badProof,
            'malformed' => $this->malformed,
            'replay' => $this->replay,
            'action_failure' => $this->actionFailure,
            'scope_switch' => $this->scopeSwitch,
            'global_pressure' => $this->globalPressure,
            'network_risk' => $this->networkRisk,
            'trust_credit' => $this->trustCredit,
            'principal_credit' => $this->principalCredit,
        ];
    }

    /**
     * The JSON object form. The payload must decode to a JSON object,
     * never a list and never a scalar. A list would otherwise reach
     * {@see self::fromArray()} with no snake_case keys and answer a
     * silent all-zero vector, which is a wrong answer dressed as a
     * valid one.
     */
    public static function fromJson(string $json): self
    {
        $data = json_decode($json, false);
        if (!$data instanceof \stdClass) {
            throw new \InvalidArgumentException('SignalVector JSON must decode to an object');
        }

        return self::fromArray((array) $data);
    }
}
