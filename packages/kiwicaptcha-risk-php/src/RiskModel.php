<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * The risk model generation implemented by this package.
 *
 * The revision is a monotonically increasing integer that identifies the
 * current risk-model generation, the scoring/calibration semantics the
 * package implements. Every decision carries the revision it was computed
 * under (`RiskDecision::$modelRevision`, exposed in the decision's public
 * JSON, bounded like every other integer field), so consumers can tell
 * which model generation produced a decision and detect mixed-model
 * fleets during a rollout.
 *
 * Revision history is monotonic (never reset). 17 is the current model
 * generation. The 16 prior generations covered the fixed-point score
 * contract, class-normalized calibration, the random-sample resolution
 * gate, the outcome ledger, the rate-of-change clamp, the non-finite
 * guards and the local-limiter warm-up ramp. This revision adds the
 * first-class rsw rung to the decision ladder (between argon64 and
 * step-up: the default bands, the marks floor, the priced band table)
 * to the model's behavior surface.
 *
 * A model revision that materially affects security (e.g. changes how
 * scores are computed or how calibration moves the bias) requires a
 * policy_version bump in the operator's policy snapshot. The decision's
 * policy_version tells consumers which operator policy produced it; the
 * model_revision tells them which model generation.
 */
final class RiskModel
{
    /** The current model generation (monotonic). */
    public const REVISION = 19;
}
