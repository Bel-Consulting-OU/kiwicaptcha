+++
title = "How it works"
template = "page.html"
description = "A proof has a context: the challenge sequence, the algorithms, the server gates, single use, operation binding, factors and supplementary evidence."
[extra]
kicker = "MECHANISM / FROM REQUEST TO DECISION"
headline = "A proof has a context."
lede = "The challenge, its lifecycle and the application's policy travel together. Computational work is one input to acceptance; it never identifies a person by itself."
+++

<div class="section">

{{ kicker(text="sequence") }}

## Four steps, with a server boundary.

The client handles work and presentation. The application controls scope, storage, verification and acceptance.

<ol class="steps">
  <li><span class="step-no">01</span><h3>Issue</h3><p>Sign and store a challenge with nonce, scope, selected algorithm, validity and policy context.</p></li>
  <li><span class="step-no">02</span><h3>Compute</h3><p>The client runs the selected computation within the protocol caps and produces a response.</p></li>
  <li><span class="step-no">03</span><h3>Verify</h3><p>Run the cheap gates first. Consume atomically where the production storage contract supports it, derive once and retain a deterministic result.</p></li>
  <li><span class="step-no">04</span><h3>Enforce</h3><p>Apply the scope's configured policy: proceed, request more assurance, chain stronger work, quarantine or deny where the complete plane implements it.</p></li>
</ol>

{{ notes(paths=["README.md", "packages/kiwicaptcha/integrations/symfony/docs/claims-registry.md"]) }}

</div>

<div class="section">

{{ kicker(text="algorithms") }}

## Different work. Explicit contracts.

SHA-256, Argon2id and the optional sequential extension have different resource properties. A stronger-sounding algorithm is not a proof of humanity.

<div class="table-wrap">

| Work | Mechanism | Client/server limit |
| --- | --- | --- |
| SHA-256 | Hash search against leading-zero difficulty | Rust/WASM plus pure-JS fallback. Browser cap and cheap server derivation are documented. |
| Argon2id | Memory-hard search under signed parameters | Requires the supported WASM/worker path in the browser. Bound memory and verification concurrency; no silent weak fallback. |
| RSW extension | Sequential time-lock squaring under modulus identity | Experimental/versioned contract. Browser/native same-hardware speed asymmetry is unmeasured; do not invent a price or speed ratio. |

</div>

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/README.md", label="Core algorithm contract", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/docs/cost-to-abuse.md", label="Measured economic limits", external=true) }}

{{ notes(paths=["README.md", "packages/kiwicaptcha/README.md", "docs/cost-to-abuse.md"]) }}

</div>

<div class="section">

{{ kicker(text="cheap / gates") }}

## Check the context before spending the proof budget.

The verifier checks structure, authentication, validity, scope, binding and the applicable policy context before expensive proof work. Per-nonce attempt accounting and aggregate controls bound verification cost.

Those mechanisms do not make the application free to leave challenge issuance unbounded. Storage, trusted proxy policy, clock and capacity remain part of the operating contract.

{{ notes(paths=["README.md", "SECURITY.md", "packages/kiwicaptcha/integrations/symfony/docs/operations.md"]) }}

</div>

<div class="section">

{{ kicker(text="single / use") }}

## One consume. Deterministic recovery.

Atomic production storage admits one pending-to-consumed transition and proof derivation. The consumed record retains its result, so an exact-operation recovery can reproduce the original outcome.

A different operation cannot treat the same token as a fresh successful request. Ordinary SiteVerify replay and exact idempotency recovery have distinct mappings; a temporary unavailable result is not a guessed success.

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/docs/claims-registry.md", "packages/kiwicaptcha/integrations/symfony/docs/siteverify.md", "packages/kiwicaptcha/integrations/symfony/docs/security-hardening.md"]) }}

</div>

<div class="section">

{{ kicker(text="binding") }}

## Bind sensitive work to a server-owned operation.

A request binding can correlate a basic anti-abuse flow. Sensitive authorization needs a backend-issued identity and the canonical protected contents.

Current demand finalization checks operation identity and content separately. A proof for transaction A does not authorize transaction B, even if the visible amounts match. The application supplies the authoritative logical operation id, not an unchecked raw client value.

<div class="binding-grid">
  <div class="binding-cell">
    <p class="binding-label">Host attribute</p>
    <p class="binding-value">KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE</p>
  </div>
  <div class="binding-cell">
    <p class="binding-label">Current literal</p>
    <p class="binding-value mono-value">_kiwi_captcha_operation_id</p>
  </div>
</div>
<div class="binding-grid binding-grid--single">
  <div class="binding-cell">
    <p class="binding-label">Scope contract</p>
    <p class="binding-value mono-value">operation_identity_source: request_attribute</p>
  </div>
</div>

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/src/DependencyInjection/Configuration.php", "packages/kiwicaptcha/integrations/symfony/src/Security/StepUp/StepUpDemandFinalizer.php", "packages/kiwicaptcha/integrations/symfony/src/Validator/Constraints/KiwiCaptchaValidator.php"]) }}

</div>

<div class="section">

{{ kicker(text="factors") }}

## An additional factor needs a complete demand.

A current anonymous ownership demand can deliver an address code and return a scope/session-bound grant. A principal-carried demand belongs to the application's authentication flow and can use the enabled reference factors.

A passing factor is not authorization. The shared finalizer checks binding, claims the demand, reassesses policy, settles its terminal state and only then applies journaled effects such as login restoration or completion credit.

<div class="table-wrap">

| Term | Meaning |
| --- | --- |
| FactorVerified | The factor assessment passed. |
| AuthorizedStepUp | The bound demand reached an authorized terminal after its checks. |
| Protected action | The host proceeds under the authoritative decision and operation identity. |

</div>

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/src/Security/StepUp/EmailOwnershipStepUp.php", "packages/kiwicaptcha/integrations/symfony/src/Controller/StepUpController.php", "packages/kiwicaptcha/integrations/symfony/src/Security/StepUp/StepUpDemandFinalizer.php"]) }}

</div>

<div class="section">

{{ kicker(text="extensions") }}

## Supplementary evidence keeps its limits.

Timing is a heuristic; IP binding mitigates relay; decoys and client telemetry are supplementary. The execution dimension is not browser attestation, and native clients have narrower execution contracts.

Do not turn an optional dimension into a human-proof or browser-proof seal. Operators should inspect the version and rollout contract before arming it.

{{ notes(paths=["SECURITY.md", "packages/kiwicaptcha/README.md", "packages/kiwicaptcha/integrations/symfony/docs/configuration.md"]) }}

</div>

<div class="section">

{{ kicker(text="next") }}

## Choose a complete host contract.

Use the Symfony plane when you need the current complete adaptive enforcement flow. For other stacks, start from the verification client or local sidecar and preserve its stated capability boundary.

{{ linkrow(href="/integration/", label="Integration roles", arrow="↗") }}

{{ linkrow(href="/playground/", label="Lifecycle and recovery", arrow="↗") }}

{{ linkrow(href="/docs/", label="Operating requirements", arrow="↗") }}

{{ notes(paths=["README.md", "packages/kiwicaptcha-verifier/README.md"]) }}

</div>
