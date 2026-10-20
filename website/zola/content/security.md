+++
title = "Security"
template = "page.html"
description = "Friction, then enforcement: the bounded anti-abuse model, protection profiles, completable factors, operation authorization, typed outcomes, economics and the verifier's own resource envelope."
[extra]
kicker = "SECURITY / EXPLICIT DECISIONS"
headline = "Friction, then enforcement."
lede = "The mechanism is public. Your application owns the policy and the final action. Keep the proof, factor and authorization boundaries explicit."
+++

<div class="section">

{{ kicker(text="model") }}

## A bounded anti-abuse model.

Computational work prices an attempt, not a person. Outsourced solvers, device pools and automation can pay it. Timing, decoys, IP binding and client evidence stay supplementary.

The current complete plane adds configured step-up, quarantine and denial. It still cannot rescue a compromised application, Redis instance or page script, or replace your transport and authentication architecture.

{{ notes(paths=["SECURITY.md", "README.md"]) }}

</div>

<div class="section">

{{ kicker(text="profiles") }}

## Choose the posture your deployment can complete.

Profiles fill derived settings as the lowest-precedence layer. Explicit values in any layer win, within the forced privacy and validation rules; explicit null can clear a profile.

Use the source code and installed doctor for effective configuration. The current numeric documentation table has drift from profile code, so this website describes purpose rather than restating it as an exact matrix.

<div class="table-wrap">

| Profile | Purpose | Operator implication |
| --- | --- | --- |
| balanced | Neutral documented baseline | Risk and factor setup are not automatically a full abuse posture. |
| privacy_strict | Strongest named privacy posture | Drops non-IP binding and forces sensitive evidence off; accept relay-mitigation tradeoff. |
| high_abuse / abuse_first | Same adaptive abuse posture | Wire its datasets, factors, real delivery, routes, scope/operation and protocol prerequisites. |
| compatibility | Documented provider/lifecycle migration posture | Binding/risk/features differ; no universal provider-score emulation. |
| ha_safe | Pinned-primary authority posture | Explicit initialization and supported Redis topology; no automatic production pin. |

</div>

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/integrations/symfony/src/DependencyInjection/ProtectionProfileDefaults.php", label="Profile code at reviewed HEAD", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/integrations/symfony/docs/configuration.md", label="Effective configuration reference", external=true) }}

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/docs/configuration.md", "packages/kiwicaptcha/integrations/symfony/src/DependencyInjection/ProtectionProfileDefaults.php", "packages/kiwicaptcha/integrations/symfony/tests/ProtectionProfileLayeringTest.php"]) }}

</div>

<div class="section">

{{ kicker(text="complete / carriers") }}

## A demanded factor must have a path to completion.

Current abuse defaults use post-credential assurance for admin login, an anonymous ownership carrier for signup and a named principal factor with operation identity for financial_action.

A blanket step-up minimum at issuance can block the visitor before any widget or credential flow. A carrier without real delivery, an available factor, reachable routes or a resolvable principal is incomplete. The current doctor checks those relationships.

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/src/DependencyInjection/ProtectionProfileDefaults.php", "packages/kiwicaptcha/integrations/symfony/src/DependencyInjection/Configuration.php", "packages/kiwicaptcha/integrations/symfony/src/Command/KiwiCaptchaDoctorCommand.php", "packages/kiwicaptcha/integrations/symfony/src/DependencyInjection/KiwiCaptchaExtension.php"]) }}

</div>

<div class="section">

{{ kicker(text="operation") }}

## Authorize this action, not a reusable pass.

The shared finalizer distinguishes FactorVerified from AuthorizedStepUp. It reproduces operation bindings, acquires finalization, reassesses risk, settles terminal authorization and only then journals completion effects.

Sensitive operations need a server-owned logical identity and canonical protected contents. An authorized demand for one action must not become credit to authorize another, even when the payload looks identical.

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/src/Security/StepUp/StepUpDemandFinalizer.php", "packages/kiwicaptcha/integrations/symfony/src/Validator/Constraints/KiwiCaptchaValidator.php", "packages/kiwicaptcha/integrations/symfony/src/Controller/StepUpController.php"]) }}

</div>

<div class="section">

{{ kicker(text="outcomes") }}

## Explain decisions without displaying identity material.

The configured risk explanation exposes names, action and work rung rather than pseudonym strings. Typed application outcomes provide confirmed feedback to the risk system; the application, not client telemetry, confirms legitimacy or abuse.

Outcome reporting and factor completion are not permission to bypass the authoritative request decision.

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/docs/configuration.md", "packages/kiwicaptcha/integrations/symfony/docs/risk-engine.md", "packages/kiwicaptcha/integrations/symfony/src/Security/StepUp/StepUpDemandFinalizer.php"]) }}

</div>

<div class="section">

{{ kicker(text="economics") }}

## Work cannot carry every stake.

The dedicated economic contract reports default browser-feasible work below declared abuse value. High-value policy needs a complete enforcement answer, not an invented claim that a few more bits make all abuse unprofitable.

The sequential extension still has an open browser/native same-hardware measurement. No speed ratio, savings statistic or hardware-cost promise is supplied by this identity or website.

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/docs/cost-to-abuse.md", label="Cost-to-abuse analysis", external=true) }}

{{ notes(paths=["docs/cost-to-abuse.md", "packages/kiwicaptcha/integrations/symfony/src/Command/KiwiCaptchaDoctorCommand.php"]) }}

</div>

<div class="section">

{{ kicker(text="resources") }}

## Protect the verifier as well as the form.

Rate-limit issuance, bound outstanding challenges and cap verification concurrency. Memory-hard verification needs a fixed resource envelope and admission control.

The security Redis is authoritative state, not a disposable cache. Preserve noeviction, TTL margin and the replication/promotion contract. A verified acknowledgement alone does not control which replica a failover manager promotes.

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/deploy/README.md", label="Deployment and capacity guide", external=true) }}

{{ notes(paths=["SECURITY.md", "packages/kiwicaptcha/integrations/symfony/docs/operations.md", "deploy/README.md"]) }}

</div>
