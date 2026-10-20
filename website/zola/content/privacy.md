+++
title = "Privacy"
template = "page.html"
description = "The KiwiCaptcha privacy model: first-party runtime, telemetry off by default, mode-specific evidence contracts, strict posture and inspectable retention scope."
[extra]
kicker = "PRIVACY / FIRST-PARTY RUNTIME"
headline = "First-party defaults you can inspect."
lede = "The default runtime path stays on your application's origin. Behavioral telemetry is off by default, and strict privacy mode forces its documented restrictions. Read the contracts instead of relying on an absolute no-data slogan."
+++

<div class="section">

{{ kicker(text="defaults") }}

## The runtime stays on your origin.

The widget, its worker and the challenge endpoints are served by the integrating application. There is no third-party script host, no cross-origin beacon and no behavioral telemetry by default. The optional telemetry module is a documented, explicit enablement.

Completion copy describes computation only. The browser produces a response token; the host's verification, lifecycle and policy remain the acceptance boundary, and identity claims stay with the application.

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/docs/privacy.md", "packages/kiwicaptcha-wasm/assets/widget-telemetry.js", "SECURITY.md"]) }}

</div>

<div class="section">

{{ kicker(text="evidence") }}

## Every stored field has a purpose and a scope.

Challenge records bind scope, session, subject context and policy; ownership grants bind the verified address control to a scope and session; risk state is kept per scope and per pseudonym, not per raw address. Purpose separation is enforced in the storage contracts, and the privacy sweep enumerates every stored Redis type so an operator can audit exactly what exists.

Stored identifiers are not reversible handles. Network-identity material is stored as a keyed HMAC so a database disclosure does not hand out addresses; the explanation surfaces use names, action and work rung rather than pseudonym strings.

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/docs/privacy.md", "packages/kiwicaptcha/integrations/symfony/docs/claims-registry.md", "packages/kiwicaptcha/integrations/symfony/docs/risk-engine.md"]) }}

</div>

<div class="section">

{{ kicker(text="strict posture") }}

## privacy_strict forces its restrictions.

The privacy_strict profile drops non-IP binding and forces sensitive evidence off by configuration, not by promise. The tradeoff is explicit: relay mitigations that depend on those bindings weaken, and the deployment accepts that in exchange for the narrower stored surface.

Explicit values in any layer still win within the forced privacy and validation rules. Read the effective configuration from the installed doctor rather than assuming a profile name implies a universal guarantee.

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/integrations/symfony/src/DependencyInjection/ProtectionProfileDefaults.php", label="Profile code at reviewed HEAD", external=true) }}

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/docs/configuration.md", "packages/kiwicaptcha/integrations/symfony/src/DependencyInjection/ProtectionProfileDefaults.php", "packages/kiwicaptcha/integrations/symfony/tests/ProtectionProfileLayeringTest.php"]) }}

</div>

<div class="section">

{{ kicker(text="retention") }}

## Retention is bounded by the record contracts.

Challenges, grants, factor demands and risk marks carry their own expiries. Expired records disappear by TTL, consumed records retain only what deterministic recovery needs, and the swept canary run drives a real email and user-name through the privacy paths so the erasure behavior is exercised, not asserted.

Ownership factors store control of an address, not the address as identity. Principal-carrying demands belong to the application's authentication flow and use pseudonyms scoped per purpose.

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/docs/privacy.md", "packages/kiwicaptcha/integrations/symfony/docs/operations.md"]) }}

</div>

<div class="section">

{{ kicker(text="claims") }}

## Bounded claims, in one registry.

The claims registry records each product claim with its assumptions, evidence and maintenance owner. Privacy copy follows the same rule as the rest of the brand: mode-specific statements, no absolute no-data slogans, and no fabricated assurances.

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/integrations/symfony/docs/claims-registry.md", label="Claims registry", external=true) }}

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/docs/claims-registry.md", "packages/kiwicaptcha/design/IDENTITY.md"]) }}

</div>
