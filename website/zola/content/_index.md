+++
title = "KiwiCaptcha"
template = "index.html"
description = "Computational checks, ownership factors and transaction-bound authorization under your application's policy."
+++

<div class="section">

{{ kicker(text="why") }}

## A check for the request. A policy for the action.

Repeated signup, login, password-reset and protected-request attempts need more than a decorative security badge. Computational work attaches real friction to an attempt; your application verifies the response and decides whether more assurance or a refusal is appropriate.

A person does not solve the PoW by hand. Their device computes it, and an automated client can do the same. KiwiCaptcha's current value combines that friction with self-hosted step-up, quarantine and denial.

<div class="why-grid">
  <div class="why-card"><h3>Signup</h3><p>Keep the work and address-ownership carrier tied to the protected scope.</p></div>
  <div class="why-card"><h3>Login</h3><p>Separate browser work from credential checks and post-credential assurance.</p></div>
  <div class="why-card"><h3>Sensitive actions</h3><p>Authorize the specific server-owned operation, not a reusable general pass.</p></div>
  <div class="why-card"><h3>Repeated requests</h3><p>Bound issuance, verification and aggregate pressure around your policy.</p></div>
</div>

{{ notes(paths=["README.md", "docs/cost-to-abuse.md"]) }}

</div>

<div class="section">

{{ kicker(text="mechanism") }}

## Challenge. Work. Decision.

Your application issues a scoped, expiring challenge. The browser computes the selected work. Your server checks the signed context, consumes the proof under the configured storage rules and applies the final policy.

A completed widget is a response to verify. A verified factor is still subject to demand finalization. Keep both boundaries visible in the product and in your integration.

{{ linkrow(href="/playground/", label="See the full lifecycle", arrow="↗") }}

{{ notes(paths=["README.md", "packages/kiwicaptcha/integrations/symfony/src/Security/StepUp/StepUpDemandFinalizer.php", "packages/kiwicaptcha-wasm/assets/widget-driver.js"]) }}

</div>

<div class="section">

{{ kicker(text="control") }}

## The enforcement stays in your application.

The complete enforcement plane composes around your application: challenge issuance, risk, additional factors, quarantine and denial. The Symfony bundle ships it as a host integration, and every server SDK carries the same decisions on machine-checked parity with the Rust core.

Other language SDKs support local verification and risk clients with explicit capabilities. Browser and native wrappers manage the client lifecycle; they do not become an authorization service.

{{ linkrow(href="/integration/", label="Compare integration roles", arrow="↗") }}

{{ notes(paths=["README.md", "packages/kiwicaptcha-client-core/README.md", "packages/kiwicaptcha-verifier/README.md"]) }}

</div>

<div class="section">

{{ kicker(text="widget") }}

## Quiet status. Useful recovery.

The baseline widget shows a static Spiral Lock, readable status and a single decorative work track. It exposes native recovery rather than a checkbox or puzzle.

Current adaptive flows can request address ownership or route a principal to the application's factor flow. Those are typed policy demands, with their own lifecycle and scope.

{{ linkrow(href="/playground/", label="Inspect the widget states", arrow="↗") }}

<div class="spec-stage">
{{ widget(state="solving") }}
</div>

{{ notes(paths=["packages/kiwicaptcha-wasm/assets/widget-driver.js", "packages/kiwicaptcha/design/README.md"]) }}

</div>

<div class="section">

{{ kicker(text="privacy") }}

## First-party defaults you can inspect.

The default runtime path stays on your application's origin. Behavioral telemetry is off by default, and strict privacy mode forces its documented restrictions.

Adaptive continuity and optional factors have a specific data contract. Read the configuration and retention scope instead of relying on an absolute no-data slogan.

{{ linkrow(href="/privacy/", label="Read the privacy model", arrow="↗") }}

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/docs/privacy.md", "packages/kiwicaptcha/integrations/symfony/docs/claims-registry.md", "packages/kiwicaptcha/integrations/symfony/src/Security/StepUp/EmailOwnershipStepUp.php"]) }}

</div>

<div class="section">

{{ kicker(text="economics") }}

## Friction is useful. It is not the whole policy.

The dedicated cost analysis finds that browser-feasible default work does not price out valuable abuse by itself. Your scope's value and complete enforcement path matter.

Current source provides completable carriers and a doctor that checks their prerequisites. A strong-looking configuration that leaves visitors unable to finish a demanded factor is not a finished deployment.

{{ linkrow(href="/security/", label="Understand policy and limits", arrow="↗") }}

{{ notes(paths=["docs/cost-to-abuse.md", "packages/kiwicaptcha/integrations/symfony/src/DependencyInjection/ProtectionProfileDefaults.php", "packages/kiwicaptcha/integrations/symfony/src/Command/KiwiCaptchaDoctorCommand.php"]) }}

</div>

<div class="section">

{{ kicker(text="start") }}

## A source-grounded path to integration.

Begin with the repository's minimal balanced flow. Configure the secret, canonical origin and Redis-backed services, render the widget, and keep verification server-side.

When you adopt an abuse posture, wire its factors, delivery, routes, operation identity and protocol prerequisites before accepting its doctor result as your deployment gate.

{% example(title="Minimal Symfony configuration", caption="Server configuration after manual repository installation; environment values must be supplied by the application.", rows=6) %}
kiwi_captcha:
    protection_profile: balanced
    secret_key: '%env(KIWI_SECRET_KEY)%'
    public_base_url: '%env(KIWI_PUBLIC_URL)%'
    redis_dsn: '%env(KIWI_REDIS_DSN)%'
{% end %}

The repository's verified-flow example. This is the balanced baseline, not a complete abuse_first enforcement deployment.

{{ linkrow(href="/docs/", label="Open the operator guide", arrow="↗") }}

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/docs/getting-started.md", "packages/kiwicaptcha/integrations/symfony/docs/configuration.md", "packages/kiwicaptcha/integrations/symfony/src/Command/KiwiCaptchaDoctorCommand.php"]) }}

</div>

<div class="section">

{{ kicker(text="faq") }}

## The questions that change a deployment.

Computation, factor completion and authorization are distinct. The current source snapshot and its exact limits are available throughout this site.

<div class="qa">
<h3>Does KiwiCaptcha prove that a visitor is human?</h3>
<p>No. Computational work proves a selected computation under its challenge rules. Automated clients can pay that work too. Email ownership establishes control of an address; a principal factor supports the application's configured assurance. None is a universal proof of humanness.</p>
</div>

<div class="qa">
<h3>Which integrations are first-class?</h3>
<p>All of them. The complete enforcement plane — issuance, risk decisions, step-up, quarantine and denial — ships as the Symfony bundle host integration, and the seven server SDKs, the PHP core, the browser and native clients and the verifier sidecar are first-class against the same Rust-defined contracts: decision, authority and rejection parity with the Rust engine is machine-checked across all of them.</p>
</div>

<div class="qa">
<h3>Does a completed widget authorize the request?</h3>
<p>No. The browser has a response token or, in the ownership path, a grant. The application must verify the response and its lifecycle. A factor must also pass the demand finalizer before an operation or pending login is authorized.</p>
</div>

<div class="qa">
<h3>Can raw work price out valuable abuse?</h3>
<p>The published default-rung analysis says it cannot at the browser-feasible costs measured. Use a scope-appropriate, completable step-up or denial policy, and bound issuance and verification resources.</p>
</div>

<div class="qa">
<h3>Can I install a current release from a registry?</h3>
<p>The reviewed README and Symfony guide still state that Rust/Symfony registry publication and the Flex recipe are pending. GitHub's latest listed snapshot is v1.6.31 from August 2026; it is not the current source tree. Use the source integration guides and check current release status before rollout.</p>
</div>

{{ linkrow(href="/faq/", label="Read every answer", arrow="↗") }}

{{ notes(paths=["README.md", "packages/kiwicaptcha/integrations/symfony/src/Security/StepUp/StepUpDemandFinalizer.php"]) }}

</div>

<div class="section">

{{ kicker(text="identity") }}

## A product with its own identity.

The Spiral Lock remains the canonical symbol. Fixed humanist lettering, teal and a clear reading rhythm give KiwiCaptcha a complete visual language within the Bel Consulting product family.

Download native artwork and use the independent guide. Historical source analysis remains available with its original date and commit.

{{ linkrow(href="/brand/", label="Open the brand system", arrow="↗") }}

{{ notes(paths=["packages/kiwicaptcha/resources/kiwi-mark.svg", "packages/kiwicaptcha/design/README.md"]) }}

</div>
