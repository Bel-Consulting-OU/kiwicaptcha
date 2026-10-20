+++
title = "Docs"
template = "page.html"
description = "KiwiCaptcha operator documentation: installation, configuration, profiles, operations, verification, migration, deployment capacity, economics, claims and accessibility."
[extra]
kicker = "DOCUMENTATION / OPERATOR GUIDE"
headline = "Every contract has a page."
lede = "The repository carries the operator documentation next to the source that implements it. Start with installation, configure through the profiles, operate against the documented limits, and verify through the exact contracts."
+++

<div class="section">

{{ kicker(text="start") }}

## Install from source, then inspect what is installed.

The Symfony guide walks the manual installation: bundle registration, environment values, routes and the first verified flow. The doctor command inspects the services and configuration actually installed and returns FAIL on a broken deployment.

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/integrations/symfony/docs/getting-started.md", label="Getting started", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/integrations/symfony/docs/operations.md", label="Doctor and operations", external=true) }}

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/docs/getting-started.md", "packages/kiwicaptcha/integrations/symfony/docs/operations.md"]) }}

</div>

<div class="section">

{{ kicker(text="configure") }}

## Configure through the profiles and their defaults.

The configuration reference documents every key with its effective layering. Protection profiles fill derived settings as the lowest-precedence layer; explicit values win within the forced privacy and validation rules.

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/integrations/symfony/docs/configuration.md", label="Configuration reference", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/integrations/symfony/src/DependencyInjection/ProtectionProfileDefaults.php", label="Profile defaults", external=true) }}

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/docs/configuration.md", "packages/kiwicaptcha/integrations/symfony/src/DependencyInjection/ProtectionProfileDefaults.php", "packages/kiwicaptcha/integrations/symfony/tests/ProtectionProfileLayeringTest.php"]) }}

</div>

<div class="section">

{{ kicker(text="operate") }}

## Operate against the documented resource and storage contract.

The deployment guide covers Redis posture, capacity framing and the replication/promotion contract. The cost-to-abuse analysis reports what default browser-feasible work does and does not price out, so a scope policy can be chosen honestly.

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/deploy/README.md", label="Deployment and capacity", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/docs/cost-to-abuse.md", label="Cost-to-abuse analysis", external=true) }}

{{ notes(paths=["deploy/README.md", "docs/cost-to-abuse.md", "SECURITY.md"]) }}

</div>

<div class="section">

{{ kicker(text="verify") }}

## Verify through the exact contracts.

SiteVerify compatibility, migration shims, deterministic recovery and security hardening each have a dedicated page next to the code that implements them.

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/integrations/symfony/docs/siteverify.md", label="SiteVerify contract", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/integrations/symfony/docs/migration.md", label="Migration guide", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/integrations/symfony/docs/security-hardening.md", label="Security hardening", external=true) }}

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/docs/siteverify.md", "packages/kiwicaptcha/integrations/symfony/docs/migration.md", "packages/kiwicaptcha/integrations/symfony/docs/security-hardening.md"]) }}

</div>

<div class="section">

{{ kicker(text="reference") }}

## Reference pages that keep the boundaries visible.

The claims registry binds product claims to evidence; the risk engine page explains decisions without identity material; the privacy page is the mode-specific data contract; accessibility records the widget's qualification scope.

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/integrations/symfony/docs/claims-registry.md", label="Claims registry", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/integrations/symfony/docs/risk-engine.md", label="Risk engine", external=true) }}

{{ linkrow(href="/privacy/", label="Privacy model", arrow="↗") }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/integrations/symfony/Resources/ACCESSIBILITY.md", label="Accessibility", external=true) }}

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/docs/claims-registry.md", "packages/kiwicaptcha/integrations/symfony/docs/risk-engine.md", "packages/kiwicaptcha/integrations/symfony/docs/privacy.md", "packages/kiwicaptcha/integrations/symfony/Resources/ACCESSIBILITY.md"]) }}

</div>
