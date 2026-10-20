+++
title = "Integration"
template = "page.html"
description = "Use the right layer: Symfony enforcement, Rust/PHP cores, server SDKs, browser wrappers, native clients and the verifier sidecar, with truthful setup routes."
[extra]
kicker = "INTEGRATIONS / START WITH YOUR STACK"
headline = "Use the right layer."
lede = "The complete enforcement plane, a verification client and a browser wrapper solve different jobs. Choose the contract your application actually needs."
+++

<div class="section">

{{ kicker(text="roles") }}

## One product. Distinct integration roles.

Every integration is first-class. The language-neutral cores define the contracts, and each host — the Symfony bundle, the PHP core, every server SDK — carries them with machine-checked parity against the Rust core, with explicit verification and client capabilities.

<div class="table-wrap">

| Layer | Role | Boundary |
| --- | --- | --- |
| Symfony | Issuance, risk, factors, quarantine and denial | The complete enforcement plane as a host integration. |
| Rust/PHP cores | Embedding issuance, verification and risk contracts | Host supplies its application integration and operating obligations. |
| Server SDKs | Local verification, stores, middleware and outcome clients | The same decision contracts at full parity; the host application composes enforcement. |
| Browser wrappers | Shared script/render/event lifecycle | Tokens still require authoritative server verification. |
| Native clients | Off-UI-thread work and client status/token assembly | Backend verifies; execution-armed/capability limits differ. |
| Verifier sidecar | Local HTTP/Unix-socket verification for other hosts or delegated dimensions | Co-located service contract; not a third-party authorization service. |

</div>

{{ notes(paths=["README.md", "packages/kiwicaptcha-client-core/README.md", "packages/kiwicaptcha-verifier/README.md"]) }}

</div>

<div class="section">

{{ kicker(text="symfony") }}

## The complete plane, as a host integration.

Follow the repository's manual installation guide, register the bundle, and provide the signing secret, canonical public origin and Redis DSN through the environment.

The four-key balanced configuration is a real documented baseline with current smoke fixtures. It does not finish the abuse profile's additional factor and deployment requirements.

{% example(title="Minimal Symfony configuration", caption="Server configuration after manual repository installation; environment values must be supplied by the application.", rows=6) %}
kiwi_captcha:
    protection_profile: balanced
    secret_key: '%env(KIWI_SECRET_KEY)%'
    public_base_url: '%env(KIWI_PUBLIC_URL)%'
    redis_dsn: '%env(KIWI_REDIS_DSN)%'
{% end %}

The repository's verified-flow example. This is the balanced baseline, not a complete abuse_first enforcement deployment.

{% example(title="Manual bundle registration", caption="Integrating application's config/bundles.php; require the repository bundle and its dependencies first.", rows=5) %}
return [
    // ...
    BelConsulting\KiwiCaptchaBundle\KiwiCaptchaBundle::class => ['all' => true],
];
{% end %}

From the manual installation guide. This is part of the source-install path while registry publication/Flex recipe remain pending.

{% example(title="Inspect the installed wiring", caption="Inside the integrating Symfony application. No application deployment or doctor result was run by this content task.", rows=2) %}
bin/console kiwicaptcha:doctor
{% end %}

The command inspects the services and configuration actually installed in the application. A FAIL returns a nonzero exit; WARN names something the command could not establish or a deployment decision still open.

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/integrations/symfony/docs/getting-started.md", label="Manual source installation", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/integrations/symfony/docs/operations.md", label="Complete operator steps", external=true) }}

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/docs/getting-started.md", "packages/kiwicaptcha/integrations/symfony/docs/configuration.md", "packages/kiwicaptcha/integrations/symfony/tests/Kernel/NewIntegratorSmokeKernel.php", "packages/kiwicaptcha/integrations/symfony/tests/NewIntegratorSmokeTest.php"]) }}

</div>

<div class="section">

{{ kicker(text="core") }}

## Keep verification server-side.

The PHP core is framework neutral. Rust and PHP share the record and risk-state contracts described by the repository. The host owns scope, storage, the expected transaction context and the outcome of the protected action.

Do not put the signing secret in a browser or native client. A client onVerify callback delivers a response; the server still decides.

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/README.md", label="Rust core", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-php/README.md", label="PHP core", external=true) }}

{{ notes(paths=["README.md", "packages/kiwicaptcha/README.md", "packages/kiwicaptcha-php/README.md", "packages/kiwicaptcha/integrations/symfony/docs/claims-registry.md"]) }}

</div>

<div class="section">

{{ kicker(text="server / sdks") }}

## Portable verification clients.

The SDK READMEs document store adapters, host middleware, outcome clients and doctor entry points. Publication syntax in a README is not a registry availability assertion on this website.

Check the algorithm and execution policy before issuing a record that a particular runtime cannot verify locally.

<div class="table-wrap">

| SDK | Host surfaces in source | Capability note |
| --- | --- | --- |
| Go | Native verifier and middleware | Argon2id through x/crypto; execution-armed records have explicit refusal/delegation policy. |
| Node/TypeScript | Middleware, optional stores and outcome client | README documents SHA-256/RSW native proof verification and unsupported Argon parameters. |
| Python | Host middleware, stores, doctor and outcomes | argon2-cffi is a current core dependency; unusable binding requires the documented refusal/sidecar path. |
| Ruby | Rack, Rails and Sinatra integration surfaces | Source-path installation is documented pending publication; retain the SDK execution/algorithm contract. |
| JVM | Servlet and Spring Boot surfaces; other host extension points | Consult store, algorithm and execution-policy scope before arming requests. |
| .NET | ASP.NET middleware, Razor and Blazor surfaces | Verification client; not a separate complete enforcement plane. |
| Elixir | Plug and Phoenix surfaces | Source-path installation is documented pending publication; backend capability scope remains explicit. |

</div>

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-go/README.md", label="Go source guide", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-node/README.md", label="Node source guide", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-python-sdk/README.md", label="Python source guide", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-ruby/README.md", label="Ruby source guide", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-jvm/README.md", label="Jvm source guide", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-dotnet/README.md", label=".NET source guide", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-elixir/README.md", label="Elixir source guide", external=true) }}

{{ notes(paths=["README.md", "packages/kiwicaptcha-go/README.md", "packages/kiwicaptcha-node/README.md", "packages/kiwicaptcha-python-sdk/README.md", "packages/kiwicaptcha-ruby/README.md", "packages/kiwicaptcha-jvm/README.md", "packages/kiwicaptcha-dotnet/README.md", "packages/kiwicaptcha-elixir/README.md"]) }}

</div>

<div class="section">

{{ kicker(text="browser") }}

## A shared browser lifecycle.

React, Vue, Svelte, Solid and Angular wrap the framework-free client core. Each render creates fresh markup; event-driven callbacks and teardown preserve the host-owned container.

Configure endpoint, sitekey, scope and language. The common callbacks handle the documented lifecycle. New step-up demand is a driver event; do not invent an onStepUp prop that the wrappers do not export.

{% example(title="The shared client shape", caption="Browser integration contract, not a standalone executable or a package-publication assertion.", rows=14) %}
import { loadKiwiCaptcha, renderKiwiCaptcha } from "@kiwicaptcha/client-core";

const api = await loadKiwiCaptcha({ scriptSrc: "/kiwi.js" });
const handle = renderKiwiCaptcha(document.getElementById("mount")!, {
  endpoint: "/api/kcaptcha/challenge",
  sitekey: "pk-live-1",
  scope: "login",
  lang: "en",
  onVerify: (token) => submit(token),
  onError: (message) => show(message),
  onExpire: () => handle.reset(),
});
{% end %}

The current client-core README's four-setting example, with its application callbacks. submit/show and the served script path belong to the host application; a callback token must still be verified by the server.

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-client-core/README.md", label="Shared client core", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-react/README.md", label="React", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-vue/README.md", label="Vue", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-svelte/README.md", label="Svelte", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-solid/README.md", label="Solid", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-angular/README.md", label="Angular", external=true) }}

{{ notes(paths=["packages/kiwicaptcha-client-core/README.md", "packages/kiwicaptcha-client-core/src/widget.ts", "packages/kiwicaptcha-react/README.md", "packages/kiwicaptcha-vue/README.md", "packages/kiwicaptcha-svelte/README.md", "packages/kiwicaptcha-solid/README.md", "packages/kiwicaptcha-angular/README.md", "packages/kiwicaptcha-wasm/assets/widget-driver.js"]) }}

</div>

<div class="section">

{{ kicker(text="native") }}

## Client work outside the browser.

The repository also carries native status/solver integrations. Their backend still runs verification, and their native dispatch and execution limits are part of the contract.

An available source package is not a promise that every native framework, module or distribution channel is ready for an arbitrary deployment.

<div class="table-wrap">

| Client | Source interface | Important scope |
| --- | --- | --- |
| Android | Compose and classic View over background JVM/Kotlin solving | No WebView; backend SiteVerify owns acceptance. |
| iOS | SwiftUI/UIKit and Swift solver package | Native solver and lifecycle; inspect exact challenge capability limits. |
| Flutter | Material widget with Rust FFI plus low-difficulty Dart path | Required native/FFI path applies above the supported low ceiling. |
| React Native | JS orchestration and native module contract | Harder work requires native module; Expo development build differs from Expo Go; execution-armed requests refused. |

</div>

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-android/README.md", label="Android guide", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-ios/README.md", label="iOS guide", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-flutter/README.md", label="Flutter guide", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-react-native/README.md", label="React Native guide", external=true) }}

{{ notes(paths=["packages/kiwicaptcha-android/README.md", "packages/kiwicaptcha-ios/README.md", "packages/kiwicaptcha-flutter/README.md", "packages/kiwicaptcha-react-native/README.md"]) }}

</div>

<div class="section">

{{ kicker(text="sidecar") }}

## A local verifier when you need it.

The verifier binary exposes a provider-shaped local HTTP or Unix-socket surface. Hosts without a native SDK, or a documented delegated dimension, can use that contract.

Pass the independent expected application binding when the operation requires it. Local delegation does not remove scope, lifecycle or storage duties.

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha-verifier/README.md", label="Verifier sidecar guide", external=true) }}

{{ notes(paths=["packages/kiwicaptcha-verifier/README.md", "packages/kiwicaptcha-go/README.md", "packages/kiwicaptcha-python-sdk/README.md"]) }}

</div>

<div class="section">

{{ kicker(text="migration") }}

## Migrate the lifecycle. Review the differences.

The same-origin compatibility loader and SiteVerify surface cover the documented provider API subset. reCAPTCHA v3 scores are intentionally not invented, and provider-specific shapes/edge behavior outside the contract are not emulated.

Keep your backend's expected scope/action and policy authoritative. TTL parity is a deliberate configuration decision, not proof of universal drop-in behavior.

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/integrations/symfony/docs/migration.md", label="Migration guide", external=true) }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/integrations/symfony/docs/siteverify.md", label="SiteVerify contract", external=true) }}

{{ notes(paths=["packages/kiwicaptcha/integrations/symfony/docs/migration.md", "packages/kiwicaptcha/integrations/symfony/docs/siteverify.md"]) }}

</div>

<div class="section">

{{ kicker(text="status") }}

## Read source status before installation.

At this reviewed snapshot the Rust core and Symfony bundle are explicitly pre-publication, and the Flex recipe is pending. Some SDKs document source-path installation; other READMEs show intended registry syntax.

Use the linked source guides and current publication status. This site does not offer a registry-install CTA or call an old GitHub runtime set the current source build.

{{ notes(paths=["README.md", "packages/kiwicaptcha/integrations/symfony/docs/getting-started.md", "packages/kiwicaptcha-ruby/README.md", "packages/kiwicaptcha-elixir/README.md"]) }}

</div>
