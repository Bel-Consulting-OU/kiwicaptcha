+++
title = "FAQ"
template = "page.html"
description = "Useful details in one place: computation, factor completion, authorization, releases, expiry, languages, accessibility, storage, step-up demands and the threat model."
[extra]
kicker = "FAQ / USEFUL DETAILS IN ONE PLACE"
headline = "The questions that change a deployment."
lede = "Computation, factor completion and authorization are distinct. Every answer below is grounded in the current source snapshot, and the exact limits are available through the linked pages."
+++

<div class="section">

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

<div class="qa">
<h3>What happens when a check expires?</h3>
<p>The widget moves to its expired state, clears the token, bindings and aliases, and preserves the host's form data. The native Retry control reacquires without a page reload. The voice contract says it plainly: the check expired, retry to reacquire — never a lost host form draft.</p>
</div>

<div class="qa">
<h3>What are the widget's states and how does recovery work?</h3>
<p>Ten states: pending, idle, connecting, solving, done, failed, expired, worker-unavailable, execution-unavailable and solver-mismatch. Recovery is native and bounded: two automatic retries precede a terminal failure, Retry reacquires after expiry, and a solver mismatch requires reloading a coherent asset set rather than retrying. The <a href="/playground/">widget page</a> renders all ten statically.</p>
</div>

<div class="qa">
<h3>Which languages does the widget ship?</h3>
<p>Ten packs: English eagerly in the driver, then German, French, Spanish, Italian, Dutch, Polish, Portuguese, Brazilian Portuguese and Arabic — the Arabic pack carries right-to-left direction. Untranslated surfaces degrade to English with a console warning; the widget still solves and renders.</p>
</div>

<div class="qa">
<h3>Is the widget accessible?</h3>
<p>The widget keeps a readable status, visible labels, wrapped text, state meaning beyond color, reduced-motion behavior and a live component text scale. The accessibility contract is recorded in the repository; manual screen-reader qualification with the specific browser and assistive-technology pairing is still an open deployment qualification, not a completed claim.</p>
</div>

<div class="qa">
<h3>Which protection profile should I choose?</h3>
<p>Choose the posture your deployment can complete. balanced is the neutral documented baseline; privacy_strict forces its documented restrictions; high_abuse/abuse_first needs its datasets, factors, delivery, routes and operation identity wired before it is a finished deployment; compatibility is the migration posture; ha_safe pins primary authority. The <a href="/security/">security page</a> describes each purpose.</p>
</div>

<div class="qa">
<h3>What does KiwiCaptcha store, and where?</h3>
<p>Authoritative state lives in your Redis: challenges, grants, factor demands and risk marks, each with its own scope and expiry. Network-identity material is stored as a keyed HMAC rather than a reversible address, and the privacy page documents the mode-specific evidence contract.</p>
</div>

<div class="qa">
<h3>How does a step-up demand differ from the widget check?</h3>
<p>The widget produces a response to verify. A step-up demand is a typed policy request — address ownership or a named principal factor — with its own lifecycle, scope and delivery. A passing factor still passes the shared demand finalizer before anything is authorized.</p>
</div>

<div class="qa">
<h3>Can the verifier become a bottleneck or an abuse target?</h3>
<p>Rate-limit issuance, bound outstanding challenges and cap verification concurrency. Memory-hard verification needs a fixed resource envelope and admission control, and the security Redis is authoritative state — preserve noeviction, TTL margin and the replication contract.</p>
</div>

<div class="qa">
<h3>Does it migrate from an existing provider?</h3>
<p>The same-origin compatibility loader and SiteVerify surface cover the documented provider API subset. Provider scores are intentionally not invented, and behavior outside the contract is not emulated. Keep the backend's expected scope, action and policy authoritative.</p>
</div>

<div class="qa">
<h3>Is there a verifier sidecar?</h3>
<p>Yes. The verifier binary exposes a provider-shaped local HTTP or Unix-socket surface for hosts without a native SDK or with a documented delegated dimension. It is a co-located service contract, not a third-party authorization service.</p>
</div>

<div class="qa">
<h3>Can I use the brand assets?</h3>
<p>Use the native masters as they are: H/4 clear space, one color, no effects. The identity page provides the light and reverse presentations, the measured palette and the downloads; the design contract in the repository is the authority.</p>
</div>

<div class="qa">
<h3>What does the threat model cover?</h3>
<p>The repository carries a recorded red-team campaign table with scale and method caveats, and a security page that states the bounded anti-abuse model and the explicit non-guarantees. Read both before relying on any single mechanism.</p>
</div>

{{ notes(paths=["README.md", "SECURITY.md", "packages/kiwicaptcha/integrations/symfony/docs/privacy.md", "packages/kiwicaptcha-wasm/assets/widget-driver.js", "packages/kiwicaptcha/integrations/symfony/Resources/ACCESSIBILITY.md"]) }}

</div>
