+++
title = "Reference"
template = "page.html"
description = "Current edition and complete prior reference: the implemented page architecture of this edition, the dated prior live-site structure and the two design PDFs."
[extra]
kicker = "REFERENCE / CURRENT EDITION AND PRIOR"
headline = "This edition, and the one before it."
lede = "The current edition is this ten-page site, generated from the repository by Zola and served without JavaScript. The prior edition was the four-page live site; its structure and direction specimen are recorded below with their original date."
+++

<div class="section">

{{ kicker(text="current edition") }}

## Ten pages, source-grounded.

Edition 4, 12 October 2026. Each page explains one job, and every section carries source notes into the repository that generates the site.

<div class="table-wrap">

| Page | Job | Implemented content |
| --- | --- | --- |
| Home | Explain mechanism and ownership | Hero with the decision-in-view component, why, mechanism, control, widget, privacy, economics, start, faq and identity sections. |
| How it works | Give the proof its context | Four-step sequence, algorithms, cheap gates, single use, operation binding, factors, extensions. |
| Integration | Give truthful setup routes | Layer roles, the complete plane, cores, server SDKs, browser wrappers, native clients, sidecar, migration, source status. |
| Security | Keep decisions explicit | Bounded model, profiles, completable factors, operation authorization, outcomes, economics, verifier resources. |
| Privacy | State the data contracts | First-party defaults, purpose-scoped evidence, strict posture, retention, claims registry. |
| Docs | Map the operator documentation | Start, configure, operate, verify and reference routes into the repository guides. |
| Widget | Explore the component | Ten states, static specimen, widths, component text scales, ten language packs, recovery. |
| Identity | Provide the complete brand | Exact board, light/reverse masters, measured palette, typography, native downloads. |
| FAQ | Useful details in one place | Sixteen deployment-changing questions with grounded answers. |
| Reference | Hold the edition record | This page: the current architecture and the dated prior reference. |

</div>

{{ notes(paths=["KiwiCaptcha_Website.pdf", "KiwiCaptcha_Visual_Identity.pdf", "packages/kiwicaptcha/design/IDENTITY.md"]) }}

</div>

<div class="section">

{{ kicker(text="prior edition") }}

## The four-page live site, as it was.

Edition 3, 11 October 2026. The prior live implementation carried four pages with a distinct, warmer personality, native logo artwork, local fonts and accessible local interactions.

<div class="table-wrap">

| Page | Job | Implemented content |
| --- | --- | --- |
| Home | Explain mechanism and ownership | Quiet host-form specimen, Work / Verify / Decide, visitor states, mode-specific privacy, integration routes and FAQ. |
| Integration | Give truthful setup routes | Pinned Rust/Symfony/frontend links, lifecycle/acceptance boundary, resource/economic/privacy limits. |
| Widget | Explore the component | Ten states; nine languages plus pt-BR; Arabic RTL; 240–352 px widths; 100% / 200% component text; simulated recovery. |
| Identity | Provide the complete brand | Native light/reverse masters, exact board, typography, guide/kit/SVG/token downloads. |

</div>

<p class="muted-note">The prior site's controls updated a local specimen by state, language, width and text scale; completion and recovery stayed explicitly simulated, and no security service or token was created. This page recreates its direction statically.</p>

<div class="prior-specimen" role="img" aria-label="Prior edition direction specimen: company strip, logo, navigation, campaign hero and an illustrative host form">
  <div class="prior-strip">
    <span class="strip-mono">BEL CONSULTING</span>
    <span class="strip-mono">SELF-HOSTED COMPUTATIONAL ANTI-ABUSE</span>
  </div>
  <div class="prior-header">
    <svg class="prior-lockup brand-art" role="img" aria-label="KiwiCaptcha lockup" xmlns="http://www.w3.org/2000/svg"><use href="#kiwi-lockup"/></svg>
    <nav class="prior-nav" aria-label="Prior edition specimen">
      <span>Integration</span><span>Widget</span><span>Identity</span>
    </nav>
  </div>
  <div class="prior-hero">
    <div>
      <p class="kicker">COMPUTATIONAL CHECKS / FIRST-PARTY CONTROL</p>
      <h2>Let the browser do the&nbsp;work.</h2>
      <p class="lede">A self-hosted check that fits quietly into your form. Your application owns the acceptance policy.</p>
      <a class="prior-button" href="/integration/">Read the guide</a>
    </div>
    <div class="prior-form">
      <p class="panel-title">A form, with less interruption.</p>
      <p class="field-label" id="prior-email-label">Email address</p>
      <input type="email" aria-labelledby="prior-email-label" placeholder="you@example.com" readonly>
      {{ widget(state="solving") }}
      <p class="mono-caption">Illustrative host form / no solver runs here.</p>
    </div>
  </div>
  <div class="prior-own">
    <h3>Small on the page. Clear behind it.</h3>
    <p>A distinct product. Its own source, identity and website.</p>
  </div>
</div>

{{ notes(paths=["KiwiCaptcha_Visual_Identity.pdf", "packages/kiwicaptcha/design/README.md"]) }}

</div>

<div class="section">

{{ kicker(text="downloads") }}

## Both editions, as documents.

The paginated editions are files in the source repository, next to the code and the identity masters.

{{ linkrow(href="/pdf/KiwiCaptcha_Website.pdf", label="Complete website PDF (edition 4, 12 October 2026)", arrow="↓") }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/KiwiCaptcha_Visual_Identity.pdf", label="Complete visual identity PDF (edition 4)", external=true) }}

{{ notes(paths=["KiwiCaptcha_Website.pdf", "KiwiCaptcha_Visual_Identity.pdf"]) }}

</div>
