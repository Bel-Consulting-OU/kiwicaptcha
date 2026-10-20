+++
title = "Identity"
template = "brand.html"
description = "The KiwiCaptcha visual identity: the exact identity board, the native light and reverse masters, the measured palette, the type system and the native downloads."
+++

<div class="section">

{{ kicker(text="board") }}

## The exact visual system in one view.

The board recreates the identity with the supplied SVG masters, the exact palette and the real widget component. Native masters govern contours, type, color and product copy.

<div class="board" role="img" aria-label="KiwiCaptcha identity board: lockup, campaign chip, palette, typography, widget component and app icon">
  <div class="board-head">
    <span>KIWICAPTCHA / VISUAL IDENTITY</span>
    <span>BEL CONSULTING / INDEPENDENT PRODUCT</span>
  </div>
  <div class="board-lockup-row">
    <img class="board-lockup" src="/brand/kiwi-lockup.svg" alt="KiwiCaptcha lockup">
    <p class="campaign-chip">Let the browser do the work.</p>
  </div>
  <div class="board-row">
    <div>
      <p class="board-label">PALETTE / SHARED FOUNDATIONS, OWN ACCENT</p>
      <div class="palette-chips">
        <div class="chip"><div class="swatch swatch--ink"></div><p class="chip-name">Ink</p><p class="chip-hex">#08110C</p></div>
        <div class="chip"><div class="swatch swatch--forest"></div><p class="chip-name">Forest</p><p class="chip-hex">#143D2B</p></div>
        <div class="chip"><div class="swatch swatch--paper"></div><p class="chip-name">Paper</p><p class="chip-hex">#F3F5EF</p></div>
        <div class="chip"><div class="swatch swatch--sage"></div><p class="chip-name">Sage</p><p class="chip-hex">#92AA99</p></div>
        <div class="chip"><div class="swatch swatch--teal"></div><p class="chip-name">Teal</p><p class="chip-hex">#9EDFD4</p></div>
        <div class="chip"><div class="swatch swatch--teal-deep"></div><p class="chip-name">Teal Deep</p><p class="chip-hex">#145C52</p></div>
      </div>
    </div>
    <div class="type-specimen">
      <p class="board-label">TYPOGRAPHY / OWN VOICE</p>
      <p class="ts-display">Alegreya Sans</p>
      <p class="ts-line">Character in the lettering. Readable product language. Exact labels.</p>
      <p class="ts-mono">IBM PLEX MONO / TECHNICAL METADATA</p>
    </div>
  </div>
  <div class="board-row">
    <div>
      <p class="board-label">PRODUCT WEBSITE / NATIVE DESIGN SPECIMEN</p>
      <div class="master-tile board-site-tile">
        <img class="board-site-lockup" src="/brand/kiwi-lockup.svg" alt="">
        <p class="board-site-headline">Let the browser do&nbsp;the&nbsp;work.</p>
        <a class="board-site-link" href="/integration/">Explore integration</a>
      </div>
    </div>
    <div>
      <p class="board-label">COMPONENT / ILLUSTRATIVE STATE</p>
      <div class="board-widget">
        {{ widget(state="done", width=300) }}
        <p class="board-widget-note">Host verification and policy still decide acceptance.</p>
      </div>
    </div>
  </div>
  <div class="board-foot-row">
    <img class="app-tile" src="/brand/kiwi-app-icon.svg" alt="KiwiCaptcha app tile">
    <div>
      <p class="board-clearspace-note">H/4 clear space. One-color masters. No effects.</p>
      <span class="mono">NATIVE MASTERS / CURRENTCOLOR</span>
    </div>
  </div>
</div>

{{ notes(paths=["packages/kiwicaptcha/design/IDENTITY.md", "packages/kiwicaptcha/design/README.md"]) }}

</div>

<div class="section">

{{ kicker(text="masters") }}

## Light and reverse from one native master.

Every master except the app tile recolors through currentColor, so the Ink, white and accent variants come from the surrounding color. The wordmark is fixed artwork: lowercase "kiwi captcha" outlined from Alegreya Sans Bold, kiwi at 100 units and captcha at 82 on the same baseline, recorded in lettering.json.

<div class="master-pair">
  <div>
    <div class="master-tile"><img src="/brand/kiwi-lockup.svg" alt="KiwiCaptcha horizontal lockup in Ink on Paper"></div>
    <p class="master-caption">PRIMARY LIGHT / INK ON PAPER</p>
  </div>
  <div>
    <div class="master-tile master-tile--reverse"><img src="/brand/kiwi-lockup.svg" alt="KiwiCaptcha horizontal lockup in Teal on Ink"></div>
    <p class="master-caption">REVERSE / TEAL ON INK</p>
  </div>
</div>

<div class="table-wrap">

| Master | File | Use |
| --- | --- | --- |
| Primary horizontal | kiwi-lockup.svg | The default signature wherever the full name reads comfortably; at least 192 px wide. |
| Secondary stacked | kiwi-stacked.svg | Square-ish placements where the horizontal signature cannot be read. |
| Wordmark | kiwi-wordmark.svg | Known-context surfaces; the fixed lettering alone. |
| Bare symbol | kiwi-mark.svg | Favicons, widget icon slots and monochrome toolbar contexts; 24 px preferred, 16 px proofed. |
| App container | kiwi-app-icon.svg | The platform tile with fixed Ink and Teal. A tile is a container, not an extra shape in the bare mark. |
| Shield | kiwi-shield.svg | Secondary security-status emblem; never a replacement for the primary mark. |

</div>

Keep H/4 clear space on all sides of the visible artwork; empty viewBox padding does not count. No stretching, rotation, letter-spacing changes, cropping, outlining, gradients, shadows or added ornament.

{{ notes(paths=["packages/kiwicaptcha/resources/kiwi-mark.svg", "packages/kiwicaptcha/design/lettering.json", "packages/kiwicaptcha/tools/sync-brand.mjs"]) }}

</div>

<div class="section">

{{ kicker(text="palette") }}

## A palette with clear responsibilities.

Family foundations plus an individual accent. Brand colors and outcome semantics remain distinct, and state meaning is carried by more than color alone.

<div class="table-wrap table--band">

| Foreground / background | Contrast | Use |
| --- | --- | --- |
| Ink / Paper | 17.45:1 | Normal text |
| Forest / Paper | 11.04:1 | Normal text |
| Muted / Paper | 5.66:1 | Normal text |
| Sage / Ink | 7.69:1 | Normal text |
| Teal / Ink | 12.74:1 | Normal text |
| Teal Deep / Paper | 7.13:1 | Normal text |
| Teal / Paper | 1.37:1 | Decorative accent only |

</div>

The normal-text target is 4.5:1 and essential non-text graphics need 3:1. Muted text on light surfaces uses the widget's `#5D625F` token.

{{ notes(paths=["packages/kiwicaptcha/design/IDENTITY.md", "packages/kiwicaptcha/resources/widget.css"]) }}

</div>

<div class="section">

{{ kicker(text="typography") }}

## Typography is part of the identity.

The display and reading fonts are specific to this product; technical metadata connects the family. Self-hosted WOFF2 files and OFL notices ship in `design/fonts/`. The production widget inherits the host system stack and takes no marketing-font payload.

<div class="table-wrap">

| Role | Typeface and scale | Behavior |
| --- | --- | --- |
| Display heading | Alegreya Sans 700/800, 56–108 px | Short, concrete heading; controlled line length. |
| Section heading | Alegreya Sans, 38–66 px | One clear proposition; editorial rhythm. |
| Reading / controls | Alegreya Sans, 19–25 px | Open leading; visible labels; natural wrapping. |
| Technical metadata | IBM Plex Mono, 10–14 px | Short IDs, source context, states and code. |
| Product host | inherit widget host; no marketing-font payload | IDE/widget keeps its existing reading environment. |

</div>

{{ notes(paths=["packages/kiwicaptcha/design/fonts/OFL-AlegreyaSans.txt", "packages/kiwicaptcha/design/fonts/OFL-IBMPlexMono.txt", "packages/kiwicaptcha/design/IDENTITY.md"]) }}

</div>

<div class="section">

{{ kicker(text="downloads") }}

## Native files, from the source repository.

The masters, the contract and the tokens are files in the repository this site is built from. Download them as they are.

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/packages/kiwicaptcha/design/IDENTITY.md", label="Design guide (IDENTITY.md)", external=true) }}

{{ linkrow(href="/brand/kiwi-mark.svg", label="Bare symbol SVG", arrow="↓") }}

{{ linkrow(href="/brand/kiwi-lockup.svg", label="Horizontal lockup SVG", arrow="↓") }}

{{ linkrow(href="/brand/kiwi-stacked.svg", label="Stacked lockup SVG", arrow="↓") }}

{{ linkrow(href="/brand/kiwi-wordmark.svg", label="Wordmark SVG", arrow="↓") }}

{{ linkrow(href="/brand/kiwi-app-icon.svg", label="App icon SVG", arrow="↓") }}

{{ linkrow(href="/brand/kiwi-shield.svg", label="Shield SVG", arrow="↓") }}

{{ linkrow(href="/brand/lettering.json", label="Lettering tokens (lettering.json)", arrow="↓") }}

{{ linkrow(href="/css/widget.css", label="Widget skin (widget.css)", arrow="↓") }}

{{ linkrow(href="https://github.com/Bel-Consulting-OU/kiwicaptcha/blob/main/KiwiCaptcha_Visual_Identity.pdf", label="Complete visual identity PDF", external=true) }}

{{ notes(paths=["packages/kiwicaptcha/design/IDENTITY.md", "packages/kiwicaptcha/design/README.md", "packages/kiwicaptcha/tools/sync-brand.mjs"]) }}

</div>
