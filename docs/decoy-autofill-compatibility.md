# Decoy autofill and password-manager compatibility

## Scope

The widget renders a server-issued decoy (honeypot) form field next to
the token input. Autofill engines are the strongest real-world
challenge to this surface: a filler that populates every field it sees
could fill the decoy, and a filler that recognizes the decoy's name
could trip the evidence. This document records the automated coverage
and the qualification log for the interaction. It is evidence, plus a
tracked list of open manual qualifications, never a plan presented as
results: every row below that has not yet been executed is explicitly
marked pending manual qualification with the precise procedure.

## The decoy name and the collision claim

A decoy name is fresh per issuance: high-entropy randomness that makes
the field look like an ordinary optional form field, never a fixed
application field name.

The collision claim: an accidental collision with an application field
requires an exact match on the full name, which for the 64 random bits
is a 2^-64 event per issuance, cryptographically negligible. A common
form field name such as `email` or `password` can never collide with a
decoy.

The widget never removes same-named application fields. Ownership is
tracked by private node references: the driver keeps the nodes it
created per widget in its private decoy state. It removes exactly
those nodes (the input and any driver-owned auxiliary element it
created), never a field the application rendered under the same name.
The DOM carries no ownership marker: there is no attribute a classifier
or a cleanup path could key on. A same-named application field is left
untouched by every lifecycle path: reissue, reset and teardown.

The name is authenticated: it is signed into the challenge record
(protocol v3, or v4 when the execution dimension rides along), and
verification checks the submitted name against the
record. A name issued for one challenge is never meaningful for
another, and the server only ever treats a non-empty value under the
exact authenticated name of the verified record as a hit.

## Presentation

The decoy presentation is polymorphic: it varies per challenge, so no
single settled look can be learned from one page load. Every
presentation keeps the same invariant surface: exactly one input,
never in the tab order, excluded from assistive technology, empty
until a filler touches it, and autofill-neutral. The offscreen
presentation carries `autocomplete=new-password`, the only
autofill-relevant attribute fact the manual qualification needs; every
other presentation is autofill-neutral. The fixture can pin the
presentation deterministically so every variant is covered by the
automated suite.

## Automated coverage

The automated suite lives in `tests/browser/specs/` and runs against
the fixture router (`tests/browser/router.php`), which issues real
challenges through the PHP core. The fixture knobs: `?decoy=1` emits a
server-issued decoy name, `?decoy=pool` arms the real authenticated
decoy issuance, and `?decoyname=<name>` pins the emitted name so the
presentation can be driven deterministically. Fills are simulated with
the native value setter plus bubbled input and change events, the same
event sequence built-in autofill and password managers produce. The
engine-form-assistance spec adds engine-specific simulations
(heuristic candidate scans, input composition, silent previews) on top
of that shape.

- `adversarial-portable.spec.mjs` runs in Chromium, Firefox and WebKit
  via `playwright.a11y.config.mjs`: decoy creation invariants, form
  serialization, the exact-name additive-evidence contract, wrong-name
  rejection, reset and re-solve, BFCache round-trips, dynamic forms and
  the autofill-compatibility surface.
- `autofill-evidence.spec.mjs` runs in Chromium, Firefox and WebKit via
  `playwright.a11y.config.mjs`: engine-specific form-assistance
  simulations beyond the generic fill path. It models the three engine
  shapes. Firefox-style heuristic autofill scans candidates over
  autocomplete tokens, names and labels, then focuses and blurs each
  field. The WebKit-style form assistant composes input events plus a
  value commit that lands after blur. Chromium-style autofill previews
  write values silently and commit them at submit. Every simulation
  runs against the offscreen presentation (the highest-sensitivity
  surface, the only one a visible-layout heuristic can consider) and
  the deferred presentation. Each pins the same contract: the decoy
  never receives an autofilled value unless a test fills it
  deliberately, real fields never trip the decoy evidence, evidence
  stays additive, and the proof verifies. Accessibility tooling is
  simulated with the browser's own accessibility tree: the locator aria
  snapshot must not expose the decoy under any presentation, and even
  the offscreen auxiliary label must never leak into it.
- `decoy-polymorphism.spec.mjs` (Chromium) covers the presentation
  variants deterministically: each is driven through the fixture,
  asserts the invariant surface (invisible, non-interactive,
  autofill-neutral) and axe-cleanliness, the unarmed renders-nothing
  case and the reset/reissue replacement across presentations.
- `request-budget.spec.mjs` (Chromium) pins the network budget: the
  full armed lifecycle (challenge fetch, solve, verification) issues
  exactly one API-origin request, the decoy adds zero requests even
  when filled, and a decoy-disabled lifecycle costs the same.
- `risk-v2.spec.mjs` (Chromium) covers the evidence semantics: a filled
  exact decoy name rides the next challenge request as honeypot
  markers.

## Why a manual step is required

Browser automation drives the page as a script inside it, so it cannot
faithfully model extension behavior. Real autofill engines run outside
the page: they match field names and autocomplete hints, apply their
own heuristics and local storage, and render native pickers that
automation cannot observe. The automated suite proves the widget
contracts; the manual matrix below proves the real-world interactions
on actual software.

## Pass criteria

A row passes when all three conditions hold:

1. The decoy is never auto-filled: it stays empty after any fill or
   page interaction.
2. Real fields never trip the decoy: filling them produces no honeypot
   evidence on the server side.
3. Evidence stays additive: a genuine decoy fill reports the hit
   alongside a valid proof, and the proof verdict is never replaced by
   a ban.

## Qualification log

### 2026-08-30, initial qualification run

Environment: macOS 26.5.2 (arm64), PHP 8.5.4 (fixture server), Redis
7 on 127.0.0.1:6399, Playwright 1.62.1. Browser engines available
locally: Chromium 151.0.7922.34 (Chrome for Testing), Firefox 153.0
(Nightly), WebKit (Playwright build 2336).

Automation evidence (headless, local run):

| Suite | Chromium | Firefox | WebKit |
|---|---|---|---|
| adversarial-portable (decoy lifecycle + autofill surface) | PASS | PASS | PASS |
| decoy-polymorphism (presentation variants, axe-clean, lifecycle) | PASS | n/a | n/a |
| request-budget (exact request count, zero decoy requests) | PASS | n/a | n/a |

The three-engine lane is the standing evidence: the portable
adversarial suite runs on every engine in CI
(`playwright.a11y.config.mjs`), and the chromium-only suites run in
the native-browser lane.

### 2026-08-30, engine form-assistance evidence run

Same environment: macOS 26.5.2 (arm64), PHP 8.5.4, Playwright 1.62.1,
Chromium 151.0.7922.34 (Chrome for Testing), Firefox 153.0 (Nightly),
WebKit (Playwright build 2336).

Automation evidence (headless, local run). The new
`autofill-evidence.spec.mjs` suite runs all six scenarios on every
engine. Every scenario below is an automated simulation of a native
autofill engine, so the row records the simulation result only:
`AUTOMATED PASS / MANUAL PENDING`. The native-autofill manual
confirmation is still pending and is tracked row by row in the
qualification matrix further down. An automated run cannot make a
native-autofill row `PASS`; only the real-engine qualification can.

| Scenario | Chromium | Firefox | WebKit |
|---|---|---|---|
| Firefox-style heuristic autofill: candidate scan plus focus and blur fills | AUTOMATED PASS / MANUAL PENDING | AUTOMATED PASS / MANUAL PENDING | AUTOMATED PASS / MANUAL PENDING |
| WebKit-style form assistant: composition events plus a delayed post-blur commit | AUTOMATED PASS / MANUAL PENDING | AUTOMATED PASS / MANUAL PENDING | AUTOMATED PASS / MANUAL PENDING |
| Chromium-style autofill preview: silent writes, committed at submit | AUTOMATED PASS / MANUAL PENDING | AUTOMATED PASS / MANUAL PENDING | AUTOMATED PASS / MANUAL PENDING |
| Offscreen decoy (`autocomplete=new-password`) under all three fills: never a candidate, never autofilled | AUTOMATED PASS / MANUAL PENDING | AUTOMATED PASS / MANUAL PENDING | AUTOMATED PASS / MANUAL PENDING |
| Deferred presentation: the post-solve decoy stays off the candidate surface | AUTOMATED PASS / MANUAL PENDING | AUTOMATED PASS / MANUAL PENDING | AUTOMATED PASS / MANUAL PENDING |
| Accessibility tooling: the AT snapshot never exposes the decoy, any presentation | AUTOMATED PASS / MANUAL PENDING | AUTOMATED PASS / MANUAL PENDING | AUTOMATED PASS / MANUAL PENDING |

Each scenario asserts the pass criteria. The decoy stays empty through
every fill unless a test fills it deliberately; real-field fills
produce no honeypot evidence; the exact-name fill reports the hit
additively with the proof verdict intact; and the proof verifies. The
lane totals moved with the suite: the three-engine lane runs 174 tests
(156 + 18) and the chromium lane runs 174.

### 2026-08-30, real-Safari attempt: blocked

Safari 26.5.2 (21624.2.5.11.8) and its bundled `safaridriver` are
present on this machine. The attempt is blocked at the operating
system's remote-automation gate, so no fill or submit result exists
yet. The exact sequence:

1. `safaridriver --version` reports "Included with Safari 26.5.2" —
   the binary is available.
2. `safaridriver --enable` requires an admin password interactively;
   this run has no admin session, so the enable step fails.
3. A direct WebDriver session request returns the exact refusal:
   "Could not create a session: You must enable 'Allow remote
   automation' in the Developer section of Safari Settings to control
   Safari via WebDriver."
4. The AppleScript fallback path: Safari launches and `open location`
   fires, but read and control AppleEvents (window count, document
   URL) hang on the pending automation-approval dialog, which cannot
   be clicked from a headless session. Even with control granted,
   `do JavaScript` needs the separate Develop-menu toggle "Allow
   JavaScript from Apple Events", whose preference key
   (`AllowJavaScriptFromAppleEvents`) is not set.

Human steps to complete the qualification (offscreen presentation
first, as the highest-sensitivity case): start the fixture server
(`php -d opcache.jit=off -S 127.0.0.1:8088 router.php` in
`tests/browser`) and open Safari. Enable the Develop menu (Settings,
Advanced, Show features for web developers) and tick "Allow Remote
Automation" (or run `safaridriver --enable` with admin rights). Then
drive the armed decoy fixture page (`http://127.0.0.1:8088/?decoy=pool`)
with the offscreen presentation pinned through the fixture's strategy
knob, the same pin the automated suites use. Register a contact card
in Safari's autofill preferences, trigger Safari's contact autofill on
the real form fields, fill the decoy and a real field by hand, submit,
and check the server response for `honeypot_hit`. The AppleScript
alternative needs the automation permission for the controlling app
granted in System Settings (Privacy and Security, Automation) plus the
"Allow JavaScript from Apple Events" toggle.

### 2026-08-30, real Google Chrome qualification run

Same environment: macOS 26.5.2 (arm64), PHP 8.5.4, Redis 7 on
127.0.0.1:6399, Playwright 1.62.1. Browser under test: the installed
Google Chrome binary at /Applications/Google Chrome.app, driven through
the Playwright `chrome` channel by the config override
`tests/browser/playwright.real-chrome.config.mjs`. This row used a
real browser: the binary is the machine's installed browser, not the
Playwright-bundled engine (the bundled engine is Chromium
151.0.7922.34). The installed binary identifies itself as Chrome for
Testing 147.0.7727.15 (the only Chrome build on this machine), and
`channel: 'chrome'` resolved to it directly, so no `connectOverCDP`
fallback was needed.

The recorded identity, read from a page launched through the channel:

- `browser.version()`: 147.0.7727.15
- `navigator.userAgent`: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/147.0.0.0 Safari/537.36`
- Date: 2026-08-30.

Real-browser automation evidence (headless, local run through the
channel; the decoy suites of the a11y spec set):

| Suite | Real Google Chrome 147 |
|---|---|
| autofill-evidence (engine form-assistance simulations) | AUTOMATED PASS / MANUAL PENDING |
| decoy-polymorphism (presentation variants, axe-clean, lifecycle) | PASS |
| targeted-bot (learned-name adaptation, additive evidence) | PASS |

The three suites ran 21 tests against the installed binary with
retries disabled and every test passed. The invariant surface (the
decoy stays empty, real-field fills never trip the evidence, evidence
stays additive) therefore holds on the installed Chrome build under
the automated simulations. The native-autofill row above stays
`AUTOMATED PASS / MANUAL PENDING`: the real Chrome address/password
autofill interaction on the fixture form is a separate manual
qualification, tracked in the matrix below. Real Safari
remains blocked by the documented safaridriver gate (see the blocked
attempt above).

### 2026-08-30, real Firefox qualification run

Same environment: macOS 26.5.2 (arm64), PHP 8.5.4, Redis 7 on
127.0.0.1:6399, Playwright 1.62.1. Browser under test: the installed
Firefox binary at /Applications/Firefox.app (release channel), a
Homebrew cask install (`brew install --cask firefox`) completed for
this run, driven through the Playwright `firefox` channel by the
config override `tests/browser/playwright.firefox.config.mjs`, a new
file mirroring the real-chrome lane. The recorded identity, read from
a page launched through the channel:

- `browser.version()`: 154.0.1

Real-browser automation evidence (headless, local run through the
channel; the decoy suites of the a11y spec set):

| Suite | Real Firefox 154.0.1 |
|---|---|
| autofill-evidence (engine form-assistance simulations) | AUTOMATED PASS / MANUAL PENDING |
| decoy-polymorphism (presentation variants, axe-clean, lifecycle) | PASS |
| targeted-bot (learned-name adaptation, additive evidence) | PASS |

The three suites ran 21 tests against the installed binary with
retries disabled and every test passed. The invariant surface (the
decoy stays empty, real-field fills never trip the evidence, evidence
stays additive) therefore holds on the installed Firefox build under
the automated simulations. The native Firefox autofill interaction
remains MANUAL PENDING: the real Firefox address/password autofill
prompt on the fixture form is a separate manual qualification,
tracked in the matrix below and logged with its procedure in
autofill-qualification-protocol.md.

### External password managers: pending manual qualification

The rows below are tracked open qualifications. Each row passes only
when the pass criteria above hold. The offscreen
`autocomplete=new-password` heuristic sensitivity is the first
priority: a password manager that fills password candidates by hint
alone may treat the offscreen decoy as a password field, which is
exactly the interaction the presentation must be qualified against.

| Tool | Qualification procedure | Expected behavior | Result |
|---|---|---|---|
| Chrome built-in autofill | Register an address profile, trigger autofill on the fixture form (real profile fields), submit and check the server response | Address autofill fills only named, visible fields; the decoy stays empty | PENDING MANUAL QUALIFICATION |
| Edge built-in autofill | Same procedure as Chrome (same engine family) | Decoy stays empty | PENDING MANUAL QUALIFICATION |
| Firefox built-in autofill | Register a profile, autofill the real form, submit and check the server response | Form-fill heuristics skip the hidden and non-interactive decoy | PENDING MANUAL QUALIFICATION |
| Safari built-in autofill | Enable contact autofill, autofill the real form, submit and check the server response | Contact autofill targets recognized fields only | PENDING MANUAL QUALIFICATION |
| iCloud Keychain | Save a login for the fixture page, then use the Keychain fill on the real form and submit | Password fill targets the recognized password and username fields; the decoy stays empty | PENDING MANUAL QUALIFICATION |
| 1Password | Use the 1Password fill action on the real form, then submit | Field-matching heuristics run on candidate fields; the offscreen presentation is the sensitivity case | PENDING MANUAL QUALIFICATION |
| Bitwarden | Use the Bitwarden fill action on the real form, then submit | Autofill matches by name and autocomplete hints; the decoy carries none that point at it | PENDING MANUAL QUALIFICATION |
| LastPass | Use the LastPass fill action on the real form, then submit | Fill heuristics skip the decoy | PENDING MANUAL QUALIFICATION |
| Dashlane | Use the Dashlane fill action on the real form, then submit | Form fill targets visible labelled fields; the decoy stays empty | PENDING MANUAL QUALIFICATION |
| Mobile-browser form helper | Use the on-screen form assistant on a mobile browser for the real form, then submit | The assistant offers fills for the visible fields only; the decoy is never a candidate | PENDING MANUAL QUALIFICATION |
| Accessibility tooling | Navigate the form fields with a screen reader and confirm the decoy is absent from the list | The decoy is excluded from assistive technology and carries no label, so it is never presented | PENDING MANUAL QUALIFICATION |

## Recording

Each qualification run appends a dated row to the log above with the
tool and version, the browser and operating system, and the result. A
row that fails is a release blocker until the behavior is understood
and fixed. New decoy rendering variants must be added to the
deterministic presentation coverage before the manual matrix is
re-run.
