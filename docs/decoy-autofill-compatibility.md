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
marked PENDING MANUAL QUALIFICATION with the precise procedure.

## The decoy name and the collision claim

A decoy name is composed of a plausible grammar prefix followed by an
underscore and 16 lowercase hex characters drawn from 64 bits of
CSPRNG randomness. The plausible prefix makes the field look like an
ordinary optional form field, and the random suffix is unique per
issuance.

The corrected collision claim: an accidental collision with an
application field requires an exact match on the full name, which for
the 64 random bits is a 2^-64 event per issuance, cryptographically
negligible. The prefix alone is never the name, so a common form field
name such as `email` or `password` cannot collide with a decoy.

The widget never removes same-named application fields. Cleanup is
ownership-marked: the driver tracks the input it created per widget and
removes exactly that input (and, for the wrapped variants, the
driver-owned auxiliary element it created), never a field the
application rendered under the same name. A same-named application
field is left untouched by every lifecycle path: reissue, reset and
teardown.

The name is authenticated: it is signed into the challenge record
(protocol v3), and verification checks the submitted name against the
record. A name issued for one challenge is never meaningful for
another, and the server only ever treats a non-empty value under the
exact authenticated name of the verified record as a hit.

## Rendering strategies

The decoy presentation is polymorphic: one of six bounded rendering
variants is chosen per challenge as a pure function of the name. The
variants compose presentation (bare input vs wrapped in a driver-owned
auxiliary element), visibility (hidden vs offscreen) and placement or
timing (before the token input, after it, or deferred until the first
solve completes):

1. Hidden, bare, after the token input: the input carries
   `autocomplete=off`, `tabindex=-1`, `aria-hidden=true` and
   `display:none`.
2. Hidden, wrapped, after the token input: the same input, wrapped in
   the driver-owned auxiliary element.
3. Offscreen, bare: the input is positioned absolutely offscreen
   (`left: -9999px`) and carries `autocomplete=new-password`; it is
   NOT hidden with `display:none`.
4. Hidden attribute, bare, before the token input: the HTML `hidden`
   attribute (not `display:none`), `autocomplete=off`.
5. Hidden attribute, wrapped, before the token input: the `hidden`
   attribute, wrapped in the driver-owned auxiliary element.
6. Deferred: the name is recorded at issuance and the input is created
   only after the first solve completes, with the hidden bare
   presentation of variant 1 (`display:none`, `autocomplete=off`), not
   the offscreen look.

Every variant keeps the same invariant surface: exactly one input,
never in the tab order, excluded from assistive tech, empty until a
filler touches it, and autofill-neutral (`autocomplete=off` or
`new-password`, never a visible labelled control). There is no blanket
`display:none` claim: variants 3-5 are hidden by other means, and
variant 3 in particular relies on the `autocomplete=new-password`
heuristic hint rather than absence from layout.

## Automated coverage

The automated suite lives in `tests/browser/specs/` and runs against
the fixture router (`tests/browser/router.php`), which issues real
challenges through the PHP core. The fixture knobs: `?decoy=1` emits a
server-issued decoy name, `?decoy=pool` arms the real authenticated
decoy issuance, and `?decoyname=<name>` pins the emitted name so every
rendering variant can be driven deterministically. Fills are simulated
with the native value setter plus bubbled input and change events, the
same event sequence built-in autofill and password managers produce,
and the engine-form-assistance spec adds the engine-specific
simulations (heuristic candidate scans, input composition, silent
previews) on top of that shape.

- `adversarial-portable.spec.mjs` runs in Chromium, Firefox and WebKit
  via `playwright.a11y.config.mjs`: decoy creation invariants, form
  serialization, the exact-name additive-evidence contract, wrong-name
  rejection, reset and re-solve, BFCache round-trips, dynamic forms and
  the autofill-compatibility surface.
- `autofill-evidence.spec.mjs` runs in Chromium, Firefox and WebKit via
  `playwright.a11y.config.mjs`: engine-specific form-assistance
  simulations beyond the generic fill path. It models Firefox-style
  heuristic autofill (a candidate scan over autocomplete tokens, names
  and labels, then per-field focus and blur sequences), the WebKit-style
  form assistant (input composition events plus a value commit that
  lands after blur) and Chromium-style autofill previews (values written
  with no events, committed at submit). Every simulation runs against
  the offscreen variant (the highest-sensitivity surface, the only one a
  visible-layout heuristic can consider) and pins the same contract:
  the decoy never receives an autofilled value unless a test fills it
  deliberately, real fields never trip the decoy evidence, evidence
  stays additive and the proof verifies. The deferred variant is
  exercised the same way. Accessibility tooling is simulated with the
  browser's own accessibility tree: the locator aria snapshot must not
  expose the decoy under any of the six strategies, and even the
  offscreen auxiliary label must never leak into it.
- `decoy-polymorphism.spec.mjs` (Chromium) covers the six strategies
  deterministically: each strategy is driven by a pinned name, asserts
  the strategy-specific shape (visibility mechanism, autocomplete
  value, placement, wrapping), axe-cleanliness per strategy, the
  deferred appearance, the unarmed renders-nothing case and the
  reset/reissue replacement across strategies.
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
| decoy-polymorphism (six strategies, axe-clean, lifecycle) | PASS | n/a | n/a |
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
engine:

| Scenario | Chromium | Firefox | WebKit |
|---|---|---|---|
| Firefox-style heuristic autofill: candidate scan plus focus and blur fills | PASS | PASS | PASS |
| WebKit-style form assistant: composition events plus a delayed post-blur commit | PASS | PASS | PASS |
| Chromium-style autofill preview: silent writes, committed at submit | PASS | PASS | PASS |
| Offscreen decoy (`autocomplete=new-password`) under all three fills: never a candidate, never autofilled | PASS | PASS | PASS |
| Deferred strategy: the post-solve decoy stays off the candidate surface | PASS | PASS | PASS |
| Accessibility tooling: the AT snapshot never exposes the decoy, any strategy | PASS | PASS | PASS |

Each scenario asserts the pass criteria: the decoy stays empty through
every fill unless a test fills it deliberately, real-field fills
produce no honeypot evidence, the exact-name fill reports the hit
additively with the proof verdict intact, and the proof verifies. The
lane totals moved with the suite: the three-engine lane runs 174 tests
(156 + 18) and the chromium lane runs 174.

### 2026-08-30, real-Safari attempt: BLOCKED

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

Human steps to complete the qualification (offscreen strategy first,
as the highest-sensitivity case): start the fixture server
(`php -d opcache.jit=off -S 127.0.0.1:8088 router.php` in
`tests/browser`), open Safari, enable the Develop menu (Settings,
Advanced, Show features for web developers), tick "Allow Remote
Automation" (or run `safaridriver --enable` with admin rights), then
drive `http://127.0.0.1:8088/?decoy=pool&strategy=3` through
`safaridriver`: register a contact card in Safari's autofill
preferences, trigger Safari's contact autofill on the real form
fields, fill the decoy and a real field by hand, submit, and check the
server response for `honeypot_hit`. The AppleScript alternative needs
the automation permission for the controlling app granted in System
Settings (Privacy and Security, Automation) plus the "Allow JavaScript
from Apple Events" toggle.

### External password managers: PENDING MANUAL QUALIFICATION

The rows below are tracked open qualifications. Each row passes only
when the pass criteria above hold. The offscreen
`autocomplete=new-password` heuristic sensitivity is the first
priority: a password manager that fills password candidates by hint
alone may treat the offscreen decoy as a password field, which is
exactly the interaction the strategy must be qualified against.

| Tool | Qualification procedure | Expected behavior | Result |
|---|---|---|---|
| Chrome built-in autofill | Register an address profile, trigger autofill on the fixture form (real profile fields), submit and check the server response | Address autofill fills only named, visible fields; the decoy stays empty | PENDING MANUAL QUALIFICATION |
| Edge built-in autofill | Same procedure as Chrome (same engine family) | Decoy stays empty | PENDING MANUAL QUALIFICATION |
| Firefox built-in autofill | Register a profile, autofill the real form, submit and check the server response | Form-fill heuristics skip the hidden and non-interactive decoy | PENDING MANUAL QUALIFICATION |
| Safari built-in autofill | Enable contact autofill, autofill the real form, submit and check the server response | Contact autofill targets recognized fields only | PENDING MANUAL QUALIFICATION |
| iCloud Keychain | Save a login for the fixture page, then use the Keychain fill on the real form and submit | Password fill targets the recognized password and username fields; the decoy stays empty | PENDING MANUAL QUALIFICATION |
| 1Password | Use the 1Password fill action on the real form, then submit | Field-matching heuristics run on candidate fields; the offscreen variant is the sensitivity case | PENDING MANUAL QUALIFICATION |
| Bitwarden | Use the Bitwarden fill action on the real form, then submit | Autofill matches by name and autocomplete hints; the decoy carries none that point at it | PENDING MANUAL QUALIFICATION |
| LastPass | Use the LastPass fill action on the real form, then submit | Fill heuristics skip the decoy | PENDING MANUAL QUALIFICATION |
| Dashlane | Use the Dashlane fill action on the real form, then submit | Form fill targets visible labelled fields; the decoy stays empty | PENDING MANUAL QUALIFICATION |
| Mobile-browser form helper | Use the on-screen form assistant on a mobile browser for the real form, then submit | The assistant offers fills for the visible fields only; the decoy is never a candidate | PENDING MANUAL QUALIFICATION |
| Accessibility tooling | Navigate the form fields with a screen reader and confirm the decoy is absent from the list | The decoy carries `aria-hidden` and no label, so it is skipped | PENDING MANUAL QUALIFICATION |

## Recording

Each qualification run appends a dated row to the log above with the
tool and version, the browser and operating system, and the result. A
row that fails is a release blocker until the behavior is understood
and fixed. New decoy rendering variants must be added to the
strategy table and to the deterministic six-strategy coverage before
the manual matrix is re-run.
