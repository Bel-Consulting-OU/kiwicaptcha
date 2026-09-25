# Autofill and password-manager qualification protocol

This document is the physical, manual qualification protocol for the
interaction between the widget and real autofill and password-manager
surfaces. The automated cross-browser evidence lives in the browser
suite (the engine form-assistance simulations and the polymorphic
decoy suites run across Chromium, Firefox and WebKit in the CI
three-engine lane, and against the machine's installed Chrome in the
real-chrome lane). This protocol covers the surfaces automation cannot
reach: real autofill engines with real saved profiles, real password
managers, and real assistive technology. The sanitized autofill
compatibility document (docs/decoy-autofill-compatibility.md) records
the automated coverage and the qualified claim; this protocol is the
manual procedure that completes the record.

## The central invariant

> Legitimate autofill must never produce false-positive decoy
> evidence. This matters more than rendering perfection.

The widget renders a server-issued decoy form field next to the token
input. The security purpose of the decoy is to attract automated
filling: a bot that fills every field it can see leaves a value under
the authenticated decoy name, and the server counts that as additive
evidence. The risk this protocol guards is the inverse failure:
a legitimate user's password manager or browser autofill fills the
decoy with a real value, and the evidence pipeline mistakes a genuine
human for a bot. Rendering imperfection (a pixel off, a stray label)
is a cosmetic issue; a false-positive decoy hit on a real user is a
security-correctness issue, because it corrupts the abuse signal with
legitimate traffic. Every manual qualification run in this protocol
is therefore judged against the invariant first and appearance
second.

## The surface registry

The machine-readable registry
`tests/browser/qualification/surfaces.json` (schema
`kiwicaptcha.autofill-surfaces/1`) is the ONE authoritative definition
of the qualification surfaces. It fixes each surface's stable id, its
expected platform class and whether a pass row must record an exact
version. The matrix
(`tests/browser/qualification/autofill-matrix.json`) and this document
refer to those ids; neither keeps a second manual list. The release
validator `tools/ci/validate-autofill-qualification.mjs` reads the
registry, not this document.

| Surface id | Product | Platform class | Exact version | Required |
|------------|---------|----------------|---------------|----------|
| `chrome-builtin-autofill` | Chrome built-in autofill | desktop | yes | yes |
| `edge-native-autofill` | Edge | windows | yes | yes |
| `firefox-native-autofill` | Firefox | desktop | yes | yes |
| `safari-autofill` | Safari | macos | yes | yes |
| `ios-safari` | iOS Safari | ios | yes | yes |
| `android-chrome` | Android Chrome | android | yes | yes |
| `icloud-keychain` | iCloud Keychain | macos | yes | yes |
| `1password` | 1Password | desktop | yes | yes |
| `bitwarden` | Bitwarden | desktop | yes | yes |
| `voiceover-macos` | VoiceOver | macos | yes | yes |
| `nvda-windows` | NVDA | windows | yes | yes |
| `second-major-manager` | LastPass or Dashlane | desktop | yes | no |
| `jaws-windows` | JAWS | windows | yes | no |

A matrix row carries the `surface` id, the exact tested `version`, the
`platform`, the `status` and the `tested_at` date. The `product`
display name is optional and must match the registry when present.
Every row is structurally validated; every surface whose registry
entry is `required: true` is also a gate. Advisory surfaces (registry
`required: false`, or an id the registry does not know) never gate and
are reported as notes.

## Pass criteria

A row passes when all three criteria hold on the tested surface:

1. **The decoy never auto-fills.** No fill sequence, preview or commit
   that the surface performs on the real fields ever writes a value
   into the decoy input. The decoy's value stays empty after the
   autofill action, and stays empty in the serialized form payload.
2. **Real fields never trip the decoy evidence.** Filling the real
   fields (email, username, password and any address fields the test
   page exposes) produces no honeypot hit on the server. The decoy
   evidence endpoint reports no hit for a form whose real fields
   carry autofilled values.
3. **Evidence stays additive.** A deliberate fill of the decoy name
   (the manual equivalent of a bot fill) still reports the hit, and
   the proof verdict stays valid alongside it. The evidence layer
   adds, never replaces: a proof that would verify still verifies,
   and the hit rides alongside it instead of banning the user.

A row that fails any criterion is recorded `FAIL` with the exact
observed behavior, the surface version, and the date. A row whose
setup could not be completed (no device, no manager, no OS) is
recorded `BLOCKED` with the exact blocker and the steps that would
unblock it. A row backed only by automated real-engine simulation
evidence is recorded `AUTOMATED PASS / MANUAL PENDING`: the automated
runs drive the installed engine binary and the page surface, but they
cannot exercise a NATIVE-autofill interaction (a saved profile filling
the form through the browser's own autofill/prompt), so they cannot
make a native-autofill row `PASS`. Only the manual qualification can.

## The qualification matrix

Every row carries the surface id (and its product name), the surface
version, the test date, the result (`PASS`, `FAIL`, `BLOCKED` or
`AUTOMATED PASS / MANUAL PENDING`) and notes. The page to use is the
standard autofill test page from the browser suite: a form with real
autocomplete-semantic fields (email, username, current-password), the
widget container, and the hidden token input, served over the local
fixture router. The exact steps per surface are listed in each row.
The decoy name is read from the challenge response and the server-side
evidence is read from the fixture's honeypot-check endpoint, exactly
as the automated suites do.

| Surface id | Required steps | Version | Date | Result | Notes |
|------------|----------------|---------|------|--------|-------|
| `chrome-builtin-autofill` | Save a profile with email, name and a password for the test page; reload; click the form and accept the native autofill; submit; check the decoy stays empty, real fields carry values, the honeypot-check reports no hit, and the proof verifies | 1xx stable | 2026-08-30 | AUTOMATED PASS / MANUAL PENDING | Automated real-Chrome evidence logged in the real-chrome lane (the machine-installed Chrome binary); the native-autofill manual confirmation is pending |
| `firefox-native-autofill` | Save a login and a form profile in Firefox; reload the page; accept the autofill prompts on the real fields; submit; check the decoy stays empty, the honeypot-check reports no hit, and the proof verifies | 154.0.1 | 2026-08-30 | AUTOMATED PASS / MANUAL PENDING | Real-Firefox automated evidence logged (autofill-evidence, decoy-polymorphism and targeted-bot suites, 21 tests, all green); the native-autofill prompt manual confirmation is pending |
| `safari-autofill` | Save a login in iCloud Keychain; enable Safari autofill; reload the page; accept the Keychain fill on the real fields; submit; check the decoy stays empty and the honeypot-check reports no hit | TBD | | PENDING | Requires a physical macOS host with iCloud Keychain; follow the steps in this row |
| `edge-native-autofill` | Save a login and an address profile in Edge; reload; accept the fills; submit; check the decoy stays empty, no hit, proof verifies | TBD | | PENDING | Requires a Windows host; follow the steps in this row |
| `bitwarden` | Install the Bitwarden browser extension; unlock with a test vault; use the inline autofill menu on the real fields; submit; check the decoy stays empty, no hit, proof verifies | TBD | | PENDING | Follow the steps in this row |
| `1password` | Install the 1Password browser extension; unlock with a test vault; use the inline autofill menu on the real fields; submit; check the decoy stays empty, no hit, proof verifies | TBD | | PENDING | Follow the steps in this row |
| `second-major-manager` (advisory) | Install the manager's extension; unlock with a test vault; use its fill menu on the real fields; submit; check the decoy stays empty, no hit, proof verifies | TBD | | PENDING | Recommended second major manager; advisory, never gates |
| `ios-safari` | On an iPhone or iPad, save a login in iCloud Keychain; open the test page in Safari; accept the AutoFill prompt on the real fields; submit; check the decoy stays empty, no hit, proof verifies | TBD | | PENDING | Requires a physical iOS device; follow the steps in this row |
| `android-chrome` | Save a login and an address in the Google account; open the test page in Chrome; accept the autofill suggestions on the real fields; submit; check the decoy stays empty, no hit, proof verifies | TBD | | PENDING | Requires a physical Android device; follow the steps in this row |
| `icloud-keychain` | With a login saved in iCloud Keychain, use the Keychain fill on the real fields in a browser that offers it; submit; check the decoy stays empty and the honeypot-check reports no hit | TBD | | PENDING | Separate row from Safari: the Keychain fill path is its own surface |
| `voiceover-macos` | Enable VoiceOver; navigate the form with the keyboard; read the fields; confirm the decoy is not announced and the real fields are; submit with a keyboard-only fill; check the decoy stays empty and the proof verifies | TBD | | PENDING | The AT snapshot evidence is automated in the a11y lane; the screen-reader confirmation is pending |
| `nvda-windows` | Start NVDA; navigate the form with the keyboard; read the fields; confirm the decoy is not announced and the real fields are; submit with a keyboard-only fill; check the decoy stays empty and the proof verifies | TBD | | PENDING | Requires a Windows host; follow the steps in this row |
| `jaws-windows` (advisory) | Start JAWS; navigate the form with the keyboard; read the fields; confirm the decoy is not announced and the real fields are; submit; check the decoy stays empty and the proof verifies | TBD | | PENDING | Recommended second screen reader; advisory, never gates |

## Record format

Every completed row appends a record entry in the matrix above and a
free-form note under it. The record is the version, the date, the
result and the notes, nothing more:

```
Surface id: <the stable registry id>
Product: <the registry product name>
Version: <exact surface version, never a placeholder for a pass row>
Date: <ISO date>
Result: <PASS | FAIL | BLOCKED | AUTOMATED PASS / MANUAL PENDING>
Notes: <the exact observed behavior; for FAIL, the criterion that
broke; for BLOCKED, the blocker and the unblocking steps>
```

A pass record must carry the exact surface version and a strict
ISO-8601 date. `CURRENT`, `TBD`, `unknown`, a blank version or a null
date is a placeholder and can only ride a non-pass row. The validator
rejects a pass row without an exact version, a malformed date, a date
more than a day in the future, or a date older than the qualification
window (90 days by default).

The notes field may describe the observed behavior in terms of the
invariant (what filled, what stayed empty, what the evidence endpoint
reported). It must not expose the decoy classifier surface: do not
re-list the rendering-strategy inventory, the decoy-name grammar or
the DOM presentation details in this protocol or in any qualification
note. The qualification facts live in the sanitized autofill
compatibility document: the collision claim, the private-node
ownership statement, the qualification rows and the single
autofill-relevant presentation fact (the offscreen presentation
carries `autocomplete=new-password`). No classifier surface exists in
the public docs. A qualification note that needs to identify the decoy
may reference that document by name; it never repeats its contents.

## Release criterion

The validator is the gate. Every required surface in the registry must
have exactly one matrix row with status `PASS`, an exact version and a
fresh, strict ISO-8601 `tested_at` inside the qualification window. No
other status satisfies the release: `FAIL`, `BLOCKED`, `manual_pending`
and `AUTOMATED PASS / MANUAL PENDING` all refuse the broad
third-party compatibility claim. A `BLOCKED` row is a useful tracking
statement for "qualification work is scheduled, with a documented
blocker", but it is never a compatibility claim. The automated
evidence (the three-engine lane and the real-browser lanes) is the
baseline that stays required; the manual matrix is the gate for the
broad third-party claim. Automated simulations of engine fill behavior
are not a substitute for the real manager surfaces, because the
invariant is about what real fill engines do with the real page.

The committed matrix stands deliberately fail-closed: every required
row is `manual_pending` with the `CURRENT` placeholder and no date, so
`tools/ci/validate-autofill-qualification.mjs` refuses it today. That
is the honest state until the manual runs happen, not a defect.

## Real-Firefox qualification log

The real-Firefox qualification was attempted and completed on
2026-08-30. Firefox was not installed at /Applications/Firefox.app;
a Homebrew cask install (brew install --cask firefox) completed
successfully, installing Firefox 154.0.1. The decoy evidence suites
(autofill-evidence, decoy-polymorphism and targeted-bot) were run
against the real installed Firefox binary through a Playwright
config override (tests/browser/playwright.firefox.config.mjs, the
'firefox' channel), a new file mirroring the real-chrome lane. All
21 tests passed. The native Firefox autofill prompt interaction (a
saved login filling the real fields through the browser's own prompt)
remains a pending manual row. The automated lane drives the engine
fill heuristics and the page surface, which is the evidence the
automated lane can provide. The manual confirmation steps are listed
in the matrix row above.
