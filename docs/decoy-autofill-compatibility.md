# Decoy autofill and password-manager compatibility

## Scope

The widget renders a server-issued decoy (honeypot) form field next to
the token input. Autofill engines are the strongest real-world
challenge to this surface: a filler that populates every field it sees
could fill the decoy, and a filler that recognizes the decoy's name
could trip the evidence. This document records the automated coverage
and the manual qualification matrix for the interaction.

## Automated coverage

The automated suite lives in `tests/browser/specs/adversarial-portable.spec.mjs`
in the autofill compatibility describe block, and runs in Chromium,
Firefox and WebKit via `playwright.a11y.config.mjs`. The fills are
simulated with the native value setter plus bubbled input and change
events, the same event sequence built-in autofill and password managers
produce.

The automated checks assert:

- The exact authenticated decoy name yields additive evidence: the
  fixture answers `ok:true` with `honeypot_hit:true`, so the valid
  proof keeps its verdict and the hit rides alongside it.
- Real-field fills and guessed pool names produce no hit, and the decoy
  input stays empty.
- The decoy keeps `autocomplete=off`, `tabindex=-1`, `aria-hidden=true`
  and `display:none`, so it stays off the autofill candidate surface.
- The serialized form payload carries the decoy only as its own empty
  name, and the decoy name never collides with a real field.
- Form-assistance DOM mutations, such as wrapping the form in a new
  element and adding attributes, leave the widget lifecycle and the
  decoy evidence intact.

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

## Manual qualification matrix

| Tool | Expected behavior | Qualification steps | Pass criteria |
|---|---|---|---|
| Chrome built-in autofill | Address and payment autofill fills only named, visible fields; the hidden decoy stays empty | Register a profile, autofill the real form, then submit and check the server response | Decoy empty, no hit, proof valid |
| Edge built-in autofill | Same engine family as Chrome; the decoy stays empty | Register a profile, autofill the real form, then submit and check the server response | Decoy empty, no hit, proof valid |
| Firefox built-in autofill | Form-fill heuristics skip hidden and non-interactive fields; the decoy stays empty | Register a profile, autofill the real form, then submit and check the server response | Decoy empty, no hit, proof valid |
| Safari built-in autofill | Contact autofill targets recognized fields only; the decoy stays empty | Enable contact autofill, fill the real form, then submit and check the server response | Decoy empty, no hit, proof valid |
| iCloud Keychain | Password fill targets the recognized password and username fields; the decoy stays empty | Save a login for the page, then use the Keychain fill on the real form | Decoy empty, no hit, proof valid |
| 1Password | Field-matching heuristics run on visible candidate fields; the decoy is hidden so it is skipped | Use the 1Password fill action on the real form, then submit | Decoy empty, no hit, proof valid |
| Bitwarden | Autofill matches by name and autocomplete hints; the decoy has none and stays empty | Use the Bitwarden fill action on the real form, then submit | Decoy empty, no hit, proof valid |
| LastPass | Fill heuristics skip hidden inputs; the decoy stays empty | Use the LastPass fill action on the real form, then submit | Decoy empty, no hit, proof valid |
| Dashlane | Form fill targets visible labeled fields; the decoy stays empty | Use the Dashlane fill action on the real form, then submit | Decoy empty, no hit, proof valid |
| Mobile-browser form helper | The on-screen form assistant offers fills for the visible fields only; the hidden decoy is never a candidate | Use the assistant on a mobile browser for the real form, then submit | Decoy empty, no hit, proof valid |
| Accessibility tooling | A screen reader's form navigation skips the decoy: it carries `aria-hidden` and no label | Navigate the form fields with a screen reader and confirm the decoy is absent from the list | Decoy skipped, no hit, proof valid |

## Recording

Qualification happens at release time for each released artifact,
following the release gate pattern used by the accessibility
qualification. Each row records the tool name and version, the browser
and operating system, the date, and the result. A row that fails is a
release blocker until the behavior is understood and fixed.
