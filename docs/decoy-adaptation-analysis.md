# Decoy adaptation analysis: the targeted-bot surface

## Scope and threat model

The decoy (honeypot) field is a form-level deception layer: the server
issues an authenticated field name, the driver renders one hidden input
with that name, and a non-empty value under the exact authenticated
name rides the submission as additive risk evidence. The proof of work
and the signed record decide the outcome; the decoy evidence is a
signal, never a gate.

The threat model here is the targeted bot, not the generic scraper. A
targeted bot is Kiwi-aware: it reads the challenge response before the
widget renders, it reads the rendered DOM after, and it can adapt its
fill or skip decisions per issuance. The question answered in this
document is what a perfect decoy classifier would use, what the current
polymorphism hides from it, and which candidate variations are worth
their cost under the standing invariants. The standing invariants are:
a perfect decoy classifier must not defeat KiwiCaptcha, presentation is
never a security boundary, the 2^-64 name-collision guarantee holds,
and accessibility and autofill safety are hard requirements.

## The machine-visible signature inventory

Every rendering variant carries the same union of signatures. A
classifier needs any one of them, not all of them.

1. The node itself: an `input[type=text]` whose `name` is a grammar
   prefix plus a fresh 16-lowercase-hex suffix, whose value starts
   empty, and which is owned by the driver (the `data-kiwi-owner`
   marker is on the input and, for the wrapped variants, on the wrapper
   too).
2. `aria-hidden=true` on the input, every variant.
3. `tabindex=-1` on the input, every variant.
4. Exactly one invisibility mechanism, never two: `display:none`
   (variants 0, 1 and the post-solve surface of 5), the HTML `hidden`
   attribute (variants 2 and 4), or an offscreen geometry (variant 3:
   `position:absolute`, `left:-9999px`, a 1x1 box, clipped).
5. An `autocomplete` attribute, always: `off` or `new-password`.
6. Placement: the input is a direct sibling of the token input inside
   the token's parent node, inserted before it (variants 2 and 4) or
   after it (variants 0, 1, 3 and 5). The token host is the protected
   form itself, so the decoy is always one edge away from the token.
7. The count: exactly one decoy input per widget, one per issuance,
   removed on reissue and reset.
8. The network surface: the challenge response carries the decoy name
   (and, on the fixture, the optional non-authenticated strategy
   hint). A bot with network access learns the name before the DOM
   exists.
9. The response-to-DOM coupling: the rendered name always equals the
   response's name, and the render happens only after a response that
   carried a decoy name.

## What a targeted DOM classifier would use

In order of power, all exact:

- The ownership marker alone: `input[data-kiwi-owner="decoy"]` is a
  one-selector identification with no ambiguity. The marker is
  internal and never submitted, but it lives in the DOM.
- The accessibility union: `input[aria-hidden="true"][tabindex="-1"]`
  selects exactly the decoy on a protected page, because no real
  application field combines both attributes.
- The adjacency: the non-token text input that is a sibling of the
  token input. This needs no Kiwi-specific knowledge at all.
- The name shape: the grammar-prefix plus 16-hex-suffix regex
  identifies the field without any attribute knowledge.
- The network: reading `decoy_field` from the challenge response
  identifies the name before rendering, which makes every DOM-only
  method redundant for a bot that can read the wire.

The honest summary: a classifier that is allowed to read the response
or the DOM union identifies the decoy with certainty. That is
structural, not a defect. The decoy must be a real serialized form
field with the authenticated name, so it cannot be hidden from a reader
that the form itself trusts. What the polymorphism can do is bound the
value of cheaper heuristics and force the targeted classifier to use
the union or the wire.

## What the polymorphism hides, quantified

The presentation space, per issuance:

- Six strategies (the fixture hint 0-5 forces each; production omits
  the hint and the driver draws the strategy from the client CSPRNG,
  uniform over six).
- Four wrapper classes for the wrapped variants (uniform, client-side
  pick), so the wrapped strategies instantiate as four looks each.
- Two placement classes (before or after the token) and two timing
  classes (immediate, or deferred until the first solve completes).

That is twelve concrete settled presentations plus the deferred timing
dimension. The strategy is drawn independently of the name: the name is
derived from the nonce and the strategy from the client CSPRNG, so the
name never predicts the presentation and the presentation never
predicts the name. Variants 0 and 5 share a settled DOM, so a
snapshot-based classifier cannot distinguish them; only an observer
that watches the form host before the solve sees the deferral.

What the polymorphism does not hide is the invariant union above. A
classifier over the union is one branch, not twelve, and it is exact.
The polymorphism raises the cost of shape-heuristic filters (a
fill-every-hidden-field bot, a display:none filter, an autofill
heuristic) and it makes the presentation dimension useless as a signal
for the classifier, but it does not and cannot make the decoy
unidentifiable. The 27,840-name grammar and the 64-bit suffix are the
name-space guarantee: guessing the name is hopeless, reading it is
trivial, and the system is designed around the second fact.

## Candidate variations: cost and benefit

### Multi-decoy manifests

Benefit: breaks the single-input count signature and the
fill-every-hidden-field heuristic; a classifier keyed on "the one
hidden input" loses its anchor. Cost: the protected form grows by N
serialized fields per page, the autofill false-positive surface grows
with each additional plausible-looking name, the axe-clean surface
grows with each additional node, and the protocol signs exactly one
decoy field per record today, so the evidence semantics would need a
protocol change (which name is the authenticated hit, what the record
carries). A targeted bot reads the response and knows the real name
whatever the count. The polymorphism specs pin the one-input invariant
and the compatibility matrix pins the no-false-positive claim. Verdict:
high cost, marginal value against the targeted model, real
accessibility and autofill risk. Not adopted.

### Per-deployment variation via a config knob

Benefit: deployments diverge. A botnet operator tunes a classifier on
one deployment's observed strategy distribution; a deployment that
pins a different subset, or a different wrapper vocabulary, forces a
re-tune per deployment. The hint seam already exists: the fixture
emits a non-authenticated strategy hint and the driver honors it when
present, so the knob would be a server-side emission policy per
sitekey, constraining the driver to a subset of the six validated
strategies. Cost: a configuration surface, a wider test matrix, and
the obligation that the subset never introduces a new presentation
(the six strategies are the axe-validated and autofill-validated set).
The invariant union is untouched, so the targeted classifier over the
union is unaffected; the value is against generic tooling trained on a
single distribution. Verdict: safe and bounded if it only constrains
the existing six. This round exercises the seam in the new spec (a
deployment pins a subset and every invariant holds) and defers the
actual knob, which would be a driver or bundle change.

### Timing variation

Benefit: defeats snapshot classifiers that inspect the page at a fixed
moment. The deferred variant already delivers the timing dimension:
the settled surface of variants 0 and 5 is identical, so a pre-solve
snapshot cannot distinguish them, and only an observer watching the
host sees the insertion. Cost: wider insertion jitter adds a race
between a submit and the deferred flush, which could serialize without
the decoy and lose evidence, for marginal gain against an observer
that already watches the host until the token write. Verdict: the
deferred variant is the timing variation; wider jitter is not adopted.

### Additional wrapper morphologies

Benefit: more templates for shape-specific classifiers; deeper nesting
can confuse adjacency heuristics. Cost: every node must stay
axe-clean, non-interactive and autofill-neutral, and the fresh render
has a bounded DOM budget pinned by an existing test. The wrapper
vocabulary is already a bounded set of four. The union signatures are
unchanged, so a targeted classifier is unaffected. Verdict: marginal
and cheap to add later inside a driver change, not adopted now.

### The ownership marker itself

The marker is the strongest single-line selector, stronger than the
accessibility union. Its removal from the DOM would cost a driver
change and a spec update (the polymorphism specs pin the marker), and
cleanup would then rely on the private owned set alone, which is
already the authoritative half of the removal contract. It is a
reasonable future driver change, out of scope here: the fixture and
the drivers are untouched by this round.

## The boundary and what this round adds

The security boundary is the authenticated name, the signed record and
the proof. The presentation is the deception layer above it: it raises
the cost of generic tooling and it is deliberately useless as a
classifier signal, but a perfect classifier changes nothing about the
outcome. This round adds the targeted-bot spec that pins that claim
(the bot learns the name and the strategy, watches the strategy vary
across fresh challenges, submits a correct solve with the decoy ignored
or filled, and receives deterministic answers on the documented evasion
surfaces), plus the analysis here. No driver file, no fixture file and
no existing file is modified.
