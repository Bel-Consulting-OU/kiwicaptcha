# Decoy adaptation analysis: the threat-model summary

## Scope

The decoy (honeypot) field is a form-level deception layer: the server
issues an authenticated field name, and the widget renders one hidden
input with that name. A non-empty value under the exact authenticated
name rides the submission as additive risk evidence. The proof of work
and the signed record decide the outcome; the decoy evidence is a
signal, never a gate.

This document is the deliberate threat-model summary of the decoy
surface. The adaptation-sensitive details behind it (the naming
structure, the presentation inventory, the exact attribute surface, the
timing characteristics and any classifier features) are intentionally
not published: strategic silence buys adaptation time, and the
properties below hold regardless of those details.

## The standing properties

- Per-challenge: a decoy exists for exactly one issuance and dies with
  it. A name issued for one challenge is never meaningful for another.
- Authenticated: the name is part of the signed challenge record, and
  a submitted hit is verified against the record it was issued with.
- Randomized: the name is fresh high-entropy randomness per issuance,
  so guessing it is hopeless while reading it is trivial.
- Browser-compatible: the decoy is a real serialized form field that
  any compliant browser submits, so it behaves like any other field on
  the wire.
- Inaccessible to legitimate interaction: the decoy is never reachable
  through normal page interaction, so a human using the form cannot
  trip it by accident.
- Probabilistic evidence only: a filled decoy raises the risk signal;
  it never decides the outcome on its own.
- Never the fundamental proof boundary: the proof-of-work cost, the
  single-use state transition, the risk engine and the replay controls
  all stand on their own. The decoy adds evidence above them and is
  deliberately useless as a classifier signal.

## The invariant

A perfect decoy classifier does not defeat KiwiCaptcha. A reader that
identifies the decoy with certainty changes nothing about the security
boundary: the proof, the signed record, the atomic single-use state and
the risk controls are independent of the decoy layer. The
identification can come from the response or from the rendered page.
The decoy is additive evidence that raises the cost of generic
automation, never a load-bearing security mechanism.

## Testing posture

The decoy surface is tested against targeted automation: a bot that
reads the issued challenge before rendering, reads the rendered page
after, learns the decoy across fresh challenges, and adapts its fill or
skip decisions per issuance. The tests pin the invariant: whatever the
bot learns, a correct solve with the decoy ignored or filled receives
the documented verdicts, and the evidence stays additive. The same
suite pins browser compatibility, accessibility and autofill safety as
hard requirements.

## Reading this summary

The properties above are the ones the product documentation depends
on. Adaptation-sensitive parameters are a moving target; the
invariants are not.
