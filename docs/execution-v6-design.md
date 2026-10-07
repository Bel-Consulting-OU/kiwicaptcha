# Execution version 6: the real-platform grammar

This document is the design record for version 6 of the
ExecutionChallengeV1 execution-program dimension. It specifies the
rung end to end: the five new opcodes, the probe designs, the
operand-derived acceptance envelopes, the async run contract, the
deterministic seed rule, the qualification harness, and the fail
proof. The design was written when version 5 was the live rung (the
causal object-graph grammar); the version-6 real-platform rung it
specifies has since landed as the generator maximum
(`ExecutionChallengeGenerator::MAX_EXECUTION_VERSION`).

## Why a sixth rung (and what it actually buys)

Versions 1-5 are reproducible by a pure implementation of the public
interpreter semantics. The forgeability oracle
(`BrowserlessExecutionForgeryTest` and its Rust mirror) pins that on
purpose: the trace of those rungs is supplementary evidence, never a
browser attestation.

Version 6 was designed as the first rung whose evidence would require
web-platform behavior: randomized-CSS computed geometry, MutationObserver
delivery order, real event phases, Range/Selection over a constructed
text graph, and IntersectionObserver thresholds. The verifier checks
every version-6 entry against an acceptance envelope derived from the
program operands.

**Honest boundary statement (full-knowledge adversary).** Every one of
those envelopes is a deterministic function of the operands that ship
with the program:

- OP_MUT_ORDER: the exact expected record-type string
- OP_RANGE_ORDER: the exact range string length plus a 1..16 fragment band
- OP_CSS_GEOM: the exact font size plus a seed-derived height interval
- OP_INT_OBS: a seed-derived ratio band
- OP_EV_PHASE_FULL: the constant `1234:3` for every program

A forger who implements those five functions (they are published in the
open-source verifier) emits passing traces WITHOUT any browser. The
white-box forger (`WhiteBoxEnvelopeForger` in the PHP suite,
`white_box_envelope_forgery_solver` in the Rust fixtures, and the
`whitebox` leg of the fail harness) measures that honestly: it passes
every version-6 program. The naive oracle's "100 percent rejection"
only tested forgers who did not know the envelopes — that is not a
full-knowledge number.

Version 6 therefore costs an attacker one reading of the source, the
same class as versions 1-5. It is NOT a browser boundary. It is
supplementary evidence that raises the cost of a *lazy* forger (one who
does not read the verifier) and keeps the pure-sim placeholder forger
out. The risk engine must never weight execution evidence as proof of a
real browser (it does not: `RiskV2Signals` and `EvidenceModel` carry no
execution field).

## The ladder after the rung lands

| version | adds | opcode space |
|---|---|---|
| 1 | the base construction-to-probe skeleton | 0-32 |
| 2 | the observe opcode and the causal u8 chain | 0-33 |
| 3 | a second constructed node and the sibling-index probe | 0-34 |
| 4 | the nested tree (DOM_CHILD, DOM_DEPTH) | 0-36 |
| 5 | the causal object-graph spine | 0-44 |
| 6 | the five real-platform probes | 0-49 |

The version-6 skeleton replaces the version-5 causal spine with the
five-op platform block over the version-4 skeleton: a fixed 20-op
skeleton plus 0..3 drawn extra probes, stamped as
`20 + (byte % 4)` (20..23, inside the 8..24 grammar bounds). The
count formula change is coherent across the generator, both mirrors
and the perf-budget largest-wire probe (its op-count ceiling for the
live rung is 23).

## The five probes

Every probe carries the probed constructed id (4..16 bytes, the
construction proof: the walker requires the id to be in the
appended-id set at probe time), a raw seed or churn operand, and a
raw u8 cell byte for its quantized observation. Every probe runs on
freshly constructed anonymous nodes it removes before returning, so
the deterministic document model is unchanged and the pure
simulators keep their no-op placeholder arms. The probe ids stay on
the two appended body children (the constructed id and the sibling
id): the dchild-created nodes never enter the appended-id set, so a
probe naming one could only ever read 'none'.

### CSS_GEOM (45, `dcsgeom`)

The seed draws the font size (10..14 px), the border width (1..3 px)
and a two-word probe text (the seed word plus the next word of
`kiwicaptcha`, `execution`, `boundary`, joined by a space, so a break
opportunity exists). The probe is a content-box 64px block with the
drawn border and `font-family: monospace`. The entry reports the
computed font size (rounded, must equal the drawn declaration
exactly) and the probe height (the wrapped line-box stack plus the
borders, quantized to a byte, written to the cell).

Envelope: `fs == drawn`; `h` inside
`[fs + 2*brd, linesMax * 2 * fs + 2 * brd + 2]` where
`linesMax = max(1, ceil(textLen * fs * 4 / 5 / 64) + 1)` in exact
integer arithmetic shared byte-for-byte by the PHP and Rust walkers.
A host without layout reports 0 and falls below the floor.

### MUT_ORDER (46, `dmutord`)

The churn: one attribute set, `1 + (b0 % 2)` element children, one
text child, optionally a characterData write (`b1 & 1`). A
MutationObserver records the type codes (attributes 1, childList 2,
characterData 3); a promise marker pushed after the churn reports as
7. The probe yields one microtask, so the observer microtask (queued
at the first mutation) and the marker both run before the entry is
built. The churn is fully self-cleaning: the probe restores the
prior attribute state and removes only the nodes it added, so the
constructed tree under the target survives.

Envelope: the entry equals
`"1" + "2" * (2 + (b0 % 2)) + ("3" if b1 & 1) + "7"` exactly, and
the record count (`3 + (b0 % 2) + (b1 & 1)` plus one) replays into
the cell. A task-queued or synchronous observer cannot produce it.

### EV_PHASE_FULL (47, `devphf`)

A fresh three-node chain (root, mid, target span) is attached to the
probed node. Listeners: root capture (logs 1), target capture-flag
(logs 2), target bubble (logs 3 and writes `target.dataset.phase`
as a listener side effect), root bubble (logs 4). The entry is
`codes.join("") + ":" + datasetReadback`, the exact `1234:3`, and
the cell carries the listener count 4.

### RANGE_ORDER (48, `drange`)

A fresh 48px monospace container holds three spans carrying the
consecutive `alpha`, `beta`, `gamma`, `delta` words from the drawn
index. The range starts at offset `ra % 5` in the first span's text
and ends at `rb % (len + 1)` in the third span's text. The entry
reports the exact range string length (derived exactly from the
drawn graph), the `getClientRects` fragment count (envelope 3..16,
the matrix band for three span fragments at the drawn wrap width)
and the Selection `rangeCount` after `addRange` (exactly 1; the
selection is cleared after the read). The fragment count replays
into the cell.

### INT_OBS (49, `dintobs`)

A fresh 120x40 root box with `overflow: hidden` (which also blocks
margin collapse) holds a 60x20 target at the drawn offset
`5 + (seed % 36)` px. An IntersectionObserver with the drawn
threshold (`0`, `0.25`, `0.5`, `0.75`) observes the target; the
probe awaits two animation frames (each raced with a 250 ms
fallback) so the observer delivers its initial entry. The entry is
`fired, round(ratio * 100), isIntersecting` and the quantized ratio
replays into the cell.

Envelope: `fired == 1`; the ratio inside the geometry-derived band
`qExp +/- 2` percent where `qExp = 5 * clamp(40 - m, 0, 20)` in
steps of five percent; `isIntersecting` must agree with the ratio
against the drawn threshold with the same two-percent band.

## The async run contract

A version-6 program runs asynchronously: the interpreter's `runProgram`
returns a promise for op versions above 5 and the message handler
posts the identical result message when it settles. The extra delay
is two microtask checkpoints plus at most four animation frames
(far inside the parent-side execution timeout). Versions 1-5 keep
the synchronous path byte-for-byte; the state machine is shared, so
both paths execute identical op semantics.

## The acceptance envelopes

The walker validates each submitted entry at its exact position and
replays every reported observation into the u8 cell it names (the
version-5 observe rule), so the whole trace stays causally coherent.
The envelope constants were calibrated against the cross-engine
qualification matrix: Chromium, Firefox and WebKit runs of the
portable v6 suite (tests/browser/specs/execution-v6-portable.spec.mjs)
must pass the walker through the fixture verifier, and the bounds
absorb the measured engine spread (monospace advance 0.45..0.80 em,
normal line-height 1.0..2.0 em, intersection quantization within two
percent, plus the exact-computed entries that admit no spread).

## The fail harness

tests/browser/execution-v6 carries the measurement harness: a
deterministic 10^5-program synthetic corpus (the real generator at the
real-platform rung) driven through four legs, all judged by the real
PHP envelope walker:

- the unchanged browserless forgery oracle (naive, emits pure-sim
  placeholders — rejected 100 percent, NOT a full-knowledge number),
- the white-box envelope forger (reimplements the five published
  envelopes; **passes every program** — the honest full-knowledge
  number, proving version 6 is not a browser boundary),
- the unmodified interpreter asset inside jsdom,
- the same inside happy-dom.

The measured outcome: the naive oracle and the emulator legs reject
100 percent of the corpus; the white-box leg passes 100 percent. The
emulator legs publish their per-attempt cost (the full-fidelity
headless emulator cost of a v6 attempt). The white-box pass rate is
the figure that belongs in every threat model: version 6 costs one
reading of the source.

## Optional hardening considered: HMAC-bound envelopes

Binding the expected envelope to a per-deployment secret (`execution_key`)
was considered and rejected as a fix that cannot exist in this
architecture:

- The key never leaves the server (it only feeds the program
  generator), so the browser interpreter cannot compute any keyed
  expected value.
- The browser reports real measurements determined by the public
  operands and the platform; a keyed envelope would either exclude real
  engines or add no restriction over the public band.
- Any keyed value shipped in the program or on the wire is visible to
  the same forger who already reads the operands.

The correct fix is honesty plus risk weighting: treat v6 as evidence
that costs one source reading, never weight it as proof of a real
browser, and keep the PoW/price ladder as the real acceptance boundary.
Deployments that want a genuine environment boundary need a protocol
change that puts a secret on the client (e.g. attested execution or a
server-mediated measurement), which is out of scope for this rung.

## Authority

The single ladder authority is the manifest row
(`protocol/execution-v1.json`, `max_execution_version: 6`), mirrored
by the PHP and Rust constants, the limits register, the widget
driver's `Kiwi-Execution-Max-Version` capability header and the
interpreter's decode gate, all pinned by the parity lanes. The
record grammar needs no change: the `|e=version,commitment` segment
carries the numeric byte, and the cores accept the canonical set
1..=6 while the SDK grammars keep their documented fail-closed
stance for records above their own ceiling.
