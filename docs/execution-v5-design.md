# Execution version 5: the causal object-graph grammar

This document is the design record for version 5 of the
ExecutionChallengeV1 execution-program dimension. It specifies the
next grammar rung end to end: the eight new opcodes, the causal-chain
design, the deterministic seed rule, the exact DOM state model the
simulators must implement, the complete file map, and the ladder
authority invariant. Version 4 is live today (the nested-tree
DOM_CHILD/DOM_DEPTH rung); this document is written against that
architecture and is the implementation blueprint for the version-5
rung. It matches the audit file list: every file that changes when the
rung lands is enumerated in the file-map section below.

## The execution-version ladder today

The dimension lives in `ExecutionChallengeGenerator` (PHP). A program
is a self-describing bytecode blob minted from a keyed PRF stream:

```text
block_i = HMAC-SHA256(execution_key,
    "kiwi-execution-v1|" . nonce . "|" . scope . "|" . action . "|" . version
    . u32be(i))
```

The same context always mints the same program, so the blob is a pure
function of (execution_key, nonce, scope, action, version). No
Math.random, no Date and no wall clock enter generation or op
semantics. The blob layout is fixed: the format version byte, the
length-prefixed scope and action, the op-version byte, the op count
(8-24), then one record per op: one opcode byte plus that opcode's
fixed-shape operand bytes, read in one canonical order everywhere. The
blob must end exactly at EOF; a valid prefix plus trailing bytes is
malformed.

The version byte is a grammar rung, and every rung bounds its own
opcode space below, so a mixed fleet rejects a newer grammar by the
declared version byte alone:

| version | adds | opcode space |
|---|---|---|
| 1 | the base construction-to-probe skeleton | 0-32 |
| 2 | the observe opcode and the causal u8 chain | 0-33 |
| 3 | a second constructed node and the sibling-index probe | 0-34 |
| 4 | the nested tree (DOM_CHILD, DOM_DEPTH) | 0-36 |

Each version raises the guaranteed-skeleton floor: version 1 floor 8,
version 2 floor 11 (the causal chain), version 3 floor 15, version 4
floor 18. The count byte is drawn from the stream before the extra
probes, and emission is capped at the stamped count, so every minted
blob lands inside the grammar and ends at EOF. The live maximum is 4
throughout: the PHP constant, the Rust mirror constant, the protocol
manifest, the driver's capability header and every test sweep derive
from the ladder in the way the authority section pins.

The execution digest binds the program, the challenge context and the
canonical op trace: hex HMAC-SHA256 keyed by the program bytes over
`kiwi-execution-v1|nonce|scope|action|version|trace`. The browser
holds only the program, computes the digest, and presents it with the
solution token; the verifier recomputes from the stored record. The
dimension is supplementary evidence, never the sole acceptance
boundary.

## How version 4 added the nested tree

Version 4 added opcodes 35 and 36. DOM_CHILD (dchild) creates a child
element under the current node and moves the current node onto the
child, so the program builds a real ancestor chain. DOM_DEPTH (ddepth)
probes the deepest nested child with an actual browser ancestor walk.
Encoding: DOM_CHILD draws a tag byte then an id operand; DOM_DEPTH
draws an id operand only. Seeds: the skeleton consumes the stream in
the fixed order above (create, mutate, append, the two child ops), so
the chain shape is deterministic per context. The verifier derives the
exact depth from its tree model instead of predicting a free value:
the depth is the number of ancestor elements up to (excluding) the
document body, counted over the parent map the replay builds from the
child ops.

## The two-language mirror and the register parity

`packages/kiwicaptcha/src/execution.rs` mirrors the PHP generator
byte-for-byte: the same PRF stream, the same draw order, the same
blob layout, the same decode strictness and the same opcode constants
through OP_COUNT 37. Its `MAX_EXECUTION_VERSION` constant is the Rust
side of the ladder. `protocol/execution-v1.json` is the shared wire
register: the schema id, the format version, the maximum execution
version, the opcode name-to-number map and the per-opcode trace-name
list, with internal-coherence rules (sequential numbers 0..N-1, equal
map and list sizes).

The parity gates:

- `ExecutionConstantsParityTest` (PHP) reads the manifest and asserts
  every constant equals the generator constant, including the maximum
  execution version, the opcode count and the trace-name list.
- The Rust mirror of that test lives in `execution.rs` and pins the
  same manifest rows against the module constants.
- `tools/ci/protocol-manifest-check.sh` re-checks every pair straight
  from the raw sources (the PHP and Rust constant declarations, the
  interpreter's declared OP_COUNT and version-gate string, and the
  manifest), so no handwritten list can drift silently.
- `WidgetDriverCapabilityParityTest` (PHP) reads the canonical driver
  asset and asserts its `Kiwi-Execution-Max-Version` header literal
  equals the generator maximum.
- The Symfony `KiwiHealthController` and `ChallengeController`
  constants derive from the generator constant, never from a literal.

## The server-side shadow simulators

The pure-PHP execution engine that recomputes expected digests
server-side is not a separate file: it is the deterministic state
machine inside `ExecutionChallengeGenerator` itself, the same class
that mints programs. `canonicalTrace` and `simulateOp` replay every op
over the shared state (the u8 array, the current DOM node, the
appended-id set), and `verifyExecutedTrace` re-simulates from a fresh
state to walk a submitted trace entry by entry. The `Verifier` calls
these entry points (`verifyExecutedTrace`, `digestOverTrace`) when an
armed record presents an executed trace, so the generator class is
both the mint and the shadow.

How the shadow models DOM_CHILD and DOM_DEPTH: DOM_CHILD creates the
child record under the current node with the id attribute reflected,
marks it appended, records its parent id, and moves the current node
onto it. The replay additionally keeps a parent map (child id to
current node id) that mirrors the tree topology, and the sibling
append ranks. DOM_DEPTH is browser-walked; the canonical sim emits
the placeholder `ddepth(ddepth)` because the exact value is derived
from the replay's parent map, and the verifier's submitted-trace
walker computes that exact ancestor count itself. The readback values
of the real-DOM probes legitimately contain ';' and parentheses, so
the trace is never split on a separator.

Two test-only twins mirror this engine: `ExecutionTraceFixture` (a
behavior-exact private copy of the simulator plus the trace-name
table, used to synthesize browser-equivalent traces with a fabricated
observed height) and `BrowserlessForgerySolver` (the adversarial
shadow solver). Both must stay in lockstep with the generator; the
verification suites pin that lockstep by replaying every fixture trace
through `verifyExecutedTrace` and cross-checking against the Rust
mirror.

## The grammar documentation format

The protocol doc is a single JSON manifest (`protocol/execution-v1.json`)
with five coherent rows: the schema id (`kiwicaptcha.execution-v1/1`),
the blob format version, the maximum execution version, the opcode map
(one row per opcode number, sequential 0..N-1) and the trace-name list
(one name per opcode). Every rung landing updates this manifest and
the parity lanes above fail until the PHP constants, the Rust
constants, the interpreter registers and the manifest all agree.

## The version-5 specification

### The rung

Version 5 is the causal object-graph rung. It extends the grammar to
forty-five opcodes: the existing 0-36 set plus eight new opcodes
37-44, with OP_COUNT 45. The decode fences become explicit per
version:

| version | fence |
|---|---|
| 1 | 33 |
| 2 | 34 |
| 3 | 35 |
| 4 | 37 |
| 5 | OP_COUNT (45) |

The version-4 row stops being the `default` arm: a version-4 program
must never carry opcodes 37-44, exactly as a version-3 program never
carries 35-36 today. The version-5 op-version byte stays a canonical
u8 on the register; the blob format version, the scope and action
grammar, the op-count bounds (8-24) and the exact-EOF rule are
unchanged.

### The eight new opcodes

Every new opcode follows the existing operand conventions: ids are
length-prefixed bytes from the id alphabet, attribute names index the
fixed ATTR_NAMES list, string values are length-prefixed printable
ASCII, raw bytes keep their canonical positions, and the generator
writes real lengths as length bytes. Trace names index the shared
table exactly like today.

| # | name | trace | operands (canonical order) | entry | class |
|---|---|---|---|---|---|
| 37 | DOM_FRAGMENT_APPEND | dfrag | slot byte (s % 4), dst cell byte | dfrag(n), child count of fragment slot s | exact, terminal |
| 38 | DOM_CLONE | dclone | id operand (the clone id), dst cell byte | dclone(n), clone subtree element count | exact |
| 39 | DOM_REPARENT | drepar | id operand (the new parent), dst cell byte | drepar(m), target child count after the move | exact |
| 40 | DOM_ATTR_REFLECT | dreflec | attribute-name byte (b % 5) | dreflec(base64 of the reflected value) | exact |
| 41 | DOM_EVENT_PHASE | dphase | dst cell byte | dphase(k), constructed elements reached | exact |
| 42 | DOM_URL_CANON | durlc | none | durlc(64 hex), canonical URL digest | observed |
| 43 | DOM_TEXT_MUTATE | dmutate | value operand, dst cell byte | dmutate(n), resulting text byte length | exact |
| 44 | DOM_SELECT_DEP | dsdep | three raw descendant-index bytes | dsdep(m), descent levels reached | exact |

Op semantics:

- DOM_FRAGMENT_APPEND moves the current node (with its whole subtree)
  into a detached real DocumentFragment held in fragment slot s, and
  the shadow moves the record the same way. The entry is the slot's
  child-element count after the move. The opcode is terminal: the
  generator emits it only as the final op of a version-5 program,
  because after the move no real-document probe can read the node.
- DOM_CLONE deep-copies the current node's subtree in the real DOM
  (cloneNode semantics), reassigns the copy's reflected id to the
  operand id, inserts the copy directly after the original, and moves
  the current node onto the copy. The entry is the cloned subtree's
  element count.
- DOM_REPARENT moves the current node's subtree under the constructed
  node named by the id operand (real appendChild semantics); the
  current node does not move. The entry is the target's child-element
  count after the move.
- DOM_ATTR_REFLECT reads the current node's real reflected property
  value for the indexed fixed attribute name (the property-reflection
  surface the browser exposes for id, title and the data-* pairs).
  The entry is the standard base64 of the reflected value.
- DOM_EVENT_PHASE dispatches a real bubbling event on the current
  node with listeners on every constructed ancestor, and the entry is
  the number of constructed elements that received it (the target and
  its constructed ancestors, excluding the body and the interpreter's
  script element): a real event-ordering readback over the built tree.
- DOM_URL_CANON reads the sandboxed document's URL, canonicalizes it
  per the URL standard (scheme and host lowercased, fragment dropped),
  and hashes the canonical string with SHA-256. The entry is the 64
  hex digest. It is the one browser-observed entry of the rung: the
  canonical sim emits the placeholder and the verifier validates the
  hex shape and replays the reported value, like the layout probes
  today. It is environment evidence, never a predicted scalar.
- DOM_TEXT_MUTATE sets the current node's real textContent to the
  value operand. The entry is the resulting byte length, and the node
  record now carries the text segment.
- DOM_SELECT_DEP walks real child elements from the current node down:
  step j descends into the child at index (byte j % child count) when
  the current level has children. The entry is the number of descent
  levels completed, 0-3, an exact traversal result.

### The causal-chain design

Version 2 introduced the causal pattern: create the u8 array, write a
browser-observed byte into a cell, read the cell back (its exact entry
must equal the observed value), then run a checksum or rotate consumer
over the array that still carries the byte. Version 5 generalizes the
pattern into a full spine where derived results feed later ops, and
the program culminates in serialization.

Cell conventions: every integer-entry v5 opcode carries a trailing dst
cell byte. The interpreter and every simulator write the op's entry
value into the u8 cell (b % 64) when the array exists and the cell is
in range, mirroring the observe replay exactly. The generator draws
dst bytes modulo the live array length, the same trick it already uses
for the observe index, so every issued program's writes land in range.
The derived-class writes happen inside the deterministic simulation,
so canonical and replayed traces agree; the observed-class write
(DOM_URL_CANON) follows the obs rule: the canonical sim emits the
placeholder, and the submitted-trace walker validates the shape and
replays the reported value into the cell.

The version-5 guaranteed spine: every issued version-5 program carries
the version-4 skeleton (15 fixed ops) plus six fixed ops, in order:
DOM_CLONE, DOM_REPARENT, U8_READ (of the reparent cell), DOM_URL_CANON,
DOM_TEXT_MUTATE and DOM_SERIALIZE_REAL. The U8_READ after DOM_REPARENT
binds the derived child count in the canonical trace, exactly like the
version-2 read-back entry binds the observed byte. The closing
DOM_SERIALIZE_REAL is the culmination: it digests the canonical
serialization of the current node record after the clone, the reparent
and the text mutation, so the trace's final readback covers the
accumulated record. The fixed skeleton is then 21 ops, and the
version-5 count formula is 21 + (nextByte % 4), keeping the 8-24
grammar bounds; 1-3 further real probes fill the drawn slots, and the
emission cap at the stamped count stays in force.

The version-5 extra-slot probe pool extends to the read-only real
probes of the rung (the observe, geometry, point, event-real,
serialize-real, sibling, depth, reflect, phase, url and select-depth
families). The topology mutators never appear in extra slots:
DOM_CHILD stays mapped away as today, DOM_FRAGMENT_APPEND is
terminal-only, and DOM_CLONE and DOM_REPARENT live only in the fixed
spine, mirroring the version-4 rule that a tree mutation never lands
mid-run in an arbitrary slot.

### Deterministic seed derivation

The seed rule is unchanged in shape and this is an invariant of the
rung: the program and every literal it carries derive from the keyed
PRF stream keyed by execution_key over the label plus the challenge
context (nonce, scope, action, version), block-counted with u32be.
Version 5 consumes the stream linearly after the version-4 draw
points: the count byte, the skeleton draws, the spine draws (clone id,
reparent id, cell bytes, the value operand), then the extra probes.
The derivation stays a pure function of the challenge context, so the
same context mints the same version-5 program on every engine and in
every mirror. Corpus and mutation seeds follow the same rule: test
suites derive their sweeps from the authority constant and their
randomness from explicit seed constants, never from a wall clock.

### The DOM state model the simulators must implement

The simulators (PHP generator shadow, the fixture twin, the browserless
solver, the Rust mirror and the interpreter) share one exact state
model. Version 5 extends the model from the current single-node-plus-
ids shape to a full ordered graph:

- A node record per constructed element: id, tag (one of the fixed
  tag list), the attrs map (with the reflected id), the dataset map,
  the classes set, an optional text segment, the appended flag, the
  parent id, and an ordered child-id list.
- The document body child list: constructed nodes in append order,
  with the interpreter's script element as the implicit first child
  (the sibling-index + 1 rule).
- Four fragment slots, each an ordered child-id list of nodes moved
  by DOM_FRAGMENT_APPEND. A fragment-moved node leaves the body child
  list; real-document probes (query-real, geometry, event-real,
  sibling, depth) read such a node as absent, deterministically.
- The appended-id set and the u8 causal array, as today.
- The current node pointer, as today. DOM_CREATE, DOM_CHILD,
  DOM_CLONE and the append-family ops move it by the rules above.

Replay bookkeeping stays derived, never stored twice: the parent map
and append ranks are rebuilt from the op stream in the same pass that
verifies the trace, so the exact sibling and depth values come from
one tree model. Node values are byte-exact across PHP, Rust and JS,
and string semantics never re-encode.

Version-5 canonical serialization: within a version-5 program, the
canonical serialization of a node record is the sorted attribute
pairs, then the sorted dataset pairs, then the sorted class names,
then the text segment when present, joined with ';' in that fixed
segment order. The serialization ops (serialize, serialize-real) hash
or base64 this canonical string, and the readback grammar is rung-
scoped: versions 1-4 keep today's attribute-only strings unchanged, so
older challenges stay verifiable for their whole TTL. The interpreter
builds the same canonical string from the real node (its real
attributes, dataset, classList and textContent), so the digest is
exact across engines.

## The file map

The audit file list, with concrete paths:

1. PHP generator and authority:
   `packages/kiwicaptcha-php/src/ExecutionChallengeGenerator.php`
   (the constant, the version rung, the count formula, the spine
   draws, the new simulateOp arms and the trace verification rules).
2. PHP simulator: the same file's deterministic state machine
   (`simulateOp`, `canonicalTrace`, `verifyExecutedTrace`), which the
   `Verifier` (`packages/kiwicaptcha-php/src/Verifier.php`) invokes;
   no separate simulator engine exists in src/.
3. Rust mirror: `packages/kiwicaptcha/src/execution.rs` (the constant,
   the opcode table, the draw order, decode and simulation, plus its
   manifest-parity test and the test-fixtures solver).
4. Interpreter and its mirrors: the canonical asset
   `packages/kiwicaptcha-wasm/assets/execution-interpreter.js` plus
   the byte-identical mirrors
   `packages/kiwicaptcha/resources/execution-interpreter.js` and
   `packages/kiwicaptcha/integrations/symfony/Resources/public/execution-interpreter.js`
   (copied by the wasm build; the asset-parity lanes pin the bytes).
5. Protocol doc: `protocol/execution-v1.json`, gated by
   `tools/ci/protocol-manifest-check.sh`.
6. Fixture twin:
   `packages/kiwicaptcha-php/tests/Support/ExecutionTraceFixture.php`.
7. Browserless oracle and solver:
   `packages/kiwicaptcha-php/tests/BrowserlessExecutionForgeryTest.php`,
   `packages/kiwicaptcha-php/tests/Support/BrowserlessForgerySolver.php`,
   and their Rust mirrors in `execution.rs` (the solver helper and the
   oracle test that sweeps every live version). The oracle must fail
   on the new rung until the solver implements the real semantics.
8. Differential corpus:
   `packages/kiwicaptcha-php/tests/ExecutionDifferentialCorpusTest.php`
   (the shared 16-case corpus) and its pinned cross-language tail in
   `packages/kiwicaptcha/tests/execution_mutation_fuzz.rs`.
9. Mutation corpora:
   `packages/kiwicaptcha/tests/execution_mutation_fuzz.rs` (the
   no-panic deterministic-outcome corpus over program bytes, header,
   opcodes, operands, trace and digest), with the cross-language
   fixtures in `packages/kiwicaptcha/tests/cross_language.rs`.
10. Browser tests: `tests/browser/specs/execution.spec.mjs` (chromium
    lane: tamper outcomes, request accounting, interpreter source
    greps), `tests/browser/specs/execution-portable.spec.mjs`
    (three-engine lane) and the widget-contract copy
    `packages/kiwicaptcha-wasm/tests/browser/specs/execution.spec.mjs`.
11. CSP tests: `tests/browser/specs/execution-csp.spec.mjs` (real
    response-header policies: the strict profile and the blocked
    profile, across the engine lanes).

## The ladder authority invariant

> The execution-version ceiling is authored in exactly one place:
> `ExecutionChallengeGenerator::MAX_EXECUTION_VERSION`. Version 5
> lands by raising that single constant to 5. Every other occurrence
> is a mirror that exists only under an executable parity pin: the
> Rust module constant, the protocol manifest row, the driver's
> capability header literal and the interpreter's declared registers
> must all be proven equal by the parity lanes, never chosen by hand.

Every test derives its range from the authority rather than hardcoding
a number: the PHP suites loop to the generator constant, the Rust
suites loop to the Rust constant (whose equality with the PHP constant
the parity lanes prove), the cross-language fixtures mint and verify
at the shared maximum, and the driver-header test reads the asset and
compares it to the generator constant. When the constant rises to 5,
the parity gates fail mechanically on every mirror until the mirror
changes agree, the version-prose ratchet then bans the stale
version-4-era phrases, and the corpus and fixture suites force the new
semantics to be real before any trace forges.

## Landing order

The implementation lands in this order: raise the authority constant,
regenerate the protocol manifest, watch the parity gates fail on every
mirror (proof the map is complete), then implement the rung in the
generator, the shadow, the Rust mirror, the interpreter and its
mirrors, extend the fixture twin and the solver together (the oracle
must pass only with real semantics), extend the differential and
mutation corpora, then run the browser and CSP suites across the
engine lanes. The version-prose ratchet must pass after the rewording
of any stale ladder phrase, and the docs-lint baseline stays at zero.
