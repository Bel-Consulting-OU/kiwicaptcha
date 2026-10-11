# Cost to abuse

The public per-value-class table (change.md Part 10.4): what an
attacker pays per successful abuse per value class, measured and
published rather than asserted. The figures below are the output of
`kiwicaptcha-solver bench` on the machine that generated this table
(the rung table, the reference classes and the dollar columns are the
tool's own printed rows, not hand-entered values), with the campaign
cross-references beneath.

Reference class provenance: Every figure below is a conservative class value compiled from free, public sources, rounded in the defender's disfavor (the attacker is assumed fast and cheap). No measurement precision is claimed: these are order-of-magnitude anchors for the bench's dollar comparison, refreshed by hand, and the bench prints this file's as_of beside every derived dollar figure.
(as of 2026-10; refreshed by hand, stale entries replaced).

## The value-class table

What one successful abuse is WORTH to an attacker per value class,
against what the rung costs them. The declared abuse value is an
independent stake estimate (the underground resale value of one
compromised account of that class, from public reporting), never a
function of the attacker's own solve cost. Deriving the stake from
the cost would make the D3.3 check circular (cost > cost/10 always
holds). Adopters override the declared value per scope in their
doctor configuration.

| Value class | Rung | Declared abuse value (USD / account) | Measured attacker cost on this CPU (USD / 1,000 solves) | Cheapest tabled GPU (USD / 1,000 solves) | Cost per 1 solve | Verdict at the default rung |
| --- | --- | --- | --- | --- | --- | --- |
| low | sha16 | $0.01 | $0.000674 | $0.00000136 (gpu-highend-2026) | $0.00000067 | cost < value: escalate |
| standard | sha18 | $0.50 | $0.003441 | $0.00000646 (gpu-highend-2026) | $0.0000034 | cost < value: escalate |
| high | argon16 | $5.00 | $0.001166 | no published class figure | $0.0000012 | cost < value: escalate |
| critical | argon64 | $50.00 | $0.004243 | no published class figure | $0.0000042 | cost < value: escalate |

Provenance: the declared values are independent stake anchors from
public credential/account resale reporting (order-of-magnitude,
rounded in the defender's favor: low-value forum/bot accounts ≈
$0.01, standard consumer accounts ≈ $0.50, financial-adjacent ≈
$5, admin/banking ≈ $50 per account). The measured columns are the
`this_cpu_usd` and `best_reference_usd` columns of a fresh
`kiwicaptcha-solver bench` run (50 seed-pinned samples per rung,
$0.01 per core-hour), cross-checked against the D3.3 campaign
measurements (`tools/redteam/runs/env/d33-economics*.json`) and the
anchors shipped in `reference-costs.json`. The argon2id rungs carry
no GPU class on purpose; the bench prints insufficient-reference-data
verdicts there and the native CPU estimate is the only anchor.

The honest conclusion is the one the calibration was hiding: raw
proof of work cannot price a stake of any real value at any
difficulty that a browser can meet. Every default rung's cost per
solve is orders of magnitude below the account's worth, so D3.3
correctly reports `cost < value: escalate` and the enforcement knob
is mandatory — raise the scope's disposition minimum
(`risk.scopes.<name>.minimum`) to `step_up` or `deny`. A D3.3 row
that claims green at these stake levels without escalation is
wrong.

## Hardware classes the attacker rents

Dollar rates are current published on-demand rental, rounded in the
defender's disfavor (the attacker is assumed to take the cheapest
published community rate). Hash rates are conservative class anchors
from public GPU cracking-benchmark indices (hashcat-class raw SHA-256
figures), not a claim about any one card. The rows are the shipped
`reference-costs.json` attacker-rate table verbatim (as of 2026-10),
the exact file the bench embeds and prices every dollar verdict from;
the bench prints each row's provenance beside it, so the table and
the tool can never drift apart.

| Hardware class | Class id | Algorithm | Rate (hashes/s) | Rental (USD/hour) | Source |
| --- | --- | --- | --- | --- | --- |
| mid-range consumer GPU | gpu-mid-2026 | sha256 | 2.0e+9 | $0.40 | public GPU cracking benchmark indices and public cloud spot pricing indices, rounded conservatively |
| high-end consumer GPU | gpu-highend-2026 | sha256 | 1.5e+10 | $1.20 | public GPU cracking benchmark indices and public cloud spot pricing indices, rounded conservatively |

A third shipped class, `mining-silicon-2026`, deliberately carries no
rate card and therefore no row above (see below).

Mining-ASIC silicon is deliberately absent. A mining ASIC is
sha256d-hardwired for the Bitcoin block-header midstate pipeline; the
SHA rungs here hash an arbitrary challenge string (challenge ∥ nonce),
so the chip cannot be pointed at this challenge format without a
redesign, and no credible public rental market exists for
captcha-scale ASIC cycles. It is not a usable attacker class for this
challenge, and carrying a row for it would imply otherwise.

The tabled rates are rounded class anchors, not today's cheapest
listing; refreshing them belongs to the documented refresh cycle
(re-check the source classes, re-run the bench, bump as_of), not to
hand-edited table rows, so the document and the bench stay one file.

## What one solve costs an attacker here

Ratios are against the sha16 rung. A leading-zero rung costs
2^(bits) expected hashes, so the ladder multiplies work by 2 per
2 bits of difficulty.

| Ladder rung | Work vs sha16 | Measured cost | Note |
| --- | --- | --- | --- |
| sha16 | 1× (2^16 hashes) | the bench's own table | native sha256, single core |
| sha18 | 4× (2^18 ÷ 2^16 = 4) | 4× the sha16 row | native sha256, single core |
| sha20 | 16× (2^20 ÷ 2^16 = 16) | 16× the sha16 row | native sha256, single core |
| argon16..64 | memory-hard; not a sha ratio | see the bench's own table | native argon2id, single core |
| rsw | inherently sequential; no hardware class buys a parallel speedup | see the bench's own table | time-lock squaring |

argon2id and rsw deliberately carry no attacker-rate rows in the
hardware table. Published GPU argon2id figures swing with the memory
cost and vendor, so one number would fabricate precision; rsw
squaring is inherently sequential and no hardware class buys a
parallel speedup. For those rungs the bench reports the native
measurement and prints insufficient-reference-data verdicts instead
of guessing.

## Open measurement: browser-versus-native asymmetry on rsw

**Unmeasured.** The rsw rung is solved by the honest client in the
browser (JavaScript BigInt / WebCrypto), while an attacker would
solve it natively (Rust `rug`/`num-bigint`, GMP). If a native
implementation is *k*× faster than the shipped browser solver on the
same hardware, the attacker's real cost is 1/*k* of the honest solve
cost, and the honest-side measurement would overstate the price of
abuse by that factor. **No value of *k* is asserted here** — this
document does not invent one.

Methodology to close it:

1. Take the same rsw challenge (T ∈ {75,000, 150,000, 300,000}
   squarings, the shipped ladder rungs) and the same modulus.
2. Measure wall-clock per solve for (a) the shipped browser solver in
   the three release engines (Chromium, Firefox, WebKit) and (b) a
   native reference implementation (the repository's Rust/GMP path),
   on the **same physical CPU**, warm, n ≥ 30 solves each.
3. Publish *k* = native ÷ browser (geometric mean across engines),
   the per-engine spread, and the three T points separately — the
   asymmetry may not be constant in T.
4. Repeat on at least one mainstream mobile CPU; the honest client
   is disproportionately mobile.
5. Until *k* is measured and published here, the rsw row reports the
   sequential-work bound only, and any rsw dollar verdict from the
   bench is labelled with this open measurement rather than folded
   into a value-class figure.

## Reading the table

The campaigns report cost per ACCEPTED abuse. A green campaign in
THREATS.md means the recorded run's required result held at the
scale its evidence column states — not that every volume of the
specification was replayed. Where the recorded run accepted zero
abuses the attacker's cost per successful abuse is unbounded there:
the spend is real (the bench prices every solve) and the yield is
zero. Where a run measured a non-zero yield (for example D3.5's
documented corpus residual), the economic line carries that count
and the scale honestly. A hash budget is never restated as a solve
count: the D3.5 wire sample, for example, paid millions of proof-of-work
hashes for a few hundred wire solves, and the evidence note says so.

The engine's economic lines carry the measured spend per honest
solve; the bench's own verdict per value class
(packages/kiwicaptcha-solver bench) prices each scope's abuse value
against these rates.
