#!/usr/bin/env python3
"""The consistency-ledger ladder gate: the declared rung order against the
two action enums, machine-compared on every run.

docs/consistency-ledger.md (and change.md §1.4) declare the escalation
ladder as an ordered rung sequence. The enforcement points are the Rust
enum (packages/kiwicaptcha-risk/src/action.rs) and the PHP mirror
(packages/kiwicaptcha-risk-php/src/RiskAction.php): the enum declaration
order is the ladder order, `rank()` is the strictly monotonic witness,
and the wire strings are the cross-language vocabulary. A rung inserted
in one place but not the others — or a declared order that drifted from
the code — silently reorders every comparison built on rank(). This gate
re-reads all four sources and fails on any disagreement:

  1. the declared ladder in docs/consistency-ledger.md (the §1.4 row's
     arrow sequence) and in change.md (§1.4's arrow line);
  2. the Rust enum: variant declaration order, each variant's wire
     string from the `as_str()` match, and the `rank()` arms 0..N-1 in
     declaration order;
  3. the PHP enum: case declaration order, each case's wire string, and
     the `rank()` arms 0..N-1 in case order.

The comparison is on the wire names (allow, sha16, ..., rsw, step_up,
deny): the enum identifiers differ per language, the wire contract does
not. Quarantine never appears in the ladder (change.md 1.3: a
disposition, never a rung); the change.md line spells the terminal rung
`Deny/Quarantine`, which normalizes to `deny`.

A declared ladder line is recognized by its shape: an arrow chain that
begins at allow and ends at deny. Prose arrows elsewhere (data-flow
diagrams, pipelines) never carry that shape.

Usage:
  python3 tools/ci/consistency-ledger-ladder-check.py            # live tree
Exit status: 0 when every source agrees, 1 with the drift report.
Pure offline tooling: it reads only the checkout.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

LEDGER = os.path.join(ROOT, "docs", "consistency-ledger.md")
CHANGE = os.path.join(ROOT, "change.md")
RUST = os.path.join(ROOT, "packages", "kiwicaptcha-risk", "src", "action.rs")
PHP = os.path.join(ROOT, "packages", "kiwicaptcha-risk-php", "src", "RiskAction.php")

# The wire-name vocabulary: every rung the two enums may declare, in no
# order (the order is the compared fact, never assumed here).
KNOWN_WIRE = {
    "allow", "sha16", "sha18", "sha20",
    "argon16", "argon32", "argon64",
    "rsw", "step_up", "deny",
}

# A declared arrow chain: rung tokens (the disposition suffix
# `Deny/Quarantine` included) joined by unicode or ascii arrows.
ARROW_SEQ = re.compile(
    r"[A-Za-z0-9_]+(?:/[A-Za-z]+)?(?:\s*(?:→|->)\s*[A-Za-z0-9_]+(?:/[A-Za-z]+)?)+")
Rung = re.compile(r"[A-Za-z0-9_]+(?:/[A-Za-z]+)?")

# The Rust enum body, the as_str wire arms and the rank arms.
RUST_ENUM = re.compile(r"pub enum RiskAction \{(.*?)\}", re.S)
RUST_VARIANT = re.compile(r"^\s+(?:#\[default\]\s+)?([A-Z][A-Za-z0-9]*),?\s*$", re.M)
RUST_AS_STR = re.compile(r"RiskAction::([A-Z][A-Za-z0-9]*) => \"([a-z0-9_]+)\"")
RUST_RANK = re.compile(r"RiskAction::([A-Z][A-Za-z0-9]*) => (\d+)")

# The PHP cases and rank arms.
PHP_CASE = re.compile(r"^\s*case ([A-Za-z0-9]+) = '([a-z0-9_]+)';\s*$", re.M)
PHP_RANK = re.compile(r"self::([A-Za-z0-9]+) => (\d+)")


def fail(messages, message):
    messages.append(message)


def normalize_rung(token, where, messages):
    """A declared rung token to its wire name: case-folded to the snake
    wire spelling (change.md writes `StepUp`, `Argon16`, `RSW`), the
    disposition suffix stripped (the terminal `Deny/Quarantine`)."""
    name = token.strip().split("/", 1)[0].strip()
    name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()
    if name not in KNOWN_WIRE:
        fail(messages, "%s: the declared rung %r is not in the wire vocabulary %s"
             % (where, token.strip(), sorted(KNOWN_WIRE)))
        return None
    return name


def declared_ladder(text, where, messages):
    """The declared ladder in the document: the arrow chain that starts
    at allow and ends at deny. More than one distinct such chain is an
    internal contradiction of the document itself."""
    ladders = []
    for line in text.split("\n"):
        for raw in ARROW_SEQ.findall(line):
            tokens = Rung.findall(raw)
            if not tokens:
                continue
            if tokens[0].split("/")[0].lower() != "allow":
                continue
            if tokens[-1].split("/")[0].lower() != "deny":
                continue
            ladder = [normalize_rung(token, where, messages) for token in tokens]
            ladder = [rung for rung in ladder if rung is not None]
            if len(ladder) >= 3 and ladder not in ladders:
                ladders.append(ladder)
    if not ladders:
        fail(messages, "%s: no declared ladder found (expected an `allow -> ... -> deny` chain)" % where)
        return None
    if len(ladders) > 1:
        fail(messages, "%s: %d distinct declared ladders (%s); the document contradicts itself"
             % (where, len(ladders), " vs ".join(" -> ".join(l) for l in ladders)))
        return None
    return ladders[0]


def rust_enum(path, messages):
    """The ladder (the wire names in declaration order) from the Rust
    enum, with the rank() monotonicity witness."""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    body = RUST_ENUM.search(text)
    if body is None:
        fail(messages, "%s: no `pub enum RiskAction` found" % path)
        return None
    variants = [match.group(1) for match in RUST_VARIANT.finditer(body.group(1))]
    if not variants:
        fail(messages, "%s: the enum declares no variants" % path)
        return None

    wire = {}
    for name, value in RUST_AS_STR.findall(text):
        wire.setdefault(name, value)
    ranks = {}
    for name, rank in RUST_RANK.findall(text):
        ranks.setdefault(name, int(rank))

    ladder = []
    for name in variants:
        if name not in wire:
            fail(messages, "%s: the variant %s carries no as_str() wire string" % (path, name))
            return None
        if name not in ranks:
            fail(messages, "%s: the variant %s carries no rank() arm" % (path, name))
            return None
        if wire[name] not in KNOWN_WIRE:
            fail(messages, "%s: the wire string %r of %s is not in the vocabulary" % (path, wire[name], name))
            return None
        ladder.append(wire[name])
    # rank() is the strictly monotonic witness: declaration order ranks
    # 0..N-1, with no gaps and no duplicates.
    for index, name in enumerate(variants):
        if ranks[name] != index:
            fail(messages, "%s: %s carries rank %d at declaration position %d; rank() must be 0..%d in declaration order"
                 % (path, name, ranks[name], index, len(variants) - 1))
    return ladder


def php_enum(path, messages):
    """The ladder (the case values in case order) from the PHP enum,
    with the rank() monotonicity witness."""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    cases = []
    wire = {}
    for match in PHP_CASE.finditer(text):
        name, value = match.group(1), match.group(2)
        if value not in KNOWN_WIRE:
            fail(messages, "%s: the case value %r is not in the vocabulary" % (path, value))
            continue
        cases.append(name)
        wire[name] = value
    if not cases:
        fail(messages, "%s: no enum cases found" % path)
        return None
    ranks = {}
    for name, rank in PHP_RANK.findall(text):
        ranks.setdefault(name, int(rank))
    ladder = []
    for name in cases:
        if name not in ranks:
            fail(messages, "%s: the case %s carries no rank() arm" % (path, name))
            return None
        ladder.append(wire[name])
    for index, name in enumerate(cases):
        if ranks[name] != index:
            fail(messages, "%s: %s carries rank %d at case position %d; rank() must be 0..%d in case order"
                 % (path, name, ranks[name], index, len(cases) - 1))
    return ladder


def compare(label, declared, actual, messages):
    if declared is None or actual is None:
        return
    if declared != actual:
        fail(messages,
             "%s ladder drift:\n      declared: %s\n      actual:   %s"
             % (label, " -> ".join(declared), " -> ".join(actual)))
        return
    print("  %s: %s" % (label, " -> ".join(actual)))


def main():
    messages = []

    def read(path):
        if not os.path.isfile(path):
            fail(messages, "missing source: %s" % os.path.relpath(path, ROOT))
            return ""
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()

    declared = declared_ladder(read(LEDGER), "docs/consistency-ledger.md", messages)
    change_ladder = declared_ladder(read(CHANGE), "change.md", messages)
    rust_ladder = rust_enum(RUST, messages)
    php_ladder = php_enum(PHP, messages)

    print("consistency-ledger ladder check")
    compare("declared (consistency-ledger.md)", declared, declared, messages)
    compare("declared (change.md §1.4)", declared, change_ladder, messages)
    compare("Rust enum (action.rs)", declared, rust_ladder, messages)
    compare("PHP enum (RiskAction.php)", declared, php_ladder, messages)

    if messages:
        for message in messages:
            print("consistency-ledger-ladder-check: FAIL: %s" % message, file=sys.stderr)
        return 1
    print("consistency-ledger-ladder-check: PASS (the declared ladder, the Rust enum "
          "and the PHP enum agree on %d rungs)" % len(declared))
    return 0


if __name__ == "__main__":
    sys.exit(main())
