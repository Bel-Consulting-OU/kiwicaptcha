#!/usr/bin/env python3
"""The challenge-response wire parity gate.

The kiwicaptcha-verifier sidecar's challenge response is the canonical
client wire: the camelCase PoW key set (mKib, targetBits, ttlSecs,
minDurationMs) plus the optional security fields on the canonical
snake_case spellings the stored-record schema owns (execution_program,
execution_version, rsw_modulus). The golden fixture
(protocol/solution-token-v1/challenge-response-fixtures.json) pins one
real body per shape. This script is the cheap, Rust-free half of the
enforcement; the other half is the Rust serializer parity test
(packages/kiwicaptcha-verifier tests/sidecar.rs
challenge_response_wire_matches_the_golden_fixtures), which mints every
shape through the real HTTP surface and asserts the structural shape
against the same fixture.

This script asserts, without building anything:

1. the fixture file itself is well-formed: one body per shape, the
   exact key set and the exact JSON value type per shape, and the
   camelCase dialect (executionProgram/executionVersion) present in no
   shape;
2. the Rust parity harness stays wired: the committed test still reads
   this fixture (deleting the test fails here before the wire can
   drift unguarded);
3. every client-side parser of the challenge wire references exactly
   the fixture's field names: the snake_case spellings where the
   execution fields are parsed, and never the camelCase wire keys in
   any sidecar client source.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "protocol" / "solution-token-v1" / "challenge-response-fixtures.json"

COMMON_KEYS = {
    "nonce": "string",
    "challenge": "string",
    "salt": "string",
    "algorithm": "string",
    "mKib": "integer",
    "t": "integer",
    "p": "integer",
    "targetBits": "integer",
    "ttlSecs": "integer",
    "minDurationMs": "integer",
    "prefix": "string",
    "profile": "string",
}
EXPECTED_SHAPES = {
    # name -> (full expected key->type map, algorithm, the non-common extras)
    "plain-sha256": (COMMON_KEYS, "sha256", set()),
    "plain-argon2id": (COMMON_KEYS, "argon2id", set()),
    "plain-rsw": (COMMON_KEYS | {"rsw_modulus": "string"}, "rsw", {"rsw_modulus"}),
    "execution-armed": (
        COMMON_KEYS | {"execution_program": "string", "execution_version": "integer"},
        "sha256",
        {"execution_program", "execution_version"},
    ),
}
# The banned camelCase dialect as a WIRE key: quoted JSON keys only. A
# quoted literal is the wire spelling; an unquoted property access (the
# SDKs' own domain objects, e.g. the node SDK's record.executionProgram)
# is internal naming over the stored-record canonical and is not wire.
CAMELCASE_WIRE_KEYS = ("executionProgram", "executionVersion")
CAMELCASE_QUOTED_WIRE_KEYS = (
    '"executionProgram"',
    "'executionProgram'",
    '"executionVersion"',
    "'executionVersion'",
)

# The client-side parsers of the challenge wire that must reference the
# fixture's snake_case execution spellings (path relative to the repo
# root, and the exact wire spelling each must carry).
SNAKE_CASE_PARSED_BY = [
    ("packages/kiwicaptcha-solver/src/lib.rs", "execution_program"),
    ("packages/kiwicaptcha-wasm/assets/widget-driver.js", "execution_program"),
    ("packages/kiwicaptcha-flutter/lib/src/challenge.dart", "'execution_program'"),
    ("packages/kiwicaptcha-php/src/Challenge.php", "'execution_program'"),
]
# The committed Rust parity harness that mints every shape against the
# fixture (the serializer half of this gate).
RUST_PARITY_TEST = "packages/kiwicaptcha-verifier/tests/sidecar.rs"
RUST_PARITY_TEST_NEEDLES = [
    "challenge-response-fixtures.json",
    "fn challenge_response_wire_matches_the_golden_fixtures",
]
# Every sidecar client that talks to the sidecar: none of them may
# reference the camelCase wire keys (they parse only the /verify verdict,
# whose shape this gate deliberately does not touch).
SIDECAR_CLIENT_SOURCES = [
    "packages/kiwicaptcha-go/sidecar.go",
    "packages/kiwicaptcha-node/src/sidecar.ts",
    "packages/kiwicaptcha-python-sdk/kiwicaptcha/sidecar.py",
    "packages/kiwicaptcha-jvm/core/src/main/java/com/kiwicaptcha/ExecutionPolicy.java",
    "packages/kiwicaptcha-dotnet/src/KiwiCaptcha/ExecutionPolicy.cs",
    "packages/kiwicaptcha-ruby/lib/kiwicaptcha/sidecar.rb",
    "packages/kiwicaptcha-elixir/lib/kiwicaptcha/sidecar.ex",
]

TYPE_NAMES = {
    str: "string",
    int: "integer",
    float: "decimal",
    bool: "boolean",
    list: "array",
    dict: "object",
    type(None): "null",
}


def json_type(value):  # noqa: ANN201
    for python_type, name in TYPE_NAMES.items():
        if python_type is int and isinstance(value, bool):
            continue  # bool is a subclass of int; keep the two distinct
        if isinstance(value, python_type):
            return name
    return "unknown"


class Failure(Exception):
    pass


def check_fixture() -> None:
    try:
        document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise Failure(f"the fixture is unreadable or not JSON: {error}") from error
    shapes = document.get("shapes")
    if not isinstance(shapes, list) or len(shapes) != len(EXPECTED_SHAPES):
        raise Failure(
            f"the fixture must carry exactly {len(EXPECTED_SHAPES)} challenge-response bodies, "
            f"found {len(shapes) if isinstance(shapes, list) else type(shapes).__name__}"
        )
    seen = set()
    for body in shapes:
        if not isinstance(body, dict):
            raise Failure("every fixture shape must be a JSON object body")
        for key in CAMELCASE_WIRE_KEYS:
            if key in body:
                raise Failure(
                    f"the fixture carries the banned camelCase wire key {key!r}: "
                    "the canonical spelling is snake_case"
                )
        for key, value in body.items():
            if json_type(value) == "unknown":
                raise Failure(f"the fixture key {key!r} has an unrecognized value type")
        body_extras = set(body) - set(COMMON_KEYS)
        matched = None
        for name, (expected_keys, algorithm, extras) in EXPECTED_SHAPES.items():
            if body.get("algorithm") == algorithm and body_extras == extras:
                matched = (name, expected_keys)
                break
        if matched is None:
            raise Failure(
                f"no expected shape matches algorithm={body.get('algorithm')!r} "
                f"extras={sorted(set(body) - set(COMMON_KEYS))}"
            )
        name, expected_keys = matched
        if name in seen:
            raise Failure(f"duplicate fixture shape {name}")
        seen.add(name)
        actual = {key: json_type(value) for key, value in body.items()}
        if actual != expected_keys:
            raise Failure(
                f"the {name} body drifted from the contract: "
                f"expected {expected_keys}, found {actual}"
            )
    if seen != set(EXPECTED_SHAPES):
        raise Failure(f"missing fixture shapes: {sorted(set(EXPECTED_SHAPES) - seen)}")
    if not document.get("$schema", "").startswith("kiwicaptcha.solution-token-v1/"):
        raise Failure("the fixture must carry the solution-token-v1 schema marker")
    print(
        "challenge-response fixture: 4 canonical shapes verified "
        "(plain sha256, plain argon2id, plain rsw, execution-armed)"
    )


def source_texts(path: Path, label: str):  # noqa: ANN201
    """The text of one source file, or of every file under a directory."""
    if path.is_dir():
        for file in sorted(path.rglob("*")):
            if file.is_file() and file.suffix in {".rs", ".php", ".ts", ".js"}:
                yield file, file.read_text(encoding="utf-8", errors="replace")
        return
    try:
        yield path, path.read_text(encoding="utf-8")
    except OSError as error:
        raise Failure(f"{label}: {path} is unreadable: {error}") from error


def check_file_contains(path: Path, needle: str, label: str) -> None:
    for file, text in source_texts(path, label):
        if needle in text:
            return
    raise Failure(
        f"{label}: {path.relative_to(REPO_ROOT)} must reference {needle!r} "
        "(the canonical snake_case wire spelling)"
    )


def check_file_absent(path: Path, needles: tuple[str, ...], label: str) -> None:
    for file, text in source_texts(path, label):
        for needle in needles:
            if needle in text:
                raise Failure(
                    f"{label}: {file.relative_to(REPO_ROOT)} references the banned camelCase "
                    f"wire key {needle!r}; the canonical spelling is snake_case"
                )


def check_parsers() -> None:
    for relative, needle in SNAKE_CASE_PARSED_BY:
        check_file_contains(REPO_ROOT / relative, needle, "challenge parser")
    check_file_absent(
        REPO_ROOT / "packages" / "kiwicaptcha-verifier" / "src",
        CAMELCASE_QUOTED_WIRE_KEYS,
        "sidecar serializer",
    )
    for relative in SIDECAR_CLIENT_SOURCES:
        check_file_absent(REPO_ROOT / relative, CAMELCASE_QUOTED_WIRE_KEYS, "sidecar client")
    for needle in RUST_PARITY_TEST_NEEDLES:
        check_file_contains(REPO_ROOT / RUST_PARITY_TEST, needle, "rust parity harness")
    print("challenge-response parsers: field names match the fixture (snake_case canonical)")


def main() -> int:
    try:
        check_fixture()
        check_parsers()
    except Failure as error:
        print(f"challenge-response parity check FAILED: {error}", file=sys.stderr)
        return 1
    print("challenge-response parity check OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
