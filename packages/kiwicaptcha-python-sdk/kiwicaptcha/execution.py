"""Execution challenge program shape parsing.

The ExecutionChallengeV1 wire blob is ``base64`` of a compact program:
format byte, scope, action, op version, op count, then the op records.
This module implements the exact program language accepted by the PHP
``ExecutionChallengeGenerator::decode`` so the record parser and the
verifier can validate a stored program's shape and reject foreign
blobs fail closed.

Out of scope, deliberately: the trace simulator and the trace replay
walker that verify a presented execution digest. See the package
README for the scope statement. A program parsed here can still be
shape validated, and its signed commitment can still be checked against
the stored bytes.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Dict, List, Optional

LABEL = "kiwi-execution-v1"
FORMAT_VERSION = 1
MAX_EXECUTION_VERSION = 5
MIN_OPS = 8
MAX_OPS = 24
MAX_PROGRAM_BASE64 = 4096
OP_COUNT = 45

OP_ADD = 0
OP_SUB = 1
OP_MUL = 2
OP_XOR = 3
OP_AND = 4
OP_OR = 5
OP_SHL = 6
OP_SHR = 7
OP_U8_CREATE = 8
OP_U8_WRITE = 9
OP_U8_READ = 10
OP_U8_ROTATE = 11
OP_STR_LEN = 12
OP_STR_CHARCODE = 13
OP_STR_CODEPOINT = 14
OP_STR_SLICE = 15
OP_DOM_CREATE = 16
OP_DOM_SET_ATTR = 17
OP_DOM_APPEND = 18
OP_DOM_QUERY = 19
OP_DOM_GET_ATTR = 20
OP_DOM_DATASET_SET = 21
OP_DOM_DATASET_GET = 22
OP_DOM_CLASS_ADD = 23
OP_DOM_CLASS_CONTAINS = 24
OP_DOM_PARENT = 25
OP_DOM_DISPATCH = 26
OP_DOM_SERIALIZE = 27
OP_DOM_QUERY_REAL = 28
OP_DOM_GEOMETRY = 29
OP_DOM_POINT = 30
OP_DOM_EVENT_REAL = 31
OP_DOM_SERIALIZE_REAL = 32
OP_DOM_OBSERVE = 33
OP_DOM_SIBLING_INDEX = 34
OP_DOM_CHILD = 35
OP_DOM_DEPTH = 36
OP_DOM_FRAGMENT_APPEND = 37
OP_DOM_CLONE = 38
OP_DOM_REPARENT = 39
OP_DOM_ATTR_REFLECT = 40
OP_DOM_EVENT_PHASE = 41
OP_DOM_URL_CANON = 42
OP_DOM_TEXT_MUTATE = 43
OP_DOM_SELECT_DEP = 44

IDENTIFIER_PATTERN = re.compile(r"\A[A-Za-z0-9._:-]+\Z")

_MAX_OPCODE_BY_VERSION = {1: 33, 2: 34, 3: 35, 4: 37, 5: OP_COUNT}


class _Cursor:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def read(self, n: int) -> Optional[bytes]:
        if self.pos + n > len(self.data):
            return None
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk


def _read_fixed(read: Any, n: int) -> Optional[int]:
    raw = read(n)
    if raw is None:
        return None
    value = 0
    for byte in raw:
        value = (value << 8) | byte
    return value


def _read_string(cur: _Cursor) -> Optional[Dict[str, Any]]:
    length = cur.read(1)
    if length is None:
        return None
    n = length[0]
    if n < 1 or n > 16:
        return None
    s = cur.read(n)
    if s is None:
        return None
    return {"len": n, "s": s}


def _read_id(cur: _Cursor) -> Optional[Dict[str, Any]]:
    length = cur.read(1)
    if length is None:
        return None
    n = length[0]
    if n < 4 or n > 16:
        return None
    s = cur.read(n)
    if s is None:
        return None
    return {"len": n, "s": s}


def _read_id_keyed(cur: _Cursor) -> Optional[Dict[str, Any]]:
    length = cur.read(1)
    if length is None:
        return None
    n = length[0]
    if n < 4 or n > 16:
        return None
    s = cur.read(n)
    if s is None:
        return None
    return {"len": n, "id": s}


def _read_value(cur: _Cursor) -> Optional[Dict[str, Any]]:
    length = cur.read(1)
    if length is None:
        return None
    n = length[0]
    if n < 1 or n > 32:
        return None
    s = cur.read(n)
    if s is None:
        return None
    return {"len": n, "s": s}


def _read_class(cur: _Cursor) -> Optional[Dict[str, Any]]:
    length = cur.read(1)
    if length is None:
        return None
    n = length[0]
    if n < 1 or n > 12:
        return None
    s = cur.read(n)
    if s is None:
        return None
    return {"len": n, "s": s}


def _read_byte(cur: _Cursor) -> Optional[int]:
    raw = cur.read(1)
    if raw is None:
        return None
    return raw[0]


def _read_create(cur: _Cursor) -> Optional[Dict[str, Any]]:
    tag = _read_byte(cur)
    if tag is None:
        return None
    ident = _read_id(cur)
    if ident is None:
        return None
    return {"tag": tag % 4, "id": ident["s"]}


def _read_set_attr(cur: _Cursor) -> Optional[Dict[str, Any]]:
    name = _read_byte(cur)
    if name is None:
        return None
    value = _read_string(cur)
    if value is None:
        return None
    return {"name": name % 5, "val": value["s"]}


def _read_dataset_set(cur: _Cursor) -> Optional[Dict[str, Any]]:
    key_byte = _read_byte(cur)
    if key_byte is None:
        return None
    if key_byte < 1 or key_byte > 16:
        return None
    key = cur.read(key_byte)
    if key is None:
        return None
    value = _read_value(cur)
    if value is None:
        return None
    return {"s": key, "val": value["s"]}


def _read_string_with_byte(cur: _Cursor) -> Optional[Dict[str, Any]]:
    value = _read_string(cur)
    if value is None:
        return None
    tail = cur.read(1)
    if tail is None:
        return None
    return {"len": value["len"], "s": value["s"], "idx": tail[0]}


def _read_string_with_bytes(cur: _Cursor) -> Optional[Dict[str, Any]]:
    value = _read_string(cur)
    if value is None:
        return None
    tail = cur.read(2)
    if tail is None:
        return None
    start = tail[0] % (value["len"] + 1)
    count = tail[1] % 32
    return {"len": value["len"], "s": value["s"], "start": start, "count": count}


def _read_u32_pair(cur: _Cursor) -> Optional[Dict[str, Any]]:
    a = _read_fixed(cur.read, 4)
    b = _read_fixed(cur.read, 4)
    if a is None or b is None:
        return None
    return {"a": a, "b": b}


def _read_u8_create(cur: _Cursor) -> Optional[Dict[str, Any]]:
    length = _read_byte(cur)
    if length is None:
        return None
    return {"len": 8 + (length % 57)}


def _read_observe(cur: _Cursor) -> Optional[Dict[str, Any]]:
    ident = _read_id_keyed(cur)
    if ident is None:
        return None
    idx = _read_byte(cur)
    if idx is None:
        return None
    return {"id": ident["id"], "idx": idx % 64}


def _read_child(cur: _Cursor) -> Optional[Dict[str, Any]]:
    tag = _read_byte(cur)
    if tag is None:
        return None
    ident = _read_id_keyed(cur)
    if ident is None:
        return None
    return {"tag": tag % 4, "id": ident["id"]}


def _read_id_cell(cur: _Cursor) -> Optional[Dict[str, Any]]:
    ident = _read_id_keyed(cur)
    if ident is None:
        return None
    cell = _read_byte(cur)
    if cell is None:
        return None
    return {"id": ident["id"], "cell": cell % 64}


def _read_frag_append(cur: _Cursor) -> Optional[Dict[str, Any]]:
    slot = _read_byte(cur)
    if slot is None:
        return None
    cell = _read_byte(cur)
    if cell is None:
        return None
    return {"s": slot % 4, "cell": cell % 64}


def _read_text_mutate(cur: _Cursor) -> Optional[Dict[str, Any]]:
    value = _read_value(cur)
    if value is None:
        return None
    cell = _read_byte(cur)
    if cell is None:
        return None
    return {"val": value["s"], "cell": cell % 64}


def _read_operands(cur: _Cursor, opcode: int) -> Optional[Dict[str, Any]]:
    if opcode in (OP_ADD, OP_SUB, OP_MUL, OP_XOR, OP_AND, OP_OR, OP_SHL, OP_SHR):
        return _read_u32_pair(cur)
    if opcode == OP_U8_CREATE:
        return _read_u8_create(cur)
    if opcode == OP_U8_WRITE:
        idx = _read_byte(cur)
        val = _read_byte(cur)
        return {"idx": (idx if idx is not None else 0) % 64,
                "val": val if val is not None else 0}
    if opcode == OP_U8_READ:
        idx = _read_byte(cur)
        return {"idx": (idx if idx is not None else 0) % 64}
    if opcode == OP_U8_ROTATE:
        k = _read_byte(cur)
        return {"k": (k if k is not None else 0) % 8}
    if opcode == OP_STR_LEN:
        return _read_string(cur)
    if opcode in (OP_STR_CHARCODE, OP_STR_CODEPOINT):
        return _read_string_with_byte(cur)
    if opcode == OP_STR_SLICE:
        return _read_string_with_bytes(cur)
    if opcode == OP_DOM_CREATE:
        return _read_create(cur)
    if opcode == OP_DOM_SET_ATTR:
        return _read_set_attr(cur)
    if opcode == OP_DOM_QUERY:
        return _read_id(cur)
    if opcode == OP_DOM_GET_ATTR:
        name = _read_byte(cur)
        return {"name": (name if name is not None else 0) % 5}
    if opcode == OP_DOM_DATASET_SET:
        return _read_dataset_set(cur)
    if opcode == OP_DOM_DATASET_GET:
        return _read_string(cur)
    if opcode in (OP_DOM_CLASS_ADD, OP_DOM_CLASS_CONTAINS):
        return _read_class(cur)
    if opcode in (OP_DOM_APPEND, OP_DOM_PARENT, OP_DOM_DISPATCH,
                  OP_DOM_SERIALIZE, OP_DOM_SERIALIZE_REAL):
        return {}
    if opcode in (OP_DOM_QUERY_REAL, OP_DOM_GEOMETRY, OP_DOM_EVENT_REAL,
                  OP_DOM_SIBLING_INDEX, OP_DOM_DEPTH):
        return _read_id_keyed(cur)
    if opcode == OP_DOM_POINT:
        x = _read_byte(cur)
        y = _read_byte(cur)
        return {"x": (x if x is not None else 0) % 256, "y": (y if y is not None else 0) % 256}
    if opcode == OP_DOM_OBSERVE:
        return _read_observe(cur)
    if opcode == OP_DOM_CHILD:
        return _read_child(cur)
    if opcode in (OP_DOM_CLONE, OP_DOM_REPARENT):
        return _read_id_cell(cur)
    if opcode == OP_DOM_FRAGMENT_APPEND:
        return _read_frag_append(cur)
    if opcode == OP_DOM_ATTR_REFLECT:
        name = _read_byte(cur)
        return {"name": (name if name is not None else 0) % 5}
    if opcode == OP_DOM_EVENT_PHASE:
        cell = _read_byte(cur)
        return {"cell": (cell if cell is not None else 0) % 64}
    if opcode == OP_DOM_URL_CANON:
        return {}
    if opcode == OP_DOM_TEXT_MUTATE:
        return _read_text_mutate(cur)
    if opcode == OP_DOM_SELECT_DEP:
        b0 = _read_byte(cur)
        b1 = _read_byte(cur)
        b2 = _read_byte(cur)
        return {"b0": b0 if b0 is not None else 0,
                "b1": b1 if b1 is not None else 0,
                "b2": b2 if b2 is not None else 0}
    return None


def decode_program(program_b64: str) -> Optional[Dict[str, Any]]:
    """Parse a program blob; return None for anything outside the language.

    The parse is exact: a valid prefix with trailing bytes is rejected,
    every version bounds its own opcode space, and the identifiers
    follow the narrow deployment alphabet.
    """
    if not isinstance(program_b64, str) or len(program_b64) > MAX_PROGRAM_BASE64:
        return None
    try:
        decoded = base64.b64decode(program_b64.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None
    if base64.b64encode(decoded).decode("ascii") != program_b64:
        return None
    cur = _Cursor(decoded)

    header = cur.read(1)
    if header is None or header[0] != FORMAT_VERSION:
        return None
    scope_len = cur.read(1)
    if scope_len is None:
        return None
    scope_raw = cur.read(scope_len[0])
    if scope_raw is None or scope_raw == b"" or len(scope_raw) > 128:
        return None
    scope = scope_raw.decode("latin-1")
    if not IDENTIFIER_PATTERN.match(scope):
        return None
    action_len = cur.read(1)
    if action_len is None:
        return None
    action_raw = cur.read(action_len[0])
    if action_raw is None or action_raw == b"" or len(action_raw) > 32:
        return None
    action = action_raw.decode("latin-1")
    if not IDENTIFIER_PATTERN.match(action):
        return None
    op_version_raw = cur.read(1)
    if op_version_raw is None:
        return None
    op_version = op_version_raw[0]
    if op_version < 1 or op_version > MAX_EXECUTION_VERSION:
        return None
    op_count_raw = cur.read(1)
    if op_count_raw is None:
        return None
    op_count = op_count_raw[0]
    if op_count < MIN_OPS or op_count > MAX_OPS:
        return None

    max_opcode = _MAX_OPCODE_BY_VERSION[op_version]
    ops: List[Dict[str, Any]] = []
    for _ in range(op_count):
        opcode_raw = cur.read(1)
        if opcode_raw is None:
            return None
        opcode = opcode_raw[0]
        if opcode >= max_opcode:
            return None
        operands = _read_operands(cur, opcode)
        if operands is None:
            return None
        ops.append({"op": opcode, "operands": operands})

    if cur.pos != len(decoded):
        return None

    return {
        "format": FORMAT_VERSION,
        "scope": scope,
        "action": action,
        "op_version": op_version,
        "ops": ops,
    }


def is_valid_program(program_b64: str) -> bool:
    """True when the blob is inside the protocol program language."""
    return decode_program(program_b64) is not None


def execution_commitment(program_b64: str) -> str:
    """The signed commitment of a program: hex sha256 of the wire string."""
    import hashlib

    return hashlib.sha256(program_b64.encode("utf-8")).hexdigest()
