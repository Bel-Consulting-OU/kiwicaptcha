"""The execution program grammar, pinned against the shared corpus at
protocol/execution-v1.json: the version-6 opcode space and the five
real-platform probe operand shapes."""

import base64
import json
import os
import sys
import unittest

sys.path.insert(0, ".")

from tests.support import PROTOCOL_DIR

from kiwicaptcha import execution


def build_program(op_version: int, ops) -> str:
    body = bytearray()
    body.append(execution.FORMAT_VERSION)
    body.append(5)
    body.extend(b"login")
    body.append(3)
    body.extend(b"act")
    body.append(op_version)
    body.append(len(ops))
    for opcode, operand_bytes in ops:
        body.append(opcode)
        body.extend(operand_bytes)
    return base64.b64encode(bytes(body)).decode("ascii")


def probe_id(n: int = 4) -> bytes:
    return bytes([n]) + b"abcd"[:n]


class ExecutionCorpusParityTest(unittest.TestCase):
    def test_opcode_space_matches_the_shared_corpus(self):
        path = os.path.join(PROTOCOL_DIR, "execution-v1.json")
        with open(path, "r", encoding="utf-8") as handle:
            corpus = json.load(handle)
        self.assertEqual(corpus["max_execution_version"], execution.MAX_EXECUTION_VERSION)
        self.assertEqual(corpus["opcode_count"], execution.OP_COUNT)
        self.assertEqual(corpus["opcode_count"], len(corpus["opcodes"]))


class VersionSixGrammarTest(unittest.TestCase):
    def test_version_one_program_still_parses(self):
        ops = [(execution.OP_ADD, (1).to_bytes(4, "little") + (1).to_bytes(4, "little"))] * 8
        self.assertTrue(execution.is_valid_program(build_program(1, ops)))

    def test_version_six_probe_operands_parse(self):
        ops = [
            (execution.OP_CSS_GEOM, probe_id() + bytes([7, 3])),
            (execution.OP_MUT_ORDER, probe_id() + bytes([1, 2, 5])),
            (execution.OP_EV_PHASE_FULL, probe_id() + bytes([9])),
            (execution.OP_RANGE_ORDER, probe_id() + bytes([4, 5, 6])),
            (execution.OP_INT_OBS, probe_id() + bytes([8, 1])),
            (execution.OP_ADD, (1).to_bytes(4, "little") + (1).to_bytes(4, "little")),
            (execution.OP_ADD, (1).to_bytes(4, "little") + (1).to_bytes(4, "little")),
            (execution.OP_ADD, (1).to_bytes(4, "little") + (1).to_bytes(4, "little")),
        ]
        program = build_program(6, ops)
        decoded = execution.decode_program(program)
        self.assertIsNotNone(decoded)
        self.assertEqual(6, decoded["op_version"])
        css = decoded["ops"][0]["operands"]
        self.assertEqual(7, css["seed"])
        self.assertEqual(3, css["cell"])
        mut = decoded["ops"][1]["operands"]
        self.assertEqual((1, 2, 5), (mut["b0"], mut["b1"], mut["cell"]))
        self.assertEqual(9, decoded["ops"][2]["operands"]["cell"])
        self.assertEqual(8, decoded["ops"][4]["operands"]["seed"])

    def test_version_five_refuses_the_version_six_opcodes(self):
        ops = [
            (execution.OP_CSS_GEOM, probe_id() + bytes([7, 3])),
            (execution.OP_ADD, (1).to_bytes(4, "little") + (1).to_bytes(4, "little")),
        ] * 4
        self.assertIsNone(execution.decode_program(build_program(5, ops[:8])))
        self.assertTrue(execution.is_valid_program(build_program(6, ops[:8])))

    def test_version_six_rejects_out_of_grammar_opcodes(self):
        ops = [(execution.OP_COUNT, b"")] * 8
        self.assertIsNone(execution.decode_program(build_program(6, ops)))

    def test_set_attr_accepts_value_widths_through_32(self):
        # The php/Rust reader pairs the name byte with a value operand
        # (1..32 bytes), not a string operand (1..16): a 17..32 byte
        # attribute value must parse.
        for value_len in (1, 16, 17, 32):
            operand = bytes([2]) + bytes([value_len]) + b"v" * value_len
            ops = [(execution.OP_DOM_SET_ATTR, operand)] * 8
            self.assertTrue(
                execution.is_valid_program(build_program(1, ops)),
                f"value length {value_len} must parse",
            )
        too_long = bytes([2, 33]) + b"v" * 33
        self.assertIsNone(
            execution.decode_program(build_program(1, [(execution.OP_DOM_SET_ATTR, too_long)] * 8))
        )

    def test_truncated_probe_operands_reject(self):
        ops = [
            (execution.OP_CSS_GEOM, probe_id()),  # missing seed + cell
            (execution.OP_ADD, (1).to_bytes(4, "little") + (1).to_bytes(4, "little")),
        ] * 4
        self.assertIsNone(execution.decode_program(build_program(6, ops[:8])))


if __name__ == "__main__":
    unittest.main()
