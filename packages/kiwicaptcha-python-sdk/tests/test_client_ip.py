"""The shared client-IP test vectors, asserted against the Python
resolver. Every SDK surfaces the same scenarios from
tools/client-ip/test-vectors.json, so one request resolves to one
canonical IP everywhere."""

import json
import os
import sys
import unittest

sys.path.insert(0, ".")

from kiwicaptcha.clientip import canonical_ip, ip_in_trusted, resolve_client_ip

VECTORS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "..",
    "tools",
    "client-ip",
    "test-vectors.json",
)


def load_vectors():
    with open(VECTORS, encoding="utf-8") as handle:
        return json.load(handle)


class ClientIpVectorTest(unittest.TestCase):
    def test_cidr_cases(self):
        data = load_vectors()
        for case in data["cidr_cases"]:
            self.assertEqual(
                ip_in_trusted(case["ip"], [case["cidr"]]),
                case["matches"],
                f"cidr case {case['cidr']} vs {case['ip']}",
            )

    def test_scenarios(self):
        data = load_vectors()
        for scenario in data["scenarios"]:
            xff_lines = scenario.get("xff_lines")
            # The Python platforms merge repeated header lines into one
            # comma-joined value, so the resolver sees the merged chain.
            xff = ",".join(xff_lines) if xff_lines is not None else None
            resolved = resolve_client_ip(
                scenario["peer"], xff, scenario.get("real_ip"), scenario["trusted"]
            )
            expected = scenario.get(
                "expected_merged", scenario["expected"]
            ) if scenario.get("duplicate_detection") else scenario["expected"]
            self.assertEqual(
                resolved,
                expected,
                f"scenario {scenario['id']}",
            )

    def test_canonical_ip_edges(self):
        self.assertIsNone(canonical_ip(""))
        self.assertIsNone(canonical_ip("unknown"))
        self.assertIsNone(canonical_ip("_obfuscated"))
        self.assertIsNone(canonical_ip("[2001:db8::1]:notaport"))
        self.assertIsNone(canonical_ip("[2001:db8::1]garbage"))
        self.assertIsNone(canonical_ip("1.2.3.4:0"))
        self.assertEqual(canonical_ip(" 192.0.2.10:4711 "), "192.0.2.10")
        self.assertEqual(canonical_ip("[2001:DB8::1]"), "2001:db8::1")
        self.assertEqual(canonical_ip("::ffff:198.51.100.5"), "198.51.100.5")
        self.assertIsNone(canonical_ip("1.2.3.4.5"))
        self.assertIsNone(canonical_ip("0:1.2.3.4"))


if __name__ == "__main__":
    unittest.main()
