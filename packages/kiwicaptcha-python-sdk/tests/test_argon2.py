"""The Argon2id implementation: RFC vectors and C-reference differential
tags, captured once from the reference build."""

import sys
import unittest

sys.path.insert(0, ".")

from kiwicaptcha import argon2


class Rfc9106VectorTest(unittest.TestCase):
    def test_argon2id_vector(self):
        # RFC 9106 section 5.3: the inputs are repeated bytes.
        tag = argon2.derive(
            password=b"\x01" * 32,
            salt=b"\x02" * 16,
            t_cost=3,
            m_cost=32,
            lanes=4,
            out_len=32,
            secret=b"\x03" * 8,
            ad=b"\x04" * 12,
        )
        self.assertEqual(
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
            tag.hex(),
        )


class DifferentialVectorTest(unittest.TestCase):
    """Tags produced by the reference build.

    The inputs match the fixture constants: the password is the
    literal string the sweep pinned, the salt the sixteen rising
    bytes."""

    CASES = {
        (1, 32, 3): "929ea45c6d883a86f284950fd0ed67f72aa687dd6ea22d25b6f833da6d50cf19",
        (1, 64, 3): "381612cb120864032b674082eb0144f821e9395f3f1ca74ab41ce8bd8e328921",
        (1, 128, 4): "7661f1eaee47643ec423cb7018a29aaea546e985e256aec5c88cc68df75fdfdf",
        (1, 256, 1): "a0e96c4b5be13e4c1ca75c71b8f0b54a26aa850a014315c405bf4212cae86d95",
        (2, 32, 3): "017d5cb68c17c85940a49908a52904e248311a0a0d56ad6827723ad5df24ad3d",
        (2, 64, 3): "61c1d3de8b09b930ef0eff624ebb407932ee6d65e4052e591ec79ab57d5397f8",
        (2, 128, 4): "c1cfa0d681bfcbf022043e6cf948bab58868c5c812ed7b8920930d0ba537b772",
        (2, 256, 1): "e88b33a5663804b559aa1ca5ec3e4d96ad0cf597165e2d1347dc9dfacc205d9d",
        (3, 32, 3): "4b8b04eb139f69296d99c24561a308708d01b0c7064914fb07a393474b90b388",
        (3, 64, 3): "3f161325d41c548325c608d8c67ceffcdeac5c88b76b177889ffeabbc6d3f125",
        (3, 128, 4): "a3f01f43ea51ef167e713ab4f31a35adb292a1cc1ef3f73809f69e4e1eb094be",
        (3, 256, 1): "29d826fb3ea732186a3e5ff2e705ae74d7d1ee646bba7d806280f1dbf5b104b3",
        (4, 32, 3): "13aecf7f9d2496db6382d49ab841c0cee84b5fab6d36c294b4c02bb578368eca",
        (4, 64, 3): "28c6c3d4239d0885247fc323c105388825304afa8b14573b42a0fdb428cee98c",
        (4, 128, 4): "827d662123b4142d9b3c918ce78cfaf5141256ff14f907223e64956a42618160",
        (4, 256, 1): "e3e8fb83637bba3475a41d3c8dda7f6c007d92deefef4a20c7dcc588a604d39e",
    }

    def test_differential_tags(self):
        for (lanes, m_cost, t_cost), expected in self.CASES.items():
            tag = argon2.derive(
                b"prefix21", bytes(range(16)), t_cost, m_cost, lanes=lanes
            )
            self.assertEqual(
                expected,
                tag.hex(),
                f"lanes={lanes} m={m_cost} t={t_cost}",
            )

    def test_protocol_profile_matches_libsodium(self):
        # The exact tag PHP sodium_crypto_pwhash produces for the
        # argon2id fixture profile (m_kib=64, t=3, p=1).
        tag = argon2.derive(b"prefix21", bytes(range(16)), 3, 64, lanes=1)
        self.assertEqual(
            "381612cb120864032b674082eb0144f821e9395f3f1ca74ab41ce8bd8e328921",
            tag.hex(),
        )

    def test_parameter_guards(self):
        with self.assertRaises(ValueError):
            argon2.derive(b"x", bytes(16), 0, 64)
        with self.assertRaises(ValueError):
            argon2.derive(b"x", bytes(16), 1, 4)  # < 8 * lanes
        with self.assertRaises(ValueError):
            argon2.derive(b"x", bytes(16), 1, 8, lanes=0)


if __name__ == "__main__":
    unittest.main()
