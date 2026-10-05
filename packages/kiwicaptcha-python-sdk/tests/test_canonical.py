"""Canonical assembly, HMAC signatures, the server-state MACs and the
IP binding derivations, pinned against the shared corpus."""

import base64
import hashlib
import hmac
import sys
import unittest

sys.path.insert(0, ".")

from tests.support import (
    CLIENT_IP,
    IP_HASH,
    ISSUED_AT,
    SECRET,
    SHA_VECTOR,
)

from kiwicaptcha.canonical import (
    ServerStateMac,
    binding_tag,
    canonical_ip_family,
    canonical_payload,
    constant_time_equals,
    hash_ip_v1,
    leading_zero_bits,
    sign_payload_v1,
    sign_payload_v2,
    signed_canonical_commits_record_meta,
    verify_record_signature,
)
from kiwicaptcha.keys import DerivedKeys, hkdf_sha256
from kiwicaptcha.records import ChallengeRecord


class CanonicalAssemblyTest(unittest.TestCase):
    def test_v2_plain_canonical_field_order(self):
        payload = canonical_payload(
            2, "NONCE", "login", "TAG", 111, 222, "sha256",
            0, 1, 1, 8, "SALT", 0,
        )
        self.assertEqual(
            "v4|2|NONCE|login|TAG|111|222|sha256|0|1|1|8|SALT|0||1|||1",
            payload,
        )

    def test_tagged_segments_append_last(self):
        payload = canonical_payload(
            4, "NONCE", "login", "TAG", 111, 222, "sha256",
            0, 1, 1, 8, "SALT", 0,
            region="eu", policy_version=3, request_binding="tx",
            issuer="prod", kid=7, decoy_field="hp",
            execution_version=1, execution_commitment="c" * 64,
            rsw_modulus_sha256="a" * 64,
            server_mac_committed=True,
        )
        self.assertTrue(payload.endswith(
            "|d=hp|e=1," + "c" * 64 + "|r=" + "a" * 64 + "|m=1"
        ))

    def test_partial_execution_pair_refused(self):
        with self.assertRaises(ValueError):
            canonical_payload(
                4, "NONCE", "login", "TAG", 111, 222, "sha256",
                0, 1, 1, 8, "SALT", 0, execution_version=1,
            )

    def test_vector_challenge_payload_decodes_to_legacy_canonical(self):
        payload_b64, signature = SHA_VECTOR["challenge"].rsplit(".", 1)
        payload = base64.b64decode(payload_b64).decode("ascii")
        self.assertEqual(
            "%s|login|%s|%d" % (SHA_VECTOR["nonce"], IP_HASH, ISSUED_AT),
            payload,
        )
        expected = hmac.new(
            SECRET.encode("ascii"), payload.encode("ascii"), hashlib.sha256
        ).hexdigest()
        self.assertEqual(expected, signature)
        self.assertTrue(
            constant_time_equals(expected, signature),
        )

    def test_signed_canonical_commits_record_meta(self):
        from tests.support import minimal_program_b64

        plain_payload = canonical_payload(
            2, "NONCE", "login", "", 1, 2, "sha256", 0, 1, 1, 8, "SALT", 0,
        )
        self.assertFalse(
            signed_canonical_commits_record_meta(
                base64.b64encode(plain_payload.encode()).decode() + ".ff"
            )
        )
        mac_payload = canonical_payload(
            2, "NONCE", "login", "", 1, 2, "sha256", 0, 1, 1, 8, "SALT", 0,
            server_mac_committed=True,
        )
        self.assertTrue(
            signed_canonical_commits_record_meta(
                base64.b64encode(mac_payload.encode()).decode() + ".ff"
            )
        )
        # Not the wire form at all: no marker.
        self.assertFalse(signed_canonical_commits_record_meta("v4|junk"))


class IpBindingTest(unittest.TestCase):
    def test_v1_hash_matches_vector(self):
        self.assertEqual(IP_HASH, hash_ip_v1(CLIENT_IP, SECRET))

    def test_v2_binding_tag_is_nonce_bound(self):
        tag_a = binding_tag("NONCEA", CLIENT_IP, SECRET, None)
        tag_b = binding_tag("NONCEB", CLIENT_IP, SECRET, None)
        self.assertEqual(64, len(tag_a))
        self.assertNotEqual(tag_a, tag_b)
        # Tenant separation: the same inputs under another tenant differ.
        tag_tenant = binding_tag("NONCEA", CLIENT_IP, SECRET, "tenant-x")
        self.assertNotEqual(tag_a, tag_tenant)

    def test_canonical_ip_family(self):
        v4 = canonical_ip_family("203.0.113.7")
        self.assertEqual(b"\x04", v4[:1])
        self.assertEqual(5, len(v4))
        v6 = canonical_ip_family("2001:db8::1")
        self.assertEqual(b"\x06", v6[:1])
        self.assertEqual(17, len(v6))
        # IPv4-mapped IPv6 folds to the IPv4 family.
        mapped = canonical_ip_family("::ffff:203.0.113.7")
        self.assertEqual(v4, mapped)
        with self.assertRaises(ValueError):
            canonical_ip_family("not-an-ip")
        with self.assertRaises(ValueError):
            canonical_ip_family("")


class ServerStateMacTest(unittest.TestCase):
    def test_record_meta_round_trip(self):
        key = ServerStateMac.key(SECRET, None)
        mac = ServerStateMac.record_meta(key, "CHALLENGE", 123, "host-1")
        record = ChallengeRecord(
            nonce="NONCE", scope="login", binding_tag="", issued_at=1,
            expires_at=2, algorithm="sha256", m_kib=0, t=1, p=1,
            target_bits=8, salt="SALT", prefix="P", challenge="CHALLENGE",
            min_duration_ms=0, issued_at_ns=123, hostname="host-1",
            server_mac=mac,
        )
        self.assertTrue(ServerStateMac.verify_record_meta(key, record))
        record.hostname = "host-2"
        self.assertFalse(ServerStateMac.verify_record_meta(key, record))

    def test_consumed_result_round_trip(self):
        key = ServerStateMac.key(SECRET, None)

        class Consumed:
            pass

        consumed = Consumed()
        consumed.record = ChallengeRecord(
            nonce="NONCE", scope="login", binding_tag="", issued_at=1,
            expires_at=2, algorithm="sha256", m_kib=0, t=1, p=1,
            target_bits=8, salt="SALT", prefix="P", challenge="CHALLENGE",
            min_duration_ms=0,
        )
        consumed.operation_identity = "order-1"
        mac = ServerStateMac.consumed_result(
            key, "CHALLENGE", True, "tx-1", "order-1"
        )

        class Result:
            pass

        result = Result()
        result.valid = True
        result.binding = "tx-1"
        result.mac = mac
        consumed.consumed_result = result
        self.assertTrue(ServerStateMac.verify_consumed_result(key, consumed))
        result.binding = "tx-2"
        self.assertFalse(ServerStateMac.verify_consumed_result(key, consumed))

    def test_tenant_key_separation(self):
        self.assertNotEqual(
            ServerStateMac.key(SECRET, "a"), ServerStateMac.key(SECRET, "b")
        )


class SignatureVerifyTest(unittest.TestCase):
    def test_v1_record_signature(self):
        from tests.support import mint_v2_record

        record = mint_v2_record(protocol_version=1, binding_ip=CLIENT_IP)
        self.assertTrue(verify_record_signature(record, SECRET, None))
        self.assertFalse(verify_record_signature(record, "k" * 32, None))

    def test_v2_tampered_field_fails(self):
        from tests.support import mint_v2_record

        record = mint_v2_record()
        self.assertTrue(verify_record_signature(record, SECRET, None))
        record.target_bits = 20
        self.assertFalse(verify_record_signature(record, SECRET, None))

    def test_mac_marker_enforced(self):
        from tests.support import mint_v2_record

        record = mint_v2_record(mint_meta_mac=True)
        self.assertTrue(verify_record_signature(record, SECRET, None))
        # Stripping the MAC breaks the signature: the signed m=1 marker
        # demands a valid MAC.
        record.server_mac = None
        self.assertFalse(verify_record_signature(record, SECRET, None))
        # Forging a MAC without the marker fails too.
        record2 = mint_v2_record()
        record2.server_mac = "ab" * 32
        self.assertFalse(verify_record_signature(record2, SECRET, None))


class DerivedKeysTest(unittest.TestCase):
    def test_rfc5863_case1(self):
        # The RFC 5863 HKDF test case 1 with the sha256 hash.
        ikm = b"\x0b" * 22
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        okm = hkdf_sha256(ikm, info, salt, 42)
        self.assertEqual(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865",
            okm.hex(),
        )

    def test_purpose_key_separation(self):
        keys = DerivedKeys.from_master(SECRET, None)
        keys_tenant = DerivedKeys.from_master(SECRET, "tenant")
        self.assertNotEqual(keys.challenge_key, keys_tenant.challenge_key)
        self.assertNotEqual(keys.challenge_key, keys.ip_bind_key)
        self.assertNotEqual(keys.result_key, keys.server_state_key)
        # Short master secrets are refused.
        with self.assertRaises(ValueError):
            DerivedKeys.from_master("short", None)

    def test_memoized_identical(self):
        a = DerivedKeys.from_master(SECRET, None)
        b = DerivedKeys.from_master(SECRET, None)
        self.assertIs(a, b)


if __name__ == "__main__":
    unittest.main()
