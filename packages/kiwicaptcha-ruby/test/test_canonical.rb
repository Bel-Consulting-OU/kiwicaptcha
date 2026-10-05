# frozen_string_literal: true

require_relative 'helper'

# The crypto seams against the shared vectors: the HKDF purpose keys,
# the canonical payload spellings and signatures, the server-state MAC
# inputs, the canonical IP family and the binding tags, all pinned
# byte-exact by the committed fixtures.
class CanonicalTest < Minitest::Test
  include TestSupport

  def test_hkdf_purpose_keys_match_the_shared_vector
    hkdf = TestSupport.golden['hkdf']
    derived = KiwiCaptcha::Keys.derived_keys(SECRET)
    assert_equal hkdf['challenge_hex'], derived.challenge_key.unpack1('H*')
    assert_equal hkdf['ip_bind_hex'], derived.ip_bind_key.unpack1('H*')
    assert_equal hkdf['result_hex'], derived.result_key.unpack1('H*')
    assert_equal hkdf['server_state_hex'], derived.server_state_key.unpack1('H*')
  end

  def test_a_short_secret_is_refused
    assert_raises(RangeError) { KiwiCaptcha::Keys.derived_keys('too short') }
  end

  def test_canonical_payload_spellings_match_the_committed_vectors
    canonical = TestSupport.golden['canonical']
    args = KiwiCaptcha::Canonical::CanonicalArgs.new(
      protocol_version: 2, nonce: 'bm9uY2UtcmV2aXNpb24tMy10ZXN0LXZlY3Rvcg==', scope: 'login',
      binding_tag: 'tag456', issued_at: 111, expires_at: 222, algorithm: 'sha256',
      m_kib: 0, t: 1, p: 1, target_bits: 8, salt: 'c2FsdC1yZXZpc2lvbi0z', min_duration_ms: 5,
      region: 'eu', policy_version: 2, request_binding: 'bind-1', issuer: 'prod', kid: 3
    )
    assert_equal canonical['base'], KiwiCaptcha::Canonical.canonical_payload(args)

    # The armed variants travel at their own protocol version with the
    # region unbound, policy 1, and no binding or issuer.
    base_variant = lambda { |version|
      variant = args.dup
      variant.protocol_version = version
      variant.region = nil
      variant.policy_version = 1
      variant.request_binding = nil
      variant.issuer = nil
      variant.kid = 1
      variant
    }
    decoy = base_variant.call(3)
    decoy.decoy_field = 'billing_address_line_a3f9c21d8e5b7401'
    assert_equal canonical['v3_decoy'], KiwiCaptcha::Canonical.canonical_payload(decoy)

    execution = base_variant.call(4)
    execution.execution_version = 1
    execution.execution_commitment = 'a' * 64
    assert_equal canonical['v4_execution'], KiwiCaptcha::Canonical.canonical_payload(execution)

    identity = base_variant.call(5)
    identity.rsw_modulus_sha256 = 'b' * 64
    assert_equal canonical['v5_identity'], KiwiCaptcha::Canonical.canonical_payload(identity)
  end

  def test_signature_versions_match_the_committed_vector
    canonical = TestSupport.golden['canonical']
    signature = KiwiCaptcha::Canonical.sign_payload_v2(canonical['base'], SECRET)
    assert_equal canonical['signature_hex'], signature
  end

  def test_server_state_mac_inputs_match_the_committed_vectors
    vectors = TestSupport.golden['server_state_mac']
    key = [vectors['key_hex']].pack('H*')
    # The fixture input is authoritative; rebuild each field from it
    # and pin the MAC byte-exact.
    meta_input = vectors['record_meta_input']
    lines = meta_input.split("\n")
    challenge = lines[1].split(':', 2).last
    issued_at_ns = Integer(lines[2], 10)
    hostname = lines[3] == '0' ? nil : lines[3].sub(/\A1:\d+:/, '')
    rebuilt = KiwiCaptcha::Mac.record_meta_input(challenge, issued_at_ns, hostname)
    assert_equal meta_input, rebuilt
    assert_equal vectors['record_meta_hex'], KiwiCaptcha::Mac.record_meta_mac(key, challenge, issued_at_ns, hostname)

    result_input = vectors['consumed_result_input']
    result_lines = result_input.split("\n")
    result_challenge = result_lines[1].split(':', 2).last
    valid = result_lines[2] == '1'
    binding_part = result_lines[3] == '0' ? nil : result_lines[3].sub(/\A1:\d+:/, '')
    identity_part = result_lines[4] == '0' ? nil : result_lines[4].sub(/\A1:\d+:/, '')
    rebuilt = KiwiCaptcha::Mac.consumed_result_input(result_challenge, valid, binding_part, identity_part)
    assert_equal result_input, rebuilt
    assert_equal vectors['consumed_result_hex'], KiwiCaptcha::Mac.consumed_result_mac(key, result_challenge, valid, binding_part, identity_part)
  end

  def test_m_marker_parse
    record = TestSupport.record_from_row(TestSupport.golden_record('sha_plain'))
    assert KiwiCaptcha::Canonical.signed_canonical_commits_record_meta(record.challenge)
    plain_v2 = 'v4|2|'.b
    bare = [plain_v2].pack('m0') + '.' + ('a' * 64)
    refute KiwiCaptcha::Canonical.signed_canonical_commits_record_meta(bare)
  end

  def test_canonical_ip_family_normalizes_mapped_spellings
    assert_equal [4].pack('C') + [203, 0, 113, 7].pack('C4'),
                 KiwiCaptcha::Canonical.canonical_ip_family('203.0.113.7')
    loopback = KiwiCaptcha::Canonical.canonical_ip_family('::1')
    assert_equal 6, loopback.getbyte(0)
    assert_equal [0, 0, 0, 1], 4.times.map { |i| loopback.getbyte(13 + i) }
    mapped = KiwiCaptcha::Canonical.canonical_ip_family('::ffff:203.0.113.7')
    assert_equal [4].pack('C') + [203, 0, 113, 7].pack('C4'), mapped
    assert_equal [4].pack('C') + [203, 0, 113, 7].pack('C4'),
                 KiwiCaptcha::Canonical.canonical_ip_family('::203.0.113.7')
    v6 = KiwiCaptcha::Canonical.canonical_ip_family('2001:db8::1')
    assert_equal 6, v6.getbyte(0)
    assert_equal 17, v6.bytesize
    assert_nil KiwiCaptcha::Canonical.canonical_ip_family('999.1.1.1')
    assert_nil KiwiCaptcha::Canonical.canonical_ip_family('01.2.3.4')
    assert_nil KiwiCaptcha::Canonical.canonical_ip_family('2001::db8::1')
  end

  def test_binding_tag_is_deterministic_and_v1_hash_differs
    tag = KiwiCaptcha::Canonical.binding_tag('bm9uY2U=', CLIENT_IP, SECRET)
    assert_equal tag, KiwiCaptcha::Canonical.binding_tag('bm9uY2U=', CLIENT_IP, SECRET)
    assert_raises(RangeError) { KiwiCaptcha::Canonical.binding_tag('bm9uY2U=', 'not-an-ip', SECRET) }
    v1 = KiwiCaptcha::Canonical.hash_ip(CLIENT_IP, SECRET)
    assert_equal IP_HASH, v1
  end

  def test_timing_safe_equals
    assert KiwiCaptcha::Mac.timing_safe_equals('abc', 'abc')
    refute KiwiCaptcha::Mac.timing_safe_equals('abc', 'abd')
    refute KiwiCaptcha::Mac.timing_safe_equals('abc', 'abcd')
  end

  def test_sha256_pow_derivation
    salt_bytes = KiwiCaptcha::Base64Utils.decode_std(TestSupport::SHA_VECTOR['salt'])
    hash = KiwiCaptcha::Pow.derive_sha256_hash(TestSupport::SHA_VECTOR['prefix'], 158, salt_bytes)
    assert KiwiCaptcha::Pow.meets_target?(hash, 8)
    refute KiwiCaptcha::Pow.meets_target?(hash, 20)
    counter = KiwiCaptcha::Pow.solve_sha256(TestSupport::SHA_VECTOR['prefix'], TestSupport::SHA_VECTOR['salt'], 8)
    assert_equal 158, counter
  end
end
