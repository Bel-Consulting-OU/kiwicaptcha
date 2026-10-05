# frozen_string_literal: true

require_relative 'helper'

# The RSW time-lock trapdoor against the shared committed pair and the
# PHP-issued golden rsw record: validation gates, the derived base, the
# 512-hex wire form and end-to-end redemption.
class RswTest < Minitest::Test
  include TestSupport

  def trapdoor_pair
    TestSupport.golden_record('rsw')['verify_opts']['rsw']
  end

  def test_the_committed_trapdoor_pair_validates
    trapdoor = KiwiCaptcha::Rsw::Trapdoor.new(trapdoor_pair['modulus_n'], trapdoor_pair['lambda'])
    assert_equal 2048, trapdoor.n.to_s(2).length
    assert trapdoor.lambda.even?
  end

  def test_validation_gates_reject_broken_pairs
    modulus_b64 = trapdoor_pair['modulus_n']
    lambda_b64 = trapdoor_pair['lambda']
    # A non-canonical base64 spelling is refused.
    assert_raises(RangeError) { KiwiCaptcha::Rsw::Trapdoor.new(modulus_b64 + '=', lambda_b64) }
    # A truncated modulus is refused.
    short = [KiwiCaptcha::Base64Utils.decode_std(modulus_b64)[0, 128]].pack('m0')
    assert_raises(RangeError) { KiwiCaptcha::Rsw::Trapdoor.new(short, lambda_b64) }
    # An odd lambda is refused (it cannot be lcm of two minus-one
    # values).
    decoded = KiwiCaptcha::Base64Utils.decode_std(lambda_b64)
    decoded.setbyte(decoded.bytesize - 1, decoded.getbyte(decoded.bytesize - 1) | 1)
    assert_raises(RangeError) { KiwiCaptcha::Rsw::Trapdoor.new(modulus_b64, [decoded].pack('m0')) }
    # A mismatched lambda fails the consistency spot-check.
    other = KiwiCaptcha::Base64Utils.decode_std(lambda_b64)
    other.setbyte(0, other.getbyte(0) ^ 0x02)
    assert_raises(RangeError) { KiwiCaptcha::Rsw::Trapdoor.new(modulus_b64, [other].pack('m0')) }
  end

  def test_the_expected_proof_matches_the_php_issued_token
    row = TestSupport.golden_record('rsw')
    record = TestSupport.record_from_row(row)
    trapdoor = KiwiCaptcha::Rsw::Trapdoor.new(trapdoor_pair['modulus_n'], trapdoor_pair['lambda'])
    expected = trapdoor.expected_proof_hex(record.prefix, record.nonce, record.t)
    token = KiwiCaptcha::Token.decode(row['token_b64'])
    assert_equal 512, expected.length
    assert_equal token.rsw_proof, expected
  end

  def test_fingerprints_and_identity_forms
    modulus_b64 = trapdoor_pair['modulus_n']
    fingerprint = KiwiCaptcha::Rsw.modulus_fingerprint_hex(modulus_b64)
    assert_equal 64, fingerprint.length
    assert KiwiCaptcha::Rsw.identity_matches?(fingerprint, modulus_b64, false)
    legacy = Digest::SHA256.hexdigest(modulus_b64.b)
    refute KiwiCaptcha::Rsw.identity_matches?(legacy, modulus_b64, false)
    assert KiwiCaptcha::Rsw.identity_matches?(legacy, modulus_b64, true)
  end

  def test_the_golden_rsw_record_verifies_end_to_end
    row = TestSupport.golden_record('rsw')
    record = TestSupport.record_from_row(row)
    storage = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
    storage.store(record)
    options = TestSupport.verify_options(
      storage: storage, secret_key: SECRET, expected_scope: 'login',
      rsw: { modulus_n: trapdoor_pair['modulus_n'], lambda: trapdoor_pair['lambda'] },
      **TestSupport.frozen_clock(record)
    )
    result = KiwiCaptcha.verify(row['token_b64'], options)
    assert result.ok, result.code
    assert_equal 'rsw', result.price
  end
end
