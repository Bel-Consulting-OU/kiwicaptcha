# frozen_string_literal: true

require_relative 'helper'

# The solution token codec against the shared boundary fixture: the
# solver hash ceiling and the exact counter spellings both decoders
# must accept or reject, plus the full decode error surface.
class TokenTest < Minitest::Test
  include TestSupport

  def test_the_shared_fixture_acceptance_split
    fixtures = TestSupport.protocol('solution-token-v1/fixtures.json')
    assert_equal 20_000_000, KiwiCaptcha::Pow::SOLVER_MAX_HASHES
    fixtures['accepted'].each do |counter, encoded|
      token = KiwiCaptcha::Token.decode(encoded)
      assert_equal Integer(counter), token.counter
      assert_equal encoded, token.encode
    end
    fixtures['rejected'].each do |_counter, encoded|
      assert_raises(KiwiCaptcha::DecodeError) { KiwiCaptcha::Token.decode(encoded) }
    end
    cross = fixtures['cross_language']
    token = KiwiCaptcha::Token.decode(cross['encoded'])
    assert_equal cross['counter'], token.counter
    assert_equal cross['encoded'], token.encode
  end

  def test_round_trip_of_a_full_token
    token = KiwiCaptcha::Token::SolutionToken.new(
      nonce: 'A' * 43 + '=',
      counter: 42,
      duration_ms: 1200,
      telemetry: { 'v' => 1, 'et' => [1, 2, 3] },
      execution_digest: nil,
      execution_trace: nil,
      rsw_proof: nil
    )
    encoded = token.encode
    decoded = KiwiCaptcha::Token.decode(encoded)
    assert_equal token.nonce, decoded.nonce
    assert_equal token.counter, decoded.counter
    assert_equal token.duration_ms, decoded.duration_ms
    assert_equal({ 'v' => 1, 'et' => [1, 2, 3] }, decoded.telemetry)
    assert_nil decoded.execution_digest
    assert_nil decoded.rsw_proof
  end

  def test_execution_and_rsw_segments_ride_the_wire
    nonce = 'A' * 43 + '='
    digest = 'a' * 64
    trace = KiwiCaptcha::Base64Utils.encode_url('entry1;entry2')
    token = KiwiCaptcha::Token::SolutionToken.new(
      nonce: nonce, counter: 7, duration_ms: 10, telemetry: {},
      execution_digest: digest, execution_trace: trace, rsw_proof: nil
    )
    decoded = KiwiCaptcha::Token.decode(token.encode)
    assert_equal digest, decoded.execution_digest
    assert_equal trace, decoded.execution_trace

    proof = 'b' * 512
    token = KiwiCaptcha::Token::SolutionToken.new(
      nonce: nonce, counter: 0, duration_ms: 10, telemetry: {},
      execution_digest: nil, execution_trace: nil, rsw_proof: proof
    )
    decoded = KiwiCaptcha::Token.decode(token.encode)
    assert_equal proof, decoded.rsw_proof
  end

  def test_every_decode_failure_carries_its_code
    nonce = 'A' * 43 + '='
    cases = [
      [:invalid_base64, 'not base64!!!'],
      [:malformed, ''],
      [:malformed, 'QQ==']
    ]
    plain_cases = [
      [:invalid_counter, "#{nonce}.01.5.{}"],
      [:counter_exceeds_solver_maximum, "#{nonce}.20000000.5.{}"],
      [:invalid_duration, "#{nonce}.5.01.{}"],
      [:malformed, "#{nonce}.5.5.[]"],
      [:malformed, "#{nonce}.5.5.3"]
    ]
    plain_cases.each do |code, plain|
      cases << [code, [plain].pack('m0')]
    end
    cases.each do |code, raw|
      error = assert_raises(KiwiCaptcha::DecodeError) { KiwiCaptcha::Token.decode(raw) }
      assert_equal code, error.code
    end
    # A nonce with non-zero unused bits in the final sextet is refused
    # by the strict re-encode check.
    bad_nonce = 'AAAA' * 10 + 'AAB='
    assert_raises(KiwiCaptcha::DecodeError) { KiwiCaptcha::Token.decode("#{bad_nonce}.5.5.{}") }
    # A duration beyond the ceiling is invalid.
    assert_raises(KiwiCaptcha::DecodeError) { KiwiCaptcha::Token.decode("#{nonce}.5.3600001.{}") }
    # Oversized input is malformed before any decode.
    assert_raises(KiwiCaptcha::DecodeError) { KiwiCaptcha::Token.decode('a' * 40_000) }
  end

  def test_non_object_telemetry_is_malformed
    nonce = 'A' * 43 + '='
    plain = "#{nonce}.5.5.[1]"
    raw = [plain].pack('m0')
    assert_raises(KiwiCaptcha::DecodeError) { KiwiCaptcha::Token.decode(raw) }
  end
end
