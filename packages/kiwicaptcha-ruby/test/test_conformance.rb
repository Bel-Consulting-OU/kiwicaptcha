# frozen_string_literal: true

require_relative 'helper'

# The cross-SDK conformance runner: the shared protocol corpus
# (solution-token-v1, limits.json, risk-v1 outcome vectors) plus the
# PHP-issued golden records, asserted end to end so behavior cannot
# drift from the other cores.
class ConformanceTest < Minitest::Test
  include TestSupport

  def test_the_shared_registers_agree_with_the_implementation_constants
    limits = TestSupport.protocol('limits.json')
    assert_equal limits['solver_max_hashes'], KiwiCaptcha::Pow::SOLVER_MAX_HASHES
    assert_equal limits['ttl_max_secs'], KiwiCaptcha::Verify::MAX_TTL_SECS
    assert_equal limits['token_max_duration_ms'], KiwiCaptcha::Token::MAX_DURATION_MS
    assert_equal limits['min_master_bytes'], KiwiCaptcha::Keys::MIN_SECRET_BYTES
    assert_equal limits['rsw_t_min'], KiwiCaptcha::Rsw::T_MIN
    assert_equal limits['rsw_t_max'], KiwiCaptcha::Rsw::T_MAX
    assert_equal limits['execution_max_program_base64'], KiwiCaptcha::Record::MAX_PROGRAM_BASE64
    fixture = TestSupport.protocol('solution-token-v1/fixtures.json')
    assert_equal fixture['solver_max_hashes'], KiwiCaptcha::Pow::SOLVER_MAX_HASHES
  end

  def test_every_verify_error_code_is_in_the_shared_vocabulary
    expected = %w[
      admission_unavailable already_consumed bad_signature capacity_exceeded
      consume_indeterminate execution_mismatch expired insufficient_work
      required_scope
      ip_mismatch malformed_record malformed_token missing_client_ip
      record_not_found request_binding_mismatch storage_unavailable
      telemetry_rejected too_fast too_many_attempts unknown_kid
      unsupported_argon2_params unsupported_rsw_params wrong_issuer
      wrong_policy_version wrong_region wrong_scope
    ]
    assert_equal expected.sort, KiwiCaptcha::VerifyError::ALL.sort
    KiwiCaptcha::VerifyError::ALL.each do |code|
      assert_match(/\A[a-z0-9_]+\z/, code)
      refute_nil KiwiCaptcha::VerifyError.describe(code)
    end
  end

  def test_every_golden_record_verifies_to_its_php_pinned_verdict
    TestSupport.golden['records'].each do |row|
      record = TestSupport.record_from_row(row)
      # The record JSON survives a strict parse and a canonical rewrite.
      token = KiwiCaptcha::Token.decode(row['token_b64'])
      assert_equal row['token_b64'], token.encode, row['name']
      storage = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
      storage.store(record)
      opts = golden_options(record, row, storage)
      result = KiwiCaptcha.verify(row['token_b64'], opts)
      assert_equal row['expected']['ok'], result.ok, "#{row['name']}: ok mismatch (#{result.code})"
      if row['expected'].key?('code')
        assert_equal row['expected']['code'], result.code, "#{row['name']}: code mismatch"
      end
      if row['expected'].key?('decoyField')
        assert_equal row['expected']['decoyField'], result.decoy_field, row['name']
      end
    end
  end

  def golden_options(record, row, storage)
    opts = { storage: storage, secret_key: golden_secret }.merge(TestSupport.frozen_clock(record))
    row['verify_opts'].each do |key, value|
      sym = {
        'expected_scope' => :expected_scope,
        'region' => :region,
        'expected_issuer' => :expected_issuer,
        'expected_policy_version' => :expected_policy_version,
        'client_ip' => :client_ip,
        'expected_request_binding' => :expected_request_binding,
        'secrets_by_kid' => :secrets_by_kid,
        'rsw' => :rsw
      }.fetch(key, nil)
      opts[sym] = value unless sym.nil?
    end
    TestSupport.verify_options(opts)
  end

  def golden_secret
    TestSupport.golden['hkdf']['secret']
  end

  def test_the_outcome_channels_match_the_risk_v1_event_kinds
    vectors = TestSupport.protocol('risk-v1/outcomes-vectors.json')
    vectors['vectors'].each do |vector|
      next unless vector['accepted']

      mapping = KiwiCaptcha::Outcomes.outcome_mapping(vector['outcome'])
      assert_equal vector['channel_value'], mapping.channel
    end
  end

  def test_a_consumed_golden_record_replays_the_identical_denial_code
    row = TestSupport.golden_record('sha_plain')
    record = TestSupport.record_from_row(row)
    storage = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
    storage.store(record)
    token = KiwiCaptcha::Token.decode(row['token_b64'])
    wrong = token.class.new(**token.to_h.merge(counter: 12_345)).encode
    clock = TestSupport.frozen_clock(record)
    first = KiwiCaptcha.verify(wrong, TestSupport.verify_options(storage: storage, secret_key: golden_secret, **clock))
    assert_equal 'insufficient_work', first.code
    second = KiwiCaptcha.verify(wrong, TestSupport.verify_options(storage: storage, secret_key: golden_secret, **clock))
    assert_equal 'insufficient_work', second.code
  end
end
