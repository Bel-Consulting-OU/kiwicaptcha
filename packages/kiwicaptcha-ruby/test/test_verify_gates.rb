# frozen_string_literal: true

require_relative 'helper'

# The verifier behavior suite over the PHP-issued golden records: the
# canonical cheap-gate order, the rollout floor window, the one-shot
# replay semantics, the measured solve duration and every locally
# drivable VerifyError code.
class VerifyGatesTest < Minitest::Test
  include TestSupport

  def random_bytes(n)
    (1..n).map { rand(256) }.pack('C*')
  end

  def store_of(name)
    row = TestSupport.golden_record(name)
    record = TestSupport.record_from_row(row)
    storage = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
    storage.store(record)
    [storage, record, row]
  end

  def options_for(record, row, storage, extra = {})
    opts = { storage: storage, secret_key: SECRET }.merge(TestSupport.frozen_clock(record))
    row['verify_opts'].each do |key, value|
      sym = case key
            when 'expected_scope' then :expected_scope
            when 'region' then :region
            when 'expected_issuer' then :expected_issuer
            when 'expected_policy_version' then :expected_policy_version
            when 'client_ip' then :client_ip
            when 'expected_request_binding' then :expected_request_binding
            when 'secrets_by_kid' then :secrets_by_kid
            when 'rsw' then :rsw
            else raise KeyError, key
            end
      opts[sym] = value
    end
    TestSupport.verify_options(opts.merge(extra))
  end

  def test_the_golden_happy_paths_verify_with_the_contract_shape
    %w[sha_plain sha_bound sha_decoy_v3 rsw].each do |name|
      storage, record, row = store_of(name)
      result = KiwiCaptcha.verify(TestSupport.golden_record(name)['token_b64'], options_for(record, row, storage))
      assert result.ok, "#{name}: #{result.code} #{result.detail}"
      assert_equal 'allow', result.disposition
      assert_equal record.nonce, result.decision_handle
      assert_instance_of String, result.price
      assert_empty result.code
      assert_nil result.detail
    end

    _s, _r, row = store_of('sha_decoy_v3')
    storage, record, = store_of('sha_decoy_v3')
    decoy = KiwiCaptcha.verify(row['token_b64'], options_for(record, row, storage))
    assert_equal 'decoy_field_a1b2c3d4e5f60718', decoy.decoy_field

    storage, record, row = store_of('sha_plain')
    plain = KiwiCaptcha.verify(row['token_b64'], options_for(record, row, storage))
    assert_instance_of Integer, plain.solve_duration_ms
    assert_operator plain.solve_duration_ms, :>, 1000
  end

  def test_execution_armed_records_fail_closed
    storage, record, row = store_of('sha_execution_v4')
    result = KiwiCaptcha.verify(row['token_b64'], options_for(record, row, storage))
    refute result.ok
    assert_equal KiwiCaptcha::VerifyError::EXECUTION_MISMATCH, result.code
  end

  def test_the_golden_negative_records_answer_their_pinned_codes
    { 'argon2id' => KiwiCaptcha::VerifyError::UNSUPPORTED_ARGON2_PARAMS,
      'tampered_signature' => KiwiCaptcha::VerifyError::BAD_SIGNATURE }.each do |name, code|
      storage, record, row = store_of(name)
      result = KiwiCaptcha.verify(TestSupport.golden_record(name)['token_b64'], options_for(record, row, storage))
      refute result.ok, name
      assert_equal 'deny', result.disposition
      assert_equal code, result.code
      assert_nil result.decision_handle
      assert_nil result.price
    end
  end

  def test_an_unknown_token_answers_record_not_found
    row = TestSupport.golden_record('sha_plain')
    storage = KiwiCaptcha::MemoryStore.new(now: -> { TestSupport.record_from_row(row).issued_at + 10 })
    result = KiwiCaptcha.verify(row['token_b64'], TestSupport.verify_options(storage: storage))
    assert_equal KiwiCaptcha::VerifyError::RECORD_NOT_FOUND, result.code
  end

  def test_malformed_tokens_answer_malformed_token
    storage = KiwiCaptcha::MemoryStore.new
    ['not base64!!!', '', 'QQ==', 'a' * 40_000].each do |raw|
      result = KiwiCaptcha.verify(raw, TestSupport.verify_options(storage: storage))
      assert_equal KiwiCaptcha::VerifyError::MALFORMED_TOKEN, result.code
    end
  end

  def test_an_expired_record_answers_expired_on_the_verifier_clock
    storage, record, row = store_of('sha_plain')
    result = KiwiCaptcha.verify(
      row['token_b64'],
      options_for(record, row, storage, now: -> { record.expires_at + 1 })
    )
    assert_equal KiwiCaptcha::VerifyError::EXPIRED, result.code

    storage, record, row = store_of('sha_plain')
    result = KiwiCaptcha.verify(
      row['token_b64'],
      options_for(record, row, storage, now: -> { record.issued_at - 61 })
    )
    assert_equal KiwiCaptcha::VerifyError::EXPIRED, result.code
  end

  def test_the_record_is_consumed_exactly_once_and_replays_deterministically
    storage, record, row = store_of('sha_plain')
    opts = options_for(record, row, storage)
    first = KiwiCaptcha.verify(row['token_b64'], opts)
    assert first.ok
    replay = KiwiCaptcha.verify(row['token_b64'], opts)
    assert_equal KiwiCaptcha::VerifyError::ALREADY_CONSUMED, replay.code
    state = storage.runtime_state(record.nonce)
    assert_equal 'consumed', state.kind
  end

  def test_a_stored_success_replays_only_under_the_proven_operation_identity
    storage, record, row = store_of('sha_plain')
    base = options_for(record, row, storage)
    ok = KiwiCaptcha.verify(row['token_b64'], options_for(record, row, storage, operation_identity: 'op-123'))
    assert ok.ok
    replay = KiwiCaptcha.verify(row['token_b64'], options_for(record, row, storage, operation_identity: 'op-123'))
    assert replay.ok
    assert replay.from_stored_result
    assert_nil replay.solve_duration_ms
    assert_equal record.nonce, replay.decision_handle
    other = KiwiCaptcha.verify(row['token_b64'], options_for(record, row, storage, operation_identity: 'op-456'))
    assert_equal KiwiCaptcha::VerifyError::ALREADY_CONSUMED, other.code
    anonymous = KiwiCaptcha.verify(row['token_b64'], base)
    assert_equal KiwiCaptcha::VerifyError::ALREADY_CONSUMED, anonymous.code
  end

  def test_a_stored_invalid_outcome_replays_to_any_caller
    storage, record, row = store_of('sha_plain')
    token = KiwiCaptcha::Token.decode(row['token_b64'])
    wrong = token.class.new(**token.to_h.merge(counter: 999_999)).encode
    opts = options_for(record, row, storage)
    bad = KiwiCaptcha.verify(wrong, opts)
    assert_equal KiwiCaptcha::VerifyError::INSUFFICIENT_WORK, bad.code
    replay = KiwiCaptcha.verify(wrong, opts)
    assert_equal KiwiCaptcha::VerifyError::INSUFFICIENT_WORK, replay.code
  end

  def test_a_resultless_consumed_record_answers_consume_indeterminate
    storage, record, row = store_of('sha_plain')
    storage.consume(record.nonce)
    result = KiwiCaptcha.verify(row['token_b64'], options_for(record, row, storage))
    assert_equal KiwiCaptcha::VerifyError::CONSUME_INDETERMINATE, result.code
  end

  def test_a_forged_success_grant_without_the_mac_is_refused_as_malformed
    storage, record, row = store_of('sha_plain')
    storage.consume(record.nonce, 'grant-op')
    storage.commit_result(record.nonce, true, nil, nil)
    forged = KiwiCaptcha.verify(row['token_b64'], options_for(record, row, storage, operation_identity: 'grant-op'))
    assert_equal KiwiCaptcha::VerifyError::MALFORMED_RECORD, forged.code

    storage2, record, row = store_of('sha_plain')
    storage2.consume(record.nonce)
    storage2.commit_result(record.nonce, true, nil, nil)
    anonymous = KiwiCaptcha.verify(row['token_b64'], options_for(record, row, storage2))
    assert_equal KiwiCaptcha::VerifyError::ALREADY_CONSUMED, anonymous.code
  end

  def test_an_operation_identity_is_validated_before_the_transition
    storage, record, row = store_of('sha_plain')
    result = KiwiCaptcha.verify(row['token_b64'], options_for(record, row, storage, operation_identity: 'spaces not allowed'))
    assert_equal KiwiCaptcha::VerifyError::CONSUME_INDETERMINATE, result.code
    assert_equal 'pending', storage.runtime_state(record.nonce).kind
  end

  def test_scope_region_issuer_and_policy_epoch_answer_their_typed_codes
    expect_code = lambda do |extra|
      storage, record, row = store_of('sha_plain')
      KiwiCaptcha.verify(row['token_b64'], options_for(record, row, storage, extra)).code
    end
    assert_equal KiwiCaptcha::VerifyError::WRONG_SCOPE, expect_code.call(expected_scope: 'other')
    # The scope option is required: an empty option is the typed
    # required_scope refusal, never an any-scope acceptance.
    assert_equal KiwiCaptcha::VerifyError::REQUIRED_SCOPE, expect_code.call(expected_scope: '')
    assert_equal KiwiCaptcha::VerifyError::WRONG_REGION, expect_code.call(region: 'us')
    assert_equal KiwiCaptcha::VerifyError::WRONG_ISSUER, expect_code.call(region: nil, expected_issuer: 'prod')
    assert_equal KiwiCaptcha::VerifyError::WRONG_POLICY_VERSION, expect_code.call(expected_policy_version: 2)
  end

  def test_the_policy_rollout_window_accepts_the_old_epoch_and_fails_closed_above_it
    storage, record, row = store_of('sha_plain')
    strict = KiwiCaptcha.verify(row['token_b64'], options_for(record, row, storage, expected_policy_version: 2))
    assert_equal KiwiCaptcha::VerifyError::WRONG_POLICY_VERSION, strict.code

    storage, record, row = store_of('sha_plain')
    window_ok = KiwiCaptcha.verify(
      row['token_b64'],
      options_for(record, row, storage, expected_policy_version: 2, policy_version_floor: 1)
    )
    assert window_ok.ok, window_ok.code

    storage, record, row = store_of('sha_plain')
    window_reject = KiwiCaptcha.verify(
      row['token_b64'],
      options_for(record, row, storage, expected_policy_version: 3, policy_version_floor: 2)
    )
    assert_equal KiwiCaptcha::VerifyError::WRONG_POLICY_VERSION, window_reject.code
  end

  def test_the_ip_binding_answers_missing_client_ip_and_ip_mismatch_and_never_deletes_on_missing
    storage, record, row = store_of('sha_bound')
    ok = KiwiCaptcha.verify(row['token_b64'], options_for(record, row, storage))
    assert ok.ok

    storage2, record2, row2 = store_of('sha_bound')
    no_ip = KiwiCaptcha.verify(row2['token_b64'], options_for(record2, row2, storage2, client_ip: nil))
    assert_equal KiwiCaptcha::VerifyError::MISSING_CLIENT_IP, no_ip.code
    assert_equal 'pending', storage2.runtime_state(record2.nonce).kind
    wrong_ip = KiwiCaptcha.verify(row2['token_b64'], options_for(record2, row2, storage2, client_ip: '198.51.100.9'))
    assert_equal KiwiCaptcha::VerifyError::IP_MISMATCH, wrong_ip.code
    assert_equal 'missing', storage2.runtime_state(record2.nonce).kind
  end

  def test_the_request_binding_is_exact_option_equality_with_the_named_legacy_mode
    storage, record, row = store_of('sha_bound')
    assert KiwiCaptcha.verify(row['token_b64'], options_for(record, row, storage)).ok

    storage2, record2, row2 = store_of('sha_bound')
    wrong = KiwiCaptcha.verify(row2['token_b64'], options_for(record2, row2, storage2, expected_request_binding: 'tx-other'))
    assert_equal KiwiCaptcha::VerifyError::REQUEST_BINDING_MISMATCH, wrong.code

    plain_row = TestSupport.golden_record('sha_plain')
    plain = TestSupport.record_from_row(plain_row)
    storage3 = KiwiCaptcha::MemoryStore.new(now: -> { plain.issued_at + 10 })
    storage3.store(plain)
    legacy = KiwiCaptcha.verify(
      plain_row['token_b64'],
      options_for(plain, plain_row, storage3, expected_request_binding: 'tx-9999', binding_expectation: :legacy)
    )
    assert legacy.ok

    storage4 = KiwiCaptcha::MemoryStore.new(now: -> { plain.issued_at + 10 })
    storage4.store(plain)
    exact = KiwiCaptcha.verify(
      plain_row['token_b64'],
      options_for(plain, plain_row, storage4, expected_request_binding: 'tx-9999')
    )
    assert_equal KiwiCaptcha::VerifyError::REQUEST_BINDING_MISMATCH, exact.code
  end

  def test_the_kid_gate_answers_unknown_kid_for_revoked_and_unresolved_kids
    storage, record, row = store_of('sha_bound')
    revoked = KiwiCaptcha.verify(row['token_b64'], options_for(record, row, storage, revoked_kids: [2]))
    assert_equal KiwiCaptcha::VerifyError::UNKNOWN_KID, revoked.code

    # A kid beyond the newest configured kid is the forward guard: the
    # forged record is re-signed so only the kid gate can reject it.
    forged = KiwiCaptcha::Record.to_json_record(record)
    forged['kid'] = 9
    signed = re_sign(forged, 9)
    storage3 = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
    storage3.store(signed)
    token = KiwiCaptcha::Token.decode(row['token_b64'])
    forward = KiwiCaptcha.verify(
      token.encode,
      options_for(record, row, storage3, secrets_by_kid: { 1 => SECRET })
    )
    assert_equal KiwiCaptcha::VerifyError::UNKNOWN_KID, forward.code
  end

  def re_sign(record_data, kid)
    record_data['protocol_version'] = 2
    record_data.delete('server_mac')
    canonical = KiwiCaptcha::Canonical.canonical_payload(
      KiwiCaptcha::Canonical::CanonicalArgs.new(
        protocol_version: 2, nonce: record_data['nonce'], scope: record_data['scope'],
        binding_tag: record_data['binding_tag'], issued_at: record_data['issued_at'],
        expires_at: record_data['expires_at'], algorithm: record_data['algorithm'],
        m_kib: record_data['m_kib'], t: record_data['t'], p: record_data['p'],
        target_bits: record_data['target_bits'], salt: record_data['salt'],
        min_duration_ms: record_data['min_duration_ms'], region: record_data['region'],
        policy_version: record_data['policy_version'], request_binding: record_data['request_binding'],
        issuer: record_data['issuer'], kid: kid,
        decoy_field: record_data['decoy_field'],
        execution_version: record_data['execution_version'],
        execution_commitment: record_data['execution_commitment'],
        rsw_modulus_sha256: record_data['rsw_modulus_sha256'],
        server_mac_committed: false
      )
    )
    challenge = [canonical].pack('m0') + '.' + KiwiCaptcha::Canonical.sign_payload_v2(canonical, SECRET)
    record_data['challenge'] = challenge
    record_data['prefix'] = "#{challenge}|#{record_data['salt']}|"
    KiwiCaptcha::Record.from_json(record_data)
  end

  def test_too_fast_fires_on_a_receipt_inside_the_signed_minimum_duration
    storage, record, row = store_of('sha_plain')
    result = KiwiCaptcha.verify(
      row['token_b64'],
      options_for(record, row, storage, now_ns: record.issued_at_ns + 100)
    )
    assert_equal KiwiCaptcha::VerifyError::TOO_FAST, result.code

    storage2, record2, row2 = store_of('sha_plain')
    ok = KiwiCaptcha.verify(row2['token_b64'], options_for(record2, row2, storage2, now_ns: record2.issued_at_ns + 600_000))
    assert ok.ok

    storage3, record3, row3 = store_of('sha_plain')
    skewed = KiwiCaptcha.verify(row3['token_b64'], options_for(record3, row3, storage3, now_ns: record3.issued_at_ns - 6_000_000))
    assert_equal KiwiCaptcha::VerifyError::TOO_FAST, skewed.code

    storage4, record4, row4 = store_of('sha_plain')
    within = KiwiCaptcha.verify(row4['token_b64'], options_for(record4, row4, storage4, now_ns: record4.issued_at_ns - 1_000_000))
    assert within.ok
  end

  def test_a_wrong_proof_on_a_real_sha256_record_is_insufficient_work
    storage, record, row = store_of('sha_plain')
    token = KiwiCaptcha::Token.decode(row['token_b64'])
    wrong = token.class.new(**token.to_h.merge(counter: token.counter + 1)).encode
    result = KiwiCaptcha.verify(wrong, options_for(record, row, storage))
    assert_equal KiwiCaptcha::VerifyError::INSUFFICIENT_WORK, result.code
  end

  def test_a_freshly_solved_proof_of_a_re_signed_record_verifies_end_to_end
    nonce = [random_bytes(32)].pack('m0')
    salt = [random_bytes(16)].pack('m0')
    issued_at = Time.now.to_i - 30
    expires_at = issued_at + 120
    canonical = KiwiCaptcha::Canonical.canonical_payload(
      KiwiCaptcha::Canonical::CanonicalArgs.new(
        protocol_version: 2, nonce: nonce, scope: 'login', binding_tag: '',
        issued_at: issued_at, expires_at: expires_at, algorithm: 'sha256',
        m_kib: 0, t: 1, p: 1, target_bits: 8, salt: salt, min_duration_ms: 0,
        region: nil, policy_version: 1, request_binding: nil, issuer: nil, kid: 1
      )
    )
    challenge = [canonical].pack('m0') + '.' + KiwiCaptcha::Canonical.sign_payload_v2(canonical, SECRET)
    prefix = "#{challenge}|#{salt}|"
    counter = KiwiCaptcha::Pow.solve_sha256(prefix, salt, 8)
    issued_at_ns = (Time.now.to_f * 1_000_000).to_i - 3_000_000
    server_mac = KiwiCaptcha::Mac.record_meta_mac(
      KiwiCaptcha::Mac.server_state_key(SECRET), challenge, issued_at_ns, nil
    )
    record = KiwiCaptcha::Record.from_json(
      'nonce' => nonce, 'scope' => 'login', 'binding_tag' => '',
      'issued_at' => issued_at, 'expires_at' => expires_at, 'algorithm' => 'sha256',
      'm_kib' => 0, 't' => 1, 'p' => 1, 'target_bits' => 8, 'salt' => salt,
      'prefix' => prefix, 'challenge' => challenge, 'min_duration_ms' => 0,
      'issued_at_ns' => issued_at_ns, 'protocol_version' => 2, 'region' => nil,
      'policy_version' => 1, 'request_binding' => nil, 'issuer' => nil, 'kid' => 1,
      'hostname' => nil, 'server_mac' => server_mac
    )
    storage = KiwiCaptcha::MemoryStore.new
    storage.store(record)
    token = TestSupport.token_for(nonce, counter, 1200, { 'v' => 1 })
    result = KiwiCaptcha.verify(token, TestSupport.verify_options(storage: storage, expected_scope: 'login'))
    assert result.ok, result.code
    assert_equal 'sha8bit', result.price
    assert_instance_of Integer, result.solve_duration_ms
    replay = KiwiCaptcha.verify(
      token,
      TestSupport.verify_options(storage: storage, expected_scope: 'login', operation_identity: 'op-x')
    )
    assert_equal KiwiCaptcha::VerifyError::ALREADY_CONSUMED, replay.code
  end

  def test_structural_tampering_fails_closed_as_malformed_record_and_burns_the_record
    row = TestSupport.golden_record('sha_plain')
    record = TestSupport.record_from_row(row)
    mutations = [
      ->(r) { r.scope = 'has space'; r },
      ->(r) { r.protocol_version = 1; r },
      ->(r) { r.expires_at = r.issued_at + 301; r },
      ->(r) { r.target_bits = 21; r },
      ->(r) { r.salt = ([1] * 15).pack('C*').unpack1('m'); r },
      ->(r) { r.prefix = 'wrong|prefix|'; r }
    ]
    mutations.each do |mutate|
      storage = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
      storage.store(mutate.call(KiwiCaptcha::Record.from_json(KiwiCaptcha::Record.to_json_record(record))))
      result = KiwiCaptcha.verify(row['token_b64'], TestSupport.verify_options(storage: storage))
      assert_equal KiwiCaptcha::VerifyError::MALFORMED_RECORD, result.code
      assert_equal 'missing', storage.runtime_state(record.nonce).kind
    end

    kid_storage = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
    kid_storage.store(KiwiCaptcha::Record.from_json(KiwiCaptcha::Record.to_json_record(record).merge('kid' => 0)))
    kid_result = KiwiCaptcha.verify(row['token_b64'], TestSupport.verify_options(storage: kid_storage))
    assert_equal KiwiCaptcha::VerifyError::BAD_SIGNATURE, kid_result.code
  end

  def test_armed_records_demand_execution_evidence_and_refuse_stray_digests
    exec_row = TestSupport.golden_record('sha_execution_v4')
    exec_record = TestSupport.record_from_row(exec_row)
    token = KiwiCaptcha::Token.decode(exec_row['token_b64'])
    bare = token.class.new(**token.to_h.merge(execution_digest: nil, execution_trace: nil)).encode
    storage = KiwiCaptcha::MemoryStore.new(now: -> { exec_record.issued_at + 10 })
    storage.store(exec_record)
    result = KiwiCaptcha.verify(bare, options_for(exec_record, exec_row, storage))
    assert_equal KiwiCaptcha::VerifyError::EXECUTION_MISMATCH, result.code

    plain_row = TestSupport.golden_record('sha_plain')
    plain = TestSupport.record_from_row(plain_row)
    stray_token = KiwiCaptcha::Token.decode(plain_row['token_b64'])
    stray = stray_token.class.new(**stray_token.to_h.merge(execution_digest: 'a' * 64)).encode
    storage4 = KiwiCaptcha::MemoryStore.new(now: -> { plain.issued_at + 10 })
    storage4.store(plain)
    stray_result = KiwiCaptcha.verify(stray, options_for(plain, plain_row, storage4))
    assert_equal KiwiCaptcha::VerifyError::EXECUTION_MISMATCH, stray_result.code
  end

  def test_an_unarmed_signed_rsw_record_without_a_trapdoor_is_unsupported
    storage, record, row = store_of('rsw')
    no_trapdoor = KiwiCaptcha.verify(row['token_b64'], options_for(record, row, storage, rsw: nil))
    assert_equal KiwiCaptcha::VerifyError::UNSUPPORTED_RSW_PARAMS, no_trapdoor.code

    storage2, record2, row2 = store_of('rsw')
    token = KiwiCaptcha::Token.decode(row2['token_b64'])
    refute_nil token.rsw_proof
    wrong = token.class.new(**token.to_h.merge(counter: 3)).encode
    wrong_result = KiwiCaptcha.verify(wrong, options_for(record2, row2, storage2))
    assert_equal KiwiCaptcha::VerifyError::INSUFFICIENT_WORK, wrong_result.code

    plain_row = TestSupport.golden_record('sha_plain')
    plain_record = TestSupport.record_from_row(plain_row)
    storage3 = KiwiCaptcha::MemoryStore.new(now: -> { plain_record.issued_at + 10 })
    storage3.store(plain_record)
    stray_token = KiwiCaptcha::Token.decode(plain_row['token_b64'])
    stray = stray_token.class.new(**stray_token.to_h.merge(rsw_proof: 'a' * 512)).encode
    stray_result = KiwiCaptcha.verify(stray, options_for(plain_record, plain_row, storage3))
    assert_equal KiwiCaptcha::VerifyError::INSUFFICIENT_WORK, stray_result.code
  end

  def test_the_telemetry_gate_rejects_bot_signals_on_a_pending_record_only
    row = TestSupport.golden_record('sha_plain')
    record = TestSupport.record_from_row(row)
    token = KiwiCaptcha::Token.decode(row['token_b64'])

    empty_storage = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
    empty_storage.store(record)
    empty = token.class.new(**token.to_h.merge(telemetry: {})).encode
    result = KiwiCaptcha.verify(empty, options_for(record, row, empty_storage, enforce_telemetry: true))
    assert_equal KiwiCaptcha::VerifyError::TELEMETRY_REJECTED, result.code

    uniform_storage = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
    uniform_storage.store(record)
    uniform = (0...30).map { |i| i * 100 }
    uniform_token = token.class.new(**token.to_h.merge(telemetry: { 'et' => uniform })).encode
    result = KiwiCaptcha.verify(uniform_token, options_for(record, row, uniform_storage, enforce_telemetry: true))
    assert_equal KiwiCaptcha::VerifyError::TELEMETRY_REJECTED, result.code

    human_storage = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
    human_storage.store(record)
    human = (0...30).map { |i| (i * 100 + (Math.sin(i) * 37).to_i + (i * i) % 13) }
    human_token = token.class.new(**token.to_h.merge(telemetry: { 'et' => human })).encode
    result = KiwiCaptcha.verify(human_token, options_for(record, row, human_storage, enforce_telemetry: true))
    assert result.ok, result.code

    wd_storage = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
    wd_storage.store(record)
    wd = token.class.new(**token.to_h.merge(telemetry: { 'wd' => true })).encode
    result = KiwiCaptcha.verify(wd, options_for(record, row, wd_storage, enforce_telemetry: true))
    assert_equal KiwiCaptcha::VerifyError::TELEMETRY_REJECTED, result.code
  end

  def test_a_store_failure_answers_storage_unavailable_fail_closed
    row = TestSupport.golden_record('sha_plain')
    failing = Object.new
    failing.define_singleton_method(:runtime_state) { raise 'down' }
    result = KiwiCaptcha.verify(row['token_b64'], TestSupport.verify_options(storage: failing))
    assert_equal KiwiCaptcha::VerifyError::STORAGE_UNAVAILABLE, result.code
  end
end
