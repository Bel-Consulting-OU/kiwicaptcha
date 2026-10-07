# frozen_string_literal: true

require_relative 'helper'

# The default Argon2id admission gate: absurd profiles refuse loudly
# before a slot is taken, exhaustion answers capacity and keeps the
# record retryable, and the budgeted pool admits small rungs.
class ArgonAdmissionGateTest < Minitest::Test
  include TestSupport

  def test_the_default_gate_is_installed_and_bounded
    gate = KiwiCaptcha::Verify::ArgonAdmissionGate.new
    assert_operator gate.max_concurrent, :>=, 1
    assert_operator gate.max_memory_kib, :>, 0
    assert_operator gate.max_time_cost, :>, 0
    shared = KiwiCaptcha::Verify.default_argon_gate
    assert_same shared, KiwiCaptcha::Verify.default_argon_gate,
                'the default gate is process-wide, never per call'
  end

  def test_gate_refuses_out_of_budget_params_loudly
    record = TestSupport.record_from_row(TestSupport.golden_record('argon2id'))
    storage = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
    storage.store(record)
    # A gate whose budget cannot cover the golden record's 64 KiB
    # rung: the refuse is loud and typed, never a silent downgrade or
    # a derivation.
    gate = KiwiCaptcha::Verify::ArgonAdmissionGate.new(max_memory_kib: 8, max_time_cost: 3)
    opts = TestSupport.verify_options(
      storage: storage, secret_key: TestSupport.golden['hkdf']['secret'],
      expected_scope: 'login', argon_gate: gate, **TestSupport.frozen_clock(record)
    )
    result = KiwiCaptcha.verify(TestSupport.golden_record('argon2id')['token_b64'], opts)
    refute result.ok
    assert_equal KiwiCaptcha::VerifyError::UNSUPPORTED_ARGON2_PARAMS, result.code
    # The refusal never consumes: the record stays intact and retryable.
    refute_nil storage.find(record.nonce)
  end

  def test_exhaustion_answers_capacity_exceeded
    record = TestSupport.record_from_row(TestSupport.golden_record('argon2id'))
    storage = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
    storage.store(record)
    gate = KiwiCaptcha::Verify::ArgonAdmissionGate.new(max_concurrent: 1)
    lease = gate.acquire
    refute_nil lease
    opts = TestSupport.verify_options(
      storage: storage, secret_key: TestSupport.golden['hkdf']['secret'],
      expected_scope: 'login', argon_gate: gate, **TestSupport.frozen_clock(record)
    )
    result = KiwiCaptcha.verify(TestSupport.golden_record('argon2id')['token_b64'], opts)
    refute result.ok
    assert_equal KiwiCaptcha::VerifyError::CAPACITY_EXCEEDED, result.code
    # The record stays intact under the capacity refusal.
    refute_nil storage.find(record.nonce)
    gate.release(lease)
  end

  def test_budgeted_gate_admits_small_rungs
    gate = KiwiCaptcha::Verify::ArgonAdmissionGate.new(max_memory_kib: 8_192, max_time_cost: 3)
    assert gate.admits_params?(64, 3)
    refute gate.admits_params?(64 * 1024, 16)
    refute gate.admits_params?(gate.max_memory_kib, gate.max_time_cost + 1)
  end

  def test_release_returns_the_slot_to_the_pool
    gate = KiwiCaptcha::Verify::ArgonAdmissionGate.new(max_concurrent: 1)
    first = gate.acquire
    refute_nil first
    assert_nil gate.acquire, 'the pool is bounded'
    gate.release(first)
    second = gate.acquire
    refute_nil second, 'the released slot is handed out again'
    gate.release(second)
  end
end
