# frozen_string_literal: true

require_relative 'helper'

# The outcomes mapping against the risk-v1 vectors, the handle grammar,
# the mark and idempotency keys, and the doctor's deployment checks.
class OutcomesDoctorTest < Minitest::Test
  include TestSupport

  def test_every_accepted_outcome_vector_resolves_through_the_mapping
    vectors = TestSupport.protocol('risk-v1/outcomes-vectors.json')
    vectors['vectors'].each do |vector|
      outcome = vector['outcome']
      mapping = KiwiCaptcha::Outcomes.outcome_mapping(outcome)
      handle = KiwiCaptcha::Outcomes::OutcomeHandle.new(
        dimension: vector['handle']['dimension'], id: vector['handle']['id']
      )
      accepted = vector['accepted']
      dimension_ok = KiwiCaptcha::Outcomes.accepts?(mapping, handle.dimension)
      # Acceptance is dimension membership AND the handle grammar: a
      # raw identifier is refused before any mark key is built.
      grammar_ok = begin
        KiwiCaptcha::Outcomes.validate_outcome_handle(handle)
        true
      rescue RangeError
        false
      end
      assert_equal accepted, dimension_ok && grammar_ok, outcome
      next unless vector.key?('channel_value')

      assert_equal vector['channel_value'], mapping.channel, outcome
      if vector['ledger_action'] == 'L'
        assert mapping.ledger_legitimate == true, outcome
      elsif vector['ledger_action'] == 'A'
        assert mapping.ledger_legitimate == false, outcome
      else
        assert_nil mapping.ledger_legitimate, outcome
      end
    end
  end

  def test_the_mapping_table_is_total_and_versioned
    assert_equal 1, KiwiCaptcha::Outcomes::MAP_VERSION
    assert_equal TestSupport.protocol('risk-v1/outcomes-vectors.json')['version'], KiwiCaptcha::Outcomes::MAP_VERSION
    rows = KiwiCaptcha::Outcomes.all_outcome_mappings
    assert_equal KiwiCaptcha::Outcomes::OUTCOMES.length, rows.length
    rows.each do |row|
      # Only the server-confirmed outcomes that never write abuse marks
      # may subtract risk, and exactly the abuse outcomes write
      # long-memory marks.
      assert_equal row.may_subtract_risk, row.server_confirmed && !row.writes_abuse_mark
      refute row.writes_abuse_mark && !row.server_confirmed
      if row.ledger_legitimate == false
        assert row.writes_abuse_mark
      end
    end
  end

  def test_the_handle_grammar_refuses_raw_identifiers
    validate = KiwiCaptcha::Outcomes.method(:validate_outcome_handle)
    pseudonym = 'a' * 32
    %w[principal target session].each do |dimension|
      validate.call(KiwiCaptcha::Outcomes::OutcomeHandle.new(dimension: dimension, id: pseudonym))
      assert_raises(RangeError) do
        validate.call(KiwiCaptcha::Outcomes::OutcomeHandle.new(dimension: dimension, id: 'raw-user@example.test'))
      end
    end
    validate.call(KiwiCaptcha::Outcomes::OutcomeHandle.new(dimension: 'agent', id: 'agent-key-1'))
    assert_raises(RangeError) { validate.call(KiwiCaptcha::Outcomes::OutcomeHandle.new(dimension: 'agent', id: 'bad:char')) }
    assert_raises(RangeError) { validate.call(KiwiCaptcha::Outcomes::OutcomeHandle.new(dimension: 'agent', id: '')) }
  end

  def test_the_client_books_the_ledger_and_marks_through_one_sink
    sink = KiwiCaptcha::Outcomes::MemorySink.new
    client = KiwiCaptcha::Outcomes::Client.new(sink, 'test')
    receipt = client.report('confirmedLegitimate', KiwiCaptcha::Outcomes::OutcomeHandle.new(dimension: 'decisionId', id: 'd' * 32))
    assert_equal 12, receipt.mapping.channel
    assert_equal 1, receipt.ledger_status
    assert_equal 0, receipt.marks_written
    assert_equal 1, sink.feedback.length

    receipt = client.report('fraudConfirmed', KiwiCaptcha::Outcomes::OutcomeHandle.new(dimension: 'principal', id: 'a' * 32))
    assert_nil receipt.ledger_status
    assert_equal 1, receipt.marks_written
    assert_equal 'fraudConfirmed', sink.marks.fetch(KiwiCaptcha::Outcomes.mark_key('test', 'principal', 'a' * 32))
    # The forget path erases the dimension's marks.
    assert_equal 1, client.forget(KiwiCaptcha::Outcomes::OutcomeHandle.new(dimension: 'principal', id: 'a' * 32))
    assert_equal 0, client.forget(KiwiCaptcha::Outcomes::OutcomeHandle.new(dimension: 'nonce', id: 'b' * 32))

    # A dimension the mapping does not accept is refused before any
    # write: confirmedLegitimate accepts every dimension, the identity
    # outcomes never accept the ledger ones.
    client.report('confirmedLegitimate', KiwiCaptcha::Outcomes::OutcomeHandle.new(dimension: 'session', id: 'c' * 32))
    assert_raises(RangeError) do
      client.report('stepUpCompleted', KiwiCaptcha::Outcomes::OutcomeHandle.new(dimension: 'nonce', id: 'c' * 32))
    end
  end

  def test_the_idempotency_key_is_a_bounded_hmac
    handle = KiwiCaptcha::Outcomes::OutcomeHandle.new(dimension: 'decisionId', id: 'd' * 32)
    key = KiwiCaptcha::Outcomes.default_idempotency_key(handle)
    assert_equal 32, key.length
    assert_match(/\A[0-9a-f]{32}\z/, key)
    assert_equal key, KiwiCaptcha::Outcomes.default_idempotency_key(handle)
    refute_equal key, KiwiCaptcha::Outcomes.default_idempotency_key(handle, 'other-secret')
  end

  def test_the_doctor_passes_a_sound_memory_deployment
    report = KiwiCaptcha::Doctor.run(secret: SECRET, store: KiwiCaptcha::MemoryStore.new)
    assert report.ok, report.checks.map { |c| "#{c.name}: #{c.detail}" }.join(', ')
    assert_equal %w[secret region issuer store], report.checks.map(&:name)
  end

  def test_the_doctor_flags_a_weak_secret_and_a_dead_store
    report = KiwiCaptcha::Doctor.run(secret: 'short', store: FailingStore.new)
    refute report.ok
    secret_check = report.checks.find { |c| c.name == 'secret' }
    refute secret_check.ok
    store_check = report.checks.find { |c| c.name == 'store' }
    refute store_check.ok
  end

  def test_the_doctor_flags_identifier_shapes
    report = KiwiCaptcha::Doctor.run(secret: SECRET, store: KiwiCaptcha::MemoryStore.new, region: 'has space', issuer: 'eu')
    refute report.checks.find { |c| c.name == 'region' }.ok
    assert report.checks.find { |c| c.name == 'issuer' }.ok
  end

  def test_the_doctor_validates_the_rsw_trapdoor
    rsw_row = TestSupport.golden_record('rsw')
    rsw_opts = rsw_row['verify_opts']['rsw']
    report = KiwiCaptcha::Doctor.run(
      secret: SECRET, store: KiwiCaptcha::MemoryStore.new,
      rsw: { modulus_n: rsw_opts['modulus_n'], lambda: rsw_opts['lambda'] }
    )
    assert report.checks.find { |c| c.name == 'rsw' }.ok
    report = KiwiCaptcha::Doctor.run(
      secret: SECRET, store: KiwiCaptcha::MemoryStore.new,
      rsw: { modulus_n: 'QQ==', lambda: 'Ag==' }
    )
    refute report.checks.find { |c| c.name == 'rsw' }.ok
  end

  def test_the_settings_open_store_surface
    store = KiwiCaptcha::Settings.open_store('memory://')
    assert_instance_of KiwiCaptcha::MemoryStore, store
    assert_raises(ArgumentError) { KiwiCaptcha::Settings.open_store('mysql://x') }
    settings = KiwiCaptcha::Settings.new(secret: SECRET, store_url: 'memory://', scopes: 'login=critical,comment=low', env: {})
    assert_equal 'abuse_first', settings.profile
    assert_equal({ 'login' => 'critical', 'comment' => 'low' }, settings.scopes)
    assert settings.valid_secret?
  end

  # A store whose every read raises: the doctor must report it, not
  # crash.
  class FailingStore
    def method_missing(name, *)
      raise "store down (#{name})"
    end

    def respond_to_missing?(*)
      true
    end
  end
end
