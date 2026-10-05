# frozen_string_literal: true

require_relative 'helper'

# The strict record parser: whitelisted keys, exact algorithm values,
# strict integer ranges, the protocol grammar and the execution triplet
# equivalence, plus the serialization round trip.
class RecordTest < Minitest::Test
  include TestSupport

  def golden_record(name)
    TestSupport.record_from_row(TestSupport.golden_record(name))
  end

  def test_golden_records_parse_and_serialize_round_trip
    %w[sha_plain sha_bound sha_decoy_v3 sha_execution_v4 argon2id rsw tampered_signature].each do |name|
      record = golden_record(name)
      data = KiwiCaptcha::Record.to_json_record(record)
      again = KiwiCaptcha::Record.from_json(data)
      assert_equal data, KiwiCaptcha::Record.to_json_record(again), name
    end
  end

  def test_unknown_keys_are_refused
    data = KiwiCaptcha::Record.to_json_record(golden_record('sha_plain'))
    data['sneaky'] = 1
    assert_raises(KiwiCaptcha::MalformedRecordError) { KiwiCaptcha::Record.from_json(data) }
  end

  def test_missing_required_fields_are_refused
    data = KiwiCaptcha::Record.to_json_record(golden_record('sha_plain'))
    data.delete('scope')
    assert_raises(KiwiCaptcha::MalformedRecordError) { KiwiCaptcha::Record.from_json(data) }
  end

  def test_integer_ranges_are_strict
    base = KiwiCaptcha::Record.to_json_record(golden_record('sha_plain'))
    { 'm_kib' => -1, 'attempts_used' => -1, 'issued_at_ns' => -5, 'kid' => (2**33) }.each do |field, value|
      data = base.merge(field => value)
      assert_raises(KiwiCaptcha::MalformedRecordError, field) { KiwiCaptcha::Record.from_json(data) }
    end
    # target_bits is range-checked by the verifier's structural gate,
    # not the serde parser (the serde range is the u32 wire bound).
    data = base.merge('target_bits' => 99)
    parsed = KiwiCaptcha::Record.from_json(data)
    assert_equal 99, parsed.target_bits
    refute KiwiCaptcha::Verify.validate_record(parsed)
  end

  def test_algorithm_is_exact
    data = KiwiCaptcha::Record.to_json_record(golden_record('sha_plain'))
    data['algorithm'] = 'sha-256'
    assert_raises(KiwiCaptcha::MalformedRecordError) { KiwiCaptcha::Record.from_json(data) }
  end

  def test_the_legacy_ip_hash_alias_maps_and_conflicts
    record = golden_record('sha_plain')
    data = KiwiCaptcha::Record.to_json_record(record)
    data.delete('binding_tag')
    data['ip_hash'] = 'a' * 64
    parsed = KiwiCaptcha::Record.from_json(data)
    assert_equal 'a' * 64, parsed.binding_tag

    data['binding_tag'] = 'b' * 64
    assert_raises(KiwiCaptcha::MalformedRecordError) { KiwiCaptcha::Record.from_json(data) }
  end

  def test_identifier_and_decoy_grammars
    assert KiwiCaptcha::Record.valid_identifier?('login', 128)
    refute KiwiCaptcha::Record.valid_identifier?('has space', 128)
    refute KiwiCaptcha::Record.valid_identifier?('x' * 129, 128)
    assert KiwiCaptcha::Record.valid_decoy_field_name?('decoy_field_a1b2c3d4e5f60718')
    refute KiwiCaptcha::Record.valid_decoy_field_name?('has space')
    refute KiwiCaptcha::Record.valid_decoy_field_name?('x' * 65)
  end

  def test_protocol_grammar_matrix
    ok = KiwiCaptcha::Record.method(:protocol_extension_grammar_ok?)
    assert ok.call(1, false, false, false)
    refute ok.call(1, false, false, true)
    assert ok.call(2, false, false, false)
    refute ok.call(2, true, false, false)
    assert ok.call(3, true, false, false)
    refute ok.call(3, false, false, false)
    assert ok.call(4, false, true, false)
    refute ok.call(4, false, false, false)
    assert ok.call(5, false, false, true)
    refute ok.call(6, false, false, false)
  end

  def test_execution_triplet_must_be_complete_and_consistent
    record = golden_record('sha_execution_v4')
    data = KiwiCaptcha::Record.to_json_record(record)
    parsed = KiwiCaptcha::Record.from_json(data)
    assert_equal 1, parsed.execution_version
    data.delete('execution_commitment')
    assert_raises(KiwiCaptcha::MalformedRecordError) { KiwiCaptcha::Record.from_json(data) }

    data = KiwiCaptcha::Record.to_json_record(record)
    data['execution_commitment'] = 'f' * 64
    assert_raises(KiwiCaptcha::MalformedRecordError) { KiwiCaptcha::Record.from_json(data) }
  end

  def test_hostname_grammar
    data = KiwiCaptcha::Record.to_json_record(golden_record('sha_plain'))
    data['hostname'] = ''
    assert_raises(KiwiCaptcha::MalformedRecordError) { KiwiCaptcha::Record.from_json(data) }
    data['hostname'] = "bad\x01host"
    assert_raises(KiwiCaptcha::MalformedRecordError) { KiwiCaptcha::Record.from_json(data) }
  end
end
