# frozen_string_literal: true

require_relative 'helper'

# The Argon2id binding probe and the golden solved-proof vector: the
# probe must ask for the derivation entry point (never the module name
# alone), and the PHP-issued golden argon2id proof must re-derive
# through the native gem in CI. The gem is optional, so its absence
# skips the vector loudly instead of silently passing a suite that
# proved nothing.
class Argon2BindingTest < Minitest::Test
  include TestSupport

  def test_the_probe_requires_the_raw_derivation_entry_point
    refute KiwiCaptcha::Pow.argon2_entry_point?(nil)
    refute KiwiCaptcha::Pow.argon2_entry_point?(Module.new),
           'a module without argon2id_hash_raw can never derive'
    half_broken = Module.new
    refute KiwiCaptcha::Pow.argon2_entry_point?(half_broken)
    usable = Module.new
    usable.define_singleton_method(:argon2id_hash_raw) { |*| 0 }
    assert KiwiCaptcha::Pow.argon2_entry_point?(usable)
  end

  def test_the_probe_matches_the_entry_point_of_the_loaded_gem
    available = KiwiCaptcha::Pow.argon2_available?
    skip 'the argon2 gem is not installed' unless defined?(::Argon2::Ext)

    assert_equal ::Argon2::Ext.respond_to?(:argon2id_hash_raw), available,
                 'the availability flag is the entry point, never the module name'
  end

  def test_golden_solved_proof_vector_derives_through_the_binding
    unless KiwiCaptcha::Pow.argon2_available?
      skip 'the argon2 gem is not installed (CI installs it to run the golden Argon2id solved-proof vector)'
    end

    row = TestSupport.golden_record('argon2id')
    record = TestSupport.record_from_row(row)
    token = KiwiCaptcha::Token.decode(row['token_b64'])
    salt_bytes = KiwiCaptcha::Base64Utils.decode_std(record.salt)
    refute_nil salt_bytes, 'the golden salt is canonical base64'

    hash = KiwiCaptcha::Pow.derive_argon2id_hash(
      "#{record.prefix}#{token.counter}", salt_bytes,
      record.t, record.m_kib, record.p, 32
    )
    refute_nil hash, 'the golden derivation must compute through the binding'
    assert_equal 32, hash.bytesize
    assert KiwiCaptcha::Pow.meets_target?(hash, record.target_bits),
           "the golden solved counter #{token.counter} must meet the record's #{record.target_bits}-bit target"

    # The end-to-end verify accepts the same solved proof as a fresh
    # derivation — the vector pins both the binding and the verdict.
    storage = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
    storage.store(record)
    result = KiwiCaptcha.verify(
      row['token_b64'],
      TestSupport.verify_options(
        storage: storage,
        secret_key: TestSupport.golden['hkdf']['secret'],
        expected_scope: row['verify_opts']['expected_scope'],
        **TestSupport.frozen_clock(record)
      )
    )
    assert result.ok, result.code
    refute result.from_stored_result
  end
end
