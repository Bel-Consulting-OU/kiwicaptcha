# frozen_string_literal: true

require_relative 'helper'
require 'tmpdir'
require 'fileutils'
require 'sqlite3'

# The consume exactly-once and replay contract, shared by every store
# adapter: memory (natural, no interleaving point) and SQLite (a
# begin-immediate transition on a temp file). Redis runs the same
# vectors live in test_redis_store.rb.
class StoresTest < Minitest::Test
  include TestSupport

  FROZEN = { now: -> { 0 } }

  def golden_sha
    row = TestSupport.golden_record('sha_plain')
    { record: TestSupport.record_from_row(row), token: row['token_b64'], row: row }
  end

  def frozen_verify(store, record, extra = {})
    TestSupport.verify_options(
      { storage: store, secret_key: SECRET }.merge(TestSupport.frozen_clock(record)).merge(extra)
    )
  end

  # The store factory: memory hands every caller the same instance
  # (the map is shared); SQLite opens one connection per caller, the
  # shape real deployments run, so the begin-immediate lock serializes
  # writers the way production consumes actually race.
  def make_store_factory(kind)
    if kind == :memory
      store = KiwiCaptcha::MemoryStore.new(**FROZEN)
      [-> { store }, -> {}]
    else
      dir = Dir.mktmpdir('kiwi-sqlite-')
      path = File.join(dir, 'kiwi.db')
      KiwiCaptcha::SqliteStore.new(SQLite3::Database.new(path), **FROZEN) # schema init
      factory = -> { KiwiCaptcha::SqliteStore.new(SQLite3::Database.new(path), **FROZEN) }
      [factory, -> { FileUtils.rm_rf(dir) }]
    end
  end

  [:memory, :sqlite].each do |kind|
    define_method("test_#{kind}_the_consume_transition_is_exactly_once") do
      factory, dispose = make_store_factory(kind)
      store = factory.call
      record = golden_sha[:record]
      store.store(record)
      first = store.consume(record.nonce)
      refute_nil first
      assert first.consumed_now
      refute first.consumed_before
      second = store.consume(record.nonce)
      refute_nil second
      refute second.consumed_now
      assert second.consumed_before
      assert_equal true, store.commit_result(record.nonce, true, nil, 'a' * 64)
      assert_equal false, store.commit_result(record.nonce, false, nil, nil)
      retained = store.runtime_state(record.nonce)
      assert_equal 'consumed', retained.kind
      assert_equal true, retained.consumed.consumed_result.valid
      dispose.call
    end

    define_method("test_#{kind}_replay_across_the_full_verify_path_is_deterministic") do
      factory, dispose = make_store_factory(kind)
      store = factory.call
      golden = golden_sha
      store.store(golden[:record])
      clock = TestSupport.frozen_clock(golden[:record])
      first = KiwiCaptcha.verify(golden[:token], TestSupport.verify_options(storage: store, secret_key: SECRET, **clock))
      assert first.ok
      replay = KiwiCaptcha.verify(golden[:token], TestSupport.verify_options(storage: store, secret_key: SECRET, **clock))
      assert_equal 'already_consumed', replay.code
      idem = KiwiCaptcha.verify(
        golden[:token],
        TestSupport.verify_options(storage: store, secret_key: SECRET, **clock, operation_identity: 'op-1')
      )
      assert_equal 'already_consumed', idem.code
      dispose.call
    end

    define_method("test_#{kind}_delete_if_pending_keeps_consumed_evidence_and_deletes_only_pending") do
      factory, dispose = make_store_factory(kind)
      store = factory.call
      golden = golden_sha
      store.store(golden[:record])
      assert_equal 'deleted_pending', store.delete_if_pending(golden[:record].nonce).kind
      assert_nil store.find(golden[:record].nonce)
      assert_equal 'missing', store.delete_if_pending(golden[:record].nonce).kind

      store.store(golden[:record])
      store.consume(golden[:record].nonce, 'op-2')
      cleanup = store.delete_if_pending(golden[:record].nonce)
      assert_equal 'consumed', cleanup.kind
      assert_equal 'op-2', cleanup.consumed.operation_identity
      refute_nil store.find(golden[:record].nonce)

      result = KiwiCaptcha.verify(
        golden[:token],
        TestSupport.verify_options(
          storage: store, secret_key: SECRET,
          **TestSupport.frozen_clock(golden[:record]), operation_identity: 'op-2'
        )
      )
      assert_equal 'consume_indeterminate', result.code
      dispose.call
    end

    define_method("test_#{kind}_expired_rows_are_absent_to_every_read") do
      record = golden_sha[:record]
      live = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
      live.store(record)
      refute_nil live.find(record.nonce)
      refute_nil live.consume(record.nonce)

      past = record.expires_at + 61
      if kind == :memory
        shifted = KiwiCaptcha::MemoryStore.new(now: -> { past })
        shifted.store(record)
        assert_nil shifted.find(record.nonce)
        assert_nil shifted.consume(record.nonce)
      else
        dir = Dir.mktmpdir('kiwi-sqlite-exp-')
        begin
          db = SQLite3::Database.new(File.join(dir, 'kiwi.db'))
          shifted = KiwiCaptcha::SqliteStore.new(db, now: -> { past })
          shifted.store(record)
          assert_nil shifted.find(record.nonce)
          assert_nil shifted.consume(record.nonce)
        ensure
          FileUtils.rm_rf(dir)
        end
      end
    end

    define_method("test_#{kind}_a_pending_envelope_carrying_markers_is_refused_as_forged") do
      factory, dispose = make_store_factory(kind)
      store = factory.call
      record = golden_sha[:record]
      store.store(record)
      store.consume(record.nonce, 'op-x')
      # Move the row back to pending while keeping the identity: the
      # classic rollback rewrite must never flip.
      if kind == :memory
        row = store.instance_variable_get(:@rows)[record.nonce]
        envelope = JSON.parse(row.envelope_json)
        envelope['state'] = 'pending'
        row.envelope_json = JSON.generate(envelope)
        row.state = 'pending'
      else
        raw_db = store.instance_variable_get(:@db)
        raw_db.execute('UPDATE kiwicaptcha_challenge_records SET state = ? WHERE nonce = ?', ['pending', record.nonce])
      end
      assert_nil store.consume(record.nonce)
      dispose.call
    end

    define_method("test_#{kind}_racing_consumers_produce_exactly_one_winner") do
      factory, dispose = make_store_factory(kind)
      seed = factory.call
      record = golden_sha[:record]
      seed.store(record)
      winners = Array.new(12) { Thread.new { factory.call.consume(record.nonce) } }.map(&:value)
      won = winners.count { |entry| entry && entry.consumed_now }
      assert_equal 1, won

      golden = golden_sha
      seed.store(golden[:record])
      clock = TestSupport.frozen_clock(golden[:record])
      results = Array.new(8) do
        Thread.new do
          KiwiCaptcha.verify(golden[:token], TestSupport.verify_options(storage: factory.call, secret_key: SECRET, **clock))
        end
      end.map(&:value)
      ok_count = results.count(&:ok)
      assert_operator ok_count, :>=, 1
      assert_operator ok_count, :<=, 1, "at most one verifier may win, saw #{ok_count}"
      dispose.call
    end
  end

  def test_the_sqlite_schema_guard_refuses_a_newer_database
    dir = Dir.mktmpdir('kiwi-sqlite-guard-')
    begin
      db = SQLite3::Database.new(File.join(dir, 'kiwi.db'))
      db.execute('PRAGMA user_version = 99')
      assert_raises(KiwiCaptcha::StoreUnavailableError) { KiwiCaptcha::SqliteStore.new(db) }
      db.close
    ensure
      FileUtils.rm_rf(dir)
    end
  end

  def test_the_operation_identity_is_written_atomically_with_the_flip
    record = golden_sha[:record]
    live = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
    live.store(record)
    won = live.consume(record.nonce, 'op-atomic')
    refute_nil won
    assert won.consumed_now
    assert_equal 'op-atomic', won.operation_identity
    retained = live.runtime_state(record.nonce)
    assert_equal 'op-atomic', retained.consumed.operation_identity
  end

  def test_an_invalid_operation_identity_throws_before_any_transition
    record = golden_sha[:record]
    live = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
    live.store(record)
    assert_raises(RangeError) { live.consume(record.nonce, 'not valid!') }
    assert_equal 'pending', live.runtime_state(record.nonce).kind
  end

  def test_a_ttl_margin_guard_refuses_negative_values
    assert_raises(RangeError) { KiwiCaptcha::MemoryStore.new(ttl_margin_secs: -1) }
    assert_raises(RangeError) { KiwiCaptcha::RedisStore.new(nil, ttl_margin_secs: -1) }
  end
end
