# frozen_string_literal: true

require_relative 'helper'

begin
  require 'redis'
rescue LoadError
  # The optional backend stays optional: the suite skips without it.
end

# The Redis adapter over a live server when one is reachable: the
# exactly-once and replay vectors of the shared store contract, plus
# the envelope guard and the TTL preservation. Skips cleanly when the
# redis gem or the server is absent, so the suite stays runnable
# everywhere.
class RedisStoreTest < Minitest::Test
  include TestSupport

  def self.redis_available?
    return false unless defined?(Redis)

    @redis_available ||= begin
      client = Redis.new(url: ENV.fetch('KIWI_REDIS_URL', 'redis://127.0.0.1:6379/15'), reconnect_attempts: 0)
      client.ping == 'PONG'
    rescue StandardError
      false
    end
  end

  def client
    @client ||= Redis.new(url: ENV.fetch('KIWI_REDIS_URL', 'redis://127.0.0.1:6379/15'))
  end

  def setup
    skip 'the redis gem is not installed' unless defined?(Redis)
    skip 'no reachable redis server' unless self.class.redis_available?
    client.flushdb
  end

  def teardown
    client.flushdb if defined?(Redis) && self.class.redis_available?
  end

  def golden_sha
    row = TestSupport.golden_record('sha_plain')
    { record: TestSupport.record_from_row(row), token: row['token_b64'] }
  end

  def store
    @store ||= KiwiCaptcha::RedisStore.new(client, now: -> { 0 })
  end

  def test_the_consume_transition_is_exactly_once
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
  end

  def test_replay_across_the_full_verify_path_is_deterministic
    golden = golden_sha
    store.store(golden[:record])
    clock = TestSupport.frozen_clock(golden[:record])
    first = KiwiCaptcha.verify(golden[:token], TestSupport.verify_options(storage: store, secret_key: SECRET, **clock))
    assert first.ok
    replay = KiwiCaptcha.verify(golden[:token], TestSupport.verify_options(storage: store, secret_key: SECRET, **clock))
    assert_equal 'already_consumed', replay.code
  end

  def test_the_operation_identity_splices_atomically_with_the_flip
    record = golden_sha[:record]
    store.store(record)
    won = store.consume(record.nonce, 'op-redis')
    assert won.consumed_now
    assert_equal 'op-redis', won.operation_identity
    retained = store.runtime_state(record.nonce)
    assert_equal 'op-redis', retained.consumed.operation_identity
    # A forged rollback rewrite can never flip: the pending marker
    # guard inside the script.
    raw = client.get("kiwicaptcha:#{record.nonce}")
    client.set("kiwicaptcha:#{record.nonce}", JSON.parse(raw).merge('state' => 'pending').to_json)
    assert_nil store.consume(record.nonce)
  end

  def test_delete_if_pending_keeps_consumed_evidence_and_deletes_only_pending
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
  end

  def test_racing_consumers_produce_exactly_one_winner
    record = golden_sha[:record]
    store.store(record)
    winners = Array.new(12) { Thread.new { store.consume(record.nonce) } }.map(&:value)
    won = winners.count { |entry| entry && entry.consumed_now }
    assert_equal 1, won
  end

  def test_commit_result_preserves_the_remaining_ttl
    record = golden_sha[:record]
    live = KiwiCaptcha::RedisStore.new(client, now: -> { record.issued_at })
    live.store(record)
    live.consume(record.nonce)
    assert_operator client.ttl("kiwicaptcha:#{record.nonce}"), :>, 100
    live.commit_result(record.nonce, true, nil, 'a' * 64)
    assert_operator client.ttl("kiwicaptcha:#{record.nonce}"), :>, 100
  end

  def test_store_ttl_lands_inside_the_retention_margin
    record = golden_sha[:record]
    live = KiwiCaptcha::RedisStore.new(client, now: -> { record.issued_at })
    live.store(record)
    ttl = client.ttl("kiwicaptcha:#{record.nonce}")
    expected = record.expires_at - record.issued_at + KiwiCaptcha::Store::DEFAULT_TTL_MARGIN_SECS
    assert_in_delta expected, ttl, 2
  end
end
