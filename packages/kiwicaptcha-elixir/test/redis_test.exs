# The gated Redis suite: the exactly-once and replay vectors of the
# shared store contract run live against a reachable server, and the
# whole module collapses to one skipped placeholder when the server is
# absent (set KIWI_REDIS_URL to point elsewhere). The gate is a
# compile-time reachability probe, because ExUnit has no runtime skip.
redis_url = System.get_env("KIWI_REDIS_URL", "redis://127.0.0.1:6379/15")

reachable? =
  try do
    {:ok, c} = Redix.start_link(redis_url, sync_connect: true)
    "PONG" = Redix.command!(c, ["PING"])
    GenServer.stop(c)
    true
  rescue
    _ -> false
  catch
    :exit, _ -> false
  end

unless reachable? do
  defmodule Kiwicaptcha.RedisStoreTest do
    @moduledoc false
    use ExUnit.Case, async: false

    @tag :skip
    test "the redis suite needs a reachable server (set KIWI_REDIS_URL)"
  end
end

if reachable? do
  defmodule Kiwicaptcha.RedisStoreTest do
    use ExUnit.Case, async: false

    import Kiwicaptcha.TestSupport

    @url redis_url

    # One connection per test process, flushed around every test so
    # the vectors never see each other's rows. The test process takes
    # its linked client down with it, so the trailing flush opens a
    # fresh short-lived one and never fails the suite.
    setup do
      {:ok, c} = Redix.start_link(@url)
      Redix.command!(c, ["FLUSHDB"])

      on_exit(fn ->
        try do
          {:ok, c2} = Redix.start_link(@url, sync_connect: true)
          Redix.command!(c2, ["FLUSHDB"])
          GenServer.stop(c2)
        rescue
          _ -> :ok
        end
      end)

      {:ok, client: c}
    end

    def golden_sha do
      row = golden_record("sha_plain")
      %{record: record_from_row(row), token: row["token_b64"]}
    end

    def store(c) do
      Kiwicaptcha.Stores.Redis.new(c, now: fn -> 0 end)
    end

    test "the consume transition is exactly once", %{client: c} do
      record = golden_sha().record
      store = store(c)
      store.store.(record)

      first = store.consume.(record.nonce, nil)
      refute first == nil
      assert first.consumed_now
      refute first.consumed_before

      second = store.consume.(record.nonce, nil)
      refute second == nil
      refute second.consumed_now
      assert second.consumed_before

      assert store.commit_result.(record.nonce, true, nil, String.duplicate("a", 64)) == true
      assert store.commit_result.(record.nonce, false, nil, nil) == false

      retained = store.runtime_state.(record.nonce)
      assert retained.kind == :consumed
      assert retained.consumed.consumed_result.valid == true
    end

    test "replay across the full verify path is deterministic", %{client: c} do
      golden = golden_sha()
      store = store(c)
      store.store.(golden.record)
      opts = row_opts(golden_record("sha_plain"), golden.record, store)

      assert Kiwicaptcha.verify(golden.token, opts).ok
      assert Kiwicaptcha.verify(golden.token, opts).code == :already_consumed
    end

    test "the operation identity splices atomically with the flip", %{client: c} do
      record = golden_sha().record
      store = store(c)
      store.store.(record)

      won = store.consume.(record.nonce, "op-redis")
      assert won.consumed_now
      assert won.operation_identity == "op-redis"
      assert store.runtime_state.(record.nonce).consumed.operation_identity == "op-redis"

      # A forged rollback rewrite can never flip: the pending marker
      # guard inside the script.
      raw = Redix.command!(c, ["GET", "kiwicaptcha:#{record.nonce}"])
      {:ok, decoded} = Kiwicaptcha.Json.decode(raw)

      Redix.command!(c, [
        "SET",
        "kiwicaptcha:#{record.nonce}",
        Kiwicaptcha.Json.encode!(Map.put(decoded, "state", "pending"))
      ])

      assert store.consume.(record.nonce, nil) == nil
    end

    test "delete if pending keeps consumed evidence and deletes only pending", %{client: c} do
      golden = golden_sha()
      store = store(c)
      store.store.(golden.record)

      assert store.delete_if_pending.(golden.record.nonce).kind == :deleted_pending
      assert store.find.(golden.record.nonce) == nil
      assert store.delete_if_pending.(golden.record.nonce).kind == :missing

      store.store.(golden.record)
      store.consume.(golden.record.nonce, "op-2")
      cleanup = store.delete_if_pending.(golden.record.nonce)
      assert cleanup.kind == :consumed
      assert cleanup.consumed.operation_identity == "op-2"
      refute store.find.(golden.record.nonce) == nil
    end

    test "racing consumers produce exactly one winner", %{client: c} do
      record = golden_sha().record
      store = store(c)
      store.store.(record)

      winners =
        Task.async_stream(1..12, fn _ -> store.consume.(record.nonce, nil) end,
          max_concurrency: 12,
          timeout: 10_000
        )
        |> Enum.map(fn {:ok, value} -> value end)

      won = Enum.count(winners, fn entry -> entry && entry.consumed_now end)
      assert won == 1
    end

    test "commit result preserves the remaining ttl", %{client: c} do
      record = golden_sha().record
      live = Kiwicaptcha.Stores.Redis.new(c, now: fn -> record.issued_at end)
      live.store.(record)
      live.consume.(record.nonce, nil)
      assert Redix.command!(c, ["TTL", "kiwicaptcha:#{record.nonce}"]) > 100
      live.commit_result.(record.nonce, true, nil, String.duplicate("a", 64))
      assert Redix.command!(c, ["TTL", "kiwicaptcha:#{record.nonce}"]) > 100
    end

    test "store ttl lands inside the retention margin", %{client: c} do
      record = golden_sha().record
      live = Kiwicaptcha.Stores.Redis.new(c, now: fn -> record.issued_at end)
      live.store.(record)

      ttl = Redix.command!(c, ["TTL", "kiwicaptcha:#{record.nonce}"])

      expected =
        record.expires_at - record.issued_at + Kiwicaptcha.Store.default_ttl_margin_secs()

      assert abs(ttl - expected) <= 2
    end
  end
end
