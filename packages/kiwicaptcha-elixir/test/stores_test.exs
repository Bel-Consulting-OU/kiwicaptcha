defmodule Kiwicaptcha.StoresTest do
  use ExUnit.Case, async: false

  import Kiwicaptcha.TestSupport

  # The consume exactly-once and replay contract, shared by every store
  # adapter: memory (a GenServer, no interleaving point) and SQLite
  # (a begin-immediate transition on a temp file). Redis runs the same
  # vectors live in redis_test.exs.
  def golden_sha do
    row = golden_record("sha_plain")
    %{record: record_from_row(row), token: row["token_b64"]}
  end

  def verify_opts(store, record, extra \\ %{}) do
    base_options(storage: store, secret_key: secret())
    |> Map.merge(Map.new(frozen_clock(record)))
    |> Map.merge(Map.new(extra))
  end

  def make_store_factory(:memory) do
    {:ok, pid} = Kiwicaptcha.Stores.Memory.start(now: fn -> 0 end)
    adapter = Kiwicaptcha.Stores.Memory.adapter(pid)

    # The rollback surgery flips the envelope state back to pending
    # while keeping the identity marker.
    surgery = fn nonce ->
      :sys.replace_state(pid, fn state ->
        %{
          state
          | rows:
              Map.update!(state.rows, nonce, fn row ->
                %{
                  row
                  | json: String.replace(row.json, ~s("state":"consumed"), ~s("state":"pending"))
                }
              end)
        }
      end)
    end

    %{
      factory: fn -> adapter end,
      seed: fn record -> Kiwicaptcha.Stores.Memory.store(pid, record) end,
      surgery: surgery,
      dispose: fn -> :ok end
    }
  end

  def make_store_factory(:sqlite) do
    unless Kiwicaptcha.Support.ExqliteDriver.available?() do
      raise "exqlite missing"
    end

    dir = Path.join(System.tmp_dir!(), "kiwi-sqlite-#{System.unique_integer()}")
    File.mkdir_p!(dir)
    {:ok, db} = Kiwicaptcha.Support.ExqliteDriver.open(Path.join(dir, "kiwi.db"))

    inner =
      Kiwicaptcha.Stores.Sqlite.raw(db,
        exec: &Kiwicaptcha.Support.ExqliteDriver.exec/3,
        now: fn -> 0 end
      )

    :ok = Kiwicaptcha.Stores.Sqlite.initialize(inner)

    adapter =
      Kiwicaptcha.Stores.Sqlite.new(db,
        exec: &Kiwicaptcha.Support.ExqliteDriver.exec/3,
        now: fn -> 0 end
      )

    surgery = fn nonce ->
      {:ok, _} =
        Kiwicaptcha.Support.ExqliteDriver.exec(
          db,
          "UPDATE kiwicaptcha_challenge_records SET state = 'pending' WHERE nonce = ?1",
          [nonce]
        )

      :ok
    end

    %{
      factory: fn -> adapter end,
      seed: fn record -> Kiwicaptcha.Stores.Sqlite.store(inner, record) end,
      surgery: surgery,
      dispose: fn ->
        Kiwicaptcha.Support.ExqliteDriver.close(db)
        File.rm_rf!(dir)
      end
    }
  end

  describe "memory store" do
    test "the consume transition is exactly once", do: run_suite(:memory, "exactly_once")
    test "replay across the full verify path is deterministic", do: run_suite(:memory, "replay")

    test "delete if pending keeps consumed evidence and deletes only pending",
      do: run_suite(:memory, "delete_if_pending")

    test "expired rows are absent to every read", do: run_suite(:memory, "expired")

    test "a pending envelope carrying markers is refused as forged",
      do: run_suite(:memory, "forged")

    test "racing consumers produce exactly one winner", do: run_suite(:memory, "racing")
  end

  describe "sqlite store" do
    test "the consume transition is exactly once", do: run_suite(:sqlite, "exactly_once")
    test "replay across the full verify path is deterministic", do: run_suite(:sqlite, "replay")

    test "delete if pending keeps consumed evidence and deletes only pending",
      do: run_suite(:sqlite, "delete_if_pending")

    test "expired rows are absent to every read", do: run_suite(:sqlite, "expired")

    test "a pending envelope carrying markers is refused as forged",
      do: run_suite(:sqlite, "forged")

    test "racing consumers produce exactly one winner", do: run_suite(:sqlite, "racing")
  end

  # The shared scenario runner: one function per scenario, parameterized
  # over the store kind so both adapters run the identical vectors.
  def run_suite(kind, "exactly_once"), do: suite_exactly_once(kind)
  def run_suite(kind, "replay"), do: suite_replay(kind)
  def run_suite(kind, "delete_if_pending"), do: suite_delete_if_pending(kind)
  def run_suite(kind, "expired"), do: suite_expired(kind)
  def run_suite(kind, "forged"), do: suite_forged(kind)
  def run_suite(kind, "racing"), do: suite_racing(kind)

  defp suite_exactly_once(kind) do
    %{factory: factory, seed: seed, dispose: dispose} = make_store_factory(kind)
    store = factory.()
    golden = golden_sha()
    seed.(golden.record)

    first = store.consume.(golden.record.nonce, nil)
    refute first == nil
    assert first.consumed_now
    refute first.consumed_before

    second = store.consume.(golden.record.nonce, nil)
    refute second == nil
    refute second.consumed_now
    assert second.consumed_before

    assert store.commit_result.(golden.record.nonce, true, nil, String.duplicate("a", 64)) == true
    assert store.commit_result.(golden.record.nonce, false, nil, nil) == false
    retained = store.runtime_state.(golden.record.nonce)
    assert retained.kind == :consumed
    assert retained.consumed.consumed_result.valid == true
    dispose.()
  end

  defp suite_replay(kind) do
    %{factory: factory, seed: seed, dispose: dispose} = make_store_factory(kind)
    store = factory.()
    golden = golden_sha()
    seed.(golden.record)

    assert Kiwicaptcha.verify(golden.token, verify_opts(store, golden.record)).ok

    replay = Kiwicaptcha.verify(golden.token, verify_opts(store, golden.record))
    assert replay.code == :already_consumed

    idem =
      Kiwicaptcha.verify(
        golden.token,
        verify_opts(store, golden.record, %{operation_identity: "op-1"})
      )

    assert idem.code == :already_consumed
    dispose.()
  end

  defp suite_delete_if_pending(kind) do
    %{factory: factory, dispose: dispose} = make_store_factory(kind)
    store = factory.()
    golden = golden_sha()
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

    result =
      Kiwicaptcha.verify(
        golden.token,
        verify_opts(store, golden.record, %{operation_identity: "op-2"})
      )

    assert result.code == :consume_indeterminate
    dispose.()
  end

  defp suite_expired(:memory) do
    golden = golden_sha()
    record = golden.record
    past = record.expires_at + 61
    {:ok, pid} = Kiwicaptcha.Stores.Memory.start(now: fn -> past end)
    store = Kiwicaptcha.Stores.Memory.adapter(pid)
    store.store.(record)
    assert store.find.(record.nonce) == nil
    assert store.consume.(record.nonce, nil) == nil
  end

  defp suite_expired(:sqlite) do
    golden = golden_sha()
    record = golden.record
    past = record.expires_at + 61
    {db, dir} = open_sqlite()

    store =
      Kiwicaptcha.Stores.Sqlite.new(db,
        exec: &Kiwicaptcha.Support.ExqliteDriver.exec/3,
        now: fn -> past end
      )

    store.store.(record)
    assert store.find.(record.nonce) == nil
    assert store.consume.(record.nonce, nil) == nil
    Kiwicaptcha.Support.ExqliteDriver.close(db)
    File.rm_rf!(dir)
  end

  defp suite_forged(kind) do
    %{factory: factory, seed: seed, surgery: surgery, dispose: dispose} = make_store_factory(kind)
    store = factory.()
    golden = golden_sha()
    seed.(golden.record)
    store.consume.(golden.record.nonce, "op-x")
    # Move the row back to pending while keeping the identity: the
    # classic rollback rewrite must never flip.
    surgery.(golden.record.nonce)
    assert store.consume.(golden.record.nonce, nil) == nil
    dispose.()
  end

  defp suite_racing(kind) do
    %{factory: factory, seed: seed, dispose: dispose} = make_store_factory(kind)
    store = factory.()
    golden = golden_sha()
    seed.(golden.record)

    winners =
      Task.async_stream(1..12, fn _ -> store.consume.(golden.record.nonce, nil) end,
        max_concurrency: 12,
        timeout: 10_000
      )
      |> Enum.map(fn {:ok, value} -> value end)

    won = Enum.count(winners, fn entry -> entry && entry.consumed_now end)
    assert won == 1

    seed.(golden.record)

    results =
      Task.async_stream(
        1..8,
        fn _ -> Kiwicaptcha.verify(golden.token, verify_opts(store, golden.record)) end,
        max_concurrency: 8,
        timeout: 10_000
      )
      |> Enum.map(fn {:ok, value} -> value end)

    ok_count = Enum.count(results, & &1.ok)
    assert ok_count >= 1
    assert ok_count <= 1, "at most one verifier may win, saw #{ok_count}"
    dispose.()
  end

  defp open_sqlite do
    dir = Path.join(System.tmp_dir!(), "kiwi-sqlite-#{System.unique_integer()}")
    File.mkdir_p!(dir)
    {:ok, db} = Kiwicaptcha.Support.ExqliteDriver.open(Path.join(dir, "kiwi.db"))
    {db, dir}
  end

  test "the sqlite schema guard refuses a newer database" do
    unless Kiwicaptcha.Support.ExqliteDriver.available?() do
      raise "exqlite missing"
    end

    dir = Path.join(System.tmp_dir!(), "kiwi-sqlite-guard-#{System.unique_integer()}")
    File.mkdir_p!(dir)
    {:ok, db} = Kiwicaptcha.Support.ExqliteDriver.open(Path.join(dir, "kiwi.db"))
    {:ok, _} = Kiwicaptcha.Support.ExqliteDriver.exec(db, "PRAGMA user_version = 99", [])

    assert_raise Kiwicaptcha.StoreUnavailableError, fn ->
      # new/2 initializes eagerly, so the guard fires before it can
      # return an adapter.
      Kiwicaptcha.Stores.Sqlite.new(db, exec: &Kiwicaptcha.Support.ExqliteDriver.exec/3)
    end

    Kiwicaptcha.Support.ExqliteDriver.close(db)
    File.rm_rf!(dir)
  end

  test "the operation identity is written atomically with the flip" do
    golden = golden_sha()
    record = golden.record
    {:ok, pid} = Kiwicaptcha.Stores.Memory.start(now: fn -> record.issued_at + 10 end)
    store = Kiwicaptcha.Stores.Memory.adapter(pid)
    store.store.(record)
    won = store.consume.(record.nonce, "op-atomic")
    refute won == nil
    assert won.consumed_now
    assert won.operation_identity == "op-atomic"
    retained = store.runtime_state.(record.nonce)
    assert retained.consumed.operation_identity == "op-atomic"
  end

  test "an invalid operation identity throws before any transition" do
    golden = golden_sha()
    record = golden.record
    {:ok, pid} = Kiwicaptcha.Stores.Memory.start(now: fn -> record.issued_at + 10 end)
    store = Kiwicaptcha.Stores.Memory.adapter(pid)
    store.store.(record)

    assert_raise Kiwicaptcha.RangeError, fn ->
      store.consume.(record.nonce, "not valid!")
    end

    assert store.runtime_state.(record.nonce).kind == :pending
  end
end
