defmodule Kiwicaptcha.Stores.SqliteDriver.Exqlite do
  @moduledoc """
  The production bridge between the SQLite store adapter and the
  optional exqlite package. `Kiwicaptcha.Settings.open_store/1` calls
  `open/1` for a `sqlite://` or `sqlite:path` URL.

  One raw `Exqlite.Sqlite3` handle permits no interleaved
  transactions: a BEGIN while another transaction is open fails
  outright. Concurrent writers in one BEAM node therefore route their
  statement calls through the single owner process below, and a
  successful `BEGIN` up to its `COMMIT` or `ROLLBACK` is held as one
  unit: racing consumers see the winner's committed state, exactly as
  `BEGIN IMMEDIATE` serializes writers across connections. Skips
  cleanly when the package is absent.
  """

  defstruct [:handle]

  use GenServer

  @doc "Whether the optional exqlite package is loaded."
  def available?, do: Code.ensure_loaded?(Exqlite.Sqlite3)

  @doc """
  Open (or create) a database file and return the store adapter: the
  closure map verify and the doctor consume. Raises ArgumentError with
  the optional-dependency guidance when exqlite is absent.
  """
  def open(path) when is_binary(path) do
    with {:ok, handle} <- open_handle(path) do
      {:ok, Kiwicaptcha.Stores.Sqlite.new(handle, exec: &exec/3)}
    end
  end

  @doc """
  Open (or create) a database file and return the serialized handle
  alone, for callers that compose their own adapter options (a frozen
  test clock, a custom retention margin).
  """
  def open_handle(path) when is_binary(path) do
    unless available?() do
      raise ArgumentError, "the sqlite backend needs the optional exqlite dependency"
    end

    {:ok, db} = Exqlite.Sqlite3.open(path)
    start_link(db)
  end

  @doc "The serialized statement fun the adapter carries."
  def exec(handle, sql, params) do
    GenServer.call(handle, {:exec, sql, params})
  end

  @doc "Stop the owner process and close the database file."
  def close(handle) do
    GenServer.stop(handle, :normal)
  end

  defp start_link(db) do
    GenServer.start_link(__MODULE__, db)
  end

  ## The owner process: serialized statements, transaction-unit locks.

  @impl true
  def init(db) do
    {:ok, %{db: db, owner: nil, monitor: nil, queue: :queue.new()}}
  end

  @impl true
  def handle_call({:exec, sql, params}, from, state) do
    cond do
      state.owner == nil or state.owner == elem(from, 0) ->
        run_direct(sql, params, from, state)

      true ->
        # Another task's statement while a transaction is open: hold
        # the reply until the open transaction settles.
        {:noreply, %{state | queue: :queue.in({from, sql, params}, state.queue)}}
    end
  end

  # The transaction owner died before committing: roll the open
  # transaction back and release the lock, so waiters never hang.
  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{monitor: ref} = state) do
    _ = raw_exec(state.db, "ROLLBACK", [])
    {:noreply, drain(%{state | owner: nil, monitor: nil})}
  end

  def handle_info(_other, state), do: {:noreply, state}

  defp run_direct(sql, params, from, state) do
    result = raw_exec(state.db, sql, params)

    cond do
      transaction_start?(sql) and match?({:ok, _}, result) ->
        monitor = Process.monitor(elem(from, 0))
        GenServer.reply(from, result)
        {:noreply, %{state | owner: elem(from, 0), monitor: monitor}}

      transaction_closed?(sql) and state.owner != nil ->
        Process.demonitor(state.monitor, [:flush])
        GenServer.reply(from, result)
        {:noreply, drain(%{state | owner: nil, monitor: nil})}

      true ->
        GenServer.reply(from, result)
        {:noreply, state}
    end
  end

  defp raw_exec(db, sql, params) do
    case Exqlite.Sqlite3.prepare(db, sql) do
      {:ok, stmt} ->
        :ok = Exqlite.Sqlite3.bind(stmt, params)

        result =
          case Exqlite.Sqlite3.multi_step(db, stmt) do
            {:done, rows} -> {:ok, rows}
            {:rows, rows} -> {:ok, rows}
            {:error, reason} -> {:error, reason}
          end

        Exqlite.Sqlite3.release(db, stmt)
        result

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp transaction_start?(sql) do
    sql |> String.upcase() |> String.trim_leading() |> String.starts_with?("BEGIN")
  end

  defp transaction_closed?(sql) do
    header = sql |> String.upcase() |> String.trim_leading()
    String.starts_with?(header, "COMMIT") or String.starts_with?(header, "ROLLBACK")
  end

  # Serve deferred statements in arrival order. A deferred BEGIN that
  # succeeds becomes the new owner; the rest of the queue stays held
  # until that owner settles its transaction.
  defp drain(%{queue: queue} = state) do
    case :queue.out(queue) do
      {:empty, _} ->
        state

      {{:value, {from, sql, params}}, rest} ->
        result = raw_exec(state.db, sql, params)
        GenServer.reply(from, result)

        if transaction_start?(sql) and match?({:ok, _}, result) do
          monitor = Process.monitor(elem(from, 0))
          %{state | queue: rest, owner: elem(from, 0), monitor: monitor}
        else
          drain(%{state | queue: rest})
        end
    end
  end

  @impl true
  def terminate(_reason, state) do
    if state.monitor, do: Process.demonitor(state.monitor, [:flush])
    if state.owner, do: _ = raw_exec(state.db, "ROLLBACK", [])
    _ = Exqlite.Sqlite3.close(state.db)
    :ok
  end
end
