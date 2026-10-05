defmodule Kiwicaptcha.Stores.Sqlite do
  @moduledoc """
  The SQLite adapter: the zero-infrastructure single-node backend.
  Every durable transition runs inside one begin-immediate transaction
  (the lock taken before the row is read, the commit as the durability
  point). SQLite serializes writers, so two racing consumers of one
  nonce cannot both observe the pending row: exactly one caller wins
  the consume and the loser reads the winner's retained state. The
  column set matches the PHP SqliteStorage table row for row, so one
  database file serves every SDK.

  The connection is duck typed: an `Exqlite.Sqlite3` db pid from the
  optional exqlite package (wrapped through `Exqlite.Connection`-style
  callables), or any module pair answering `open/1` semantics through
  the `driver` option. The bundled test driver exercises the full
  transition logic without a native dependency.
  """

  @behaviour Kiwicaptcha.Store.Behaviour

  @schema_version 1

  @select_row "SELECT nonce, record_json, state, consumed_result_json, operation_identity, retained_until " <>
                "FROM kiwicaptcha_challenge_records WHERE nonce = ?1"

  @doc """
  Wrap a connection. `:exec` is a `(conn, sql, params -> {:ok, rows} |
  {:error, term})` fun; `rows` is a list of lists in column order.
  Transaction control statements flow through the same fun.
  """
  @spec new(term(), keyword()) :: map()
  def new(conn, opts \\ []) do
    inner = raw(conn, opts)
    initialize(inner)

    %{
      store: fn record -> store(inner, record) end,
      find: fn nonce -> find(inner, nonce) end,
      runtime_state: fn nonce -> runtime_state(inner, nonce) end,
      consume: fn nonce, identity -> consume(inner, nonce, identity) end,
      commit_result: fn nonce, valid, binding, mac ->
        commit_result(inner, nonce, valid, binding, mac)
      end,
      delete_if_pending: fn nonce -> delete_if_pending(inner, nonce) end,
      authenticated_result_commit?: fn -> true end
    }
  end

  @doc "The inner connection map: what initialize/1 and the callbacks take."
  @spec raw(term(), keyword()) :: map()
  def raw(conn, opts) do
    %{
      conn: conn,
      exec: Keyword.fetch!(opts, :exec),
      ttl_margin:
        Keyword.get(opts, :ttl_margin_secs, Kiwicaptcha.Store.default_ttl_margin_secs()),
      now: Keyword.get(opts, :now)
    }
  end

  @impl true
  def authenticated_result_commit?, do: true

  @impl true
  def store(adapter, record) do
    json = Kiwicaptcha.Record.to_json(record)
    retained_until = record.expires_at + adapter.ttl_margin

    write_transition(adapter, "challenge issuance", fn ->
      {:ok, _} =
        exec(adapter, "DELETE FROM kiwicaptcha_challenge_records WHERE retained_until <= ?1", [
          store_now(adapter)
        ])

      {:ok, _} =
        exec(
          adapter,
          "INSERT INTO kiwicaptcha_challenge_records " <>
            "(nonce, record_json, state, consumed_result_json, operation_identity, retained_until) " <>
            "VALUES (?1, ?2, ?3, NULL, NULL, ?4) " <>
            "ON CONFLICT(nonce) DO UPDATE SET " <>
            "record_json = excluded.record_json, state = excluded.state, " <>
            "consumed_result_json = excluded.consumed_result_json, " <>
            "operation_identity = excluded.operation_identity, " <>
            "retained_until = excluded.retained_until",
          [record.nonce, json, "pending", retained_until]
        )

      :ok
    end)
  end

  @impl true
  def find(adapter, nonce) do
    case live_row(adapter, nonce) do
      nil -> nil
      row -> row |> decode_row() |> decoded_record()
    end
  end

  @impl true
  def runtime_state(adapter, nonce) do
    case live_row(adapter, nonce) do
      nil ->
        %{kind: :missing, record: nil, consumed: nil}

      row ->
        decoded = decode_row(row)

        cond do
          decoded == nil ->
            # A corrupt row fails closed as missing, never pending.
            %{kind: :missing, record: nil, consumed: nil}

          row.state == "cancelled" ->
            %{kind: :cancelled, record: decoded.record, consumed: nil}

          row.state == "consumed" ->
            %{kind: :consumed, record: decoded.record, consumed: retained_snapshot(decoded)}

          row.state == "pending" ->
            %{kind: :pending, record: decoded.record, consumed: nil}

          true ->
            %{kind: :missing, record: nil, consumed: nil}
        end
    end
  end

  @impl true
  def consume(adapter, nonce, operation_identity) do
    identity = Kiwicaptcha.Store.validated_operation_identity(operation_identity)

    write_transition(adapter, "the pending-to-consumed transition", fn ->
      case live_row(adapter, nonce) do
        nil ->
          nil

        row ->
          decoded = decode_row(row)

          cond do
            decoded == nil ->
              nil

            row.state == "consumed" ->
              retained_snapshot(decoded)

            row.state != "pending" ->
              # A cancelled row is never consumable.
              nil

            row.consumed_result_json != nil or row.operation_identity != nil ->
              # The pending-envelope guard mirrors the Redis script
              # marker check: a pending row carrying a result or
              # identity is a forged rewrite and reports missing.
              nil

            true ->
              {:ok, _} =
                exec(
                  adapter,
                  "UPDATE kiwicaptcha_challenge_records SET state = ?1, operation_identity = ?2 WHERE nonce = ?3",
                  [
                    "consumed",
                    identity,
                    nonce
                  ]
                )

              after_row = row_by_nonce(adapter, nonce)

              if after_row == nil or after_row.state != "consumed" or
                   (identity != nil and after_row.operation_identity != identity) do
                raise Kiwicaptcha.StoreWriteError,
                  message:
                    "the consume transition could not record the operation identity on the flipped row"
              end

              %{
                record: decoded.record,
                consumed_now: true,
                consumed_before: false,
                consumed_result: nil,
                operation_identity: identity
              }
          end
      end
    end)
  end

  @impl true
  def commit_result(adapter, nonce, valid, binding, mac) do
    result_map = %{"valid" => valid, "binding" => binding}
    result_map = if mac, do: Map.put(result_map, "mac", mac), else: result_map
    result_json = encode_json(result_map)

    write_transition(adapter, "the result commit", fn ->
      case live_row(adapter, nonce) do
        nil ->
          false

        row ->
          if decode_row(row) == nil or row.state != "consumed" or row.consumed_result_json != nil do
            false
          else
            {:ok, _} =
              exec(
                adapter,
                "UPDATE kiwicaptcha_challenge_records SET consumed_result_json = ?1 WHERE nonce = ?2",
                [
                  result_json,
                  nonce
                ]
              )

            true
          end
      end
    end)
  end

  @impl true
  def delete_if_pending(adapter, nonce) do
    write_transition(adapter, "the delete-if-pending transition", fn ->
      case live_row(adapter, nonce) do
        nil ->
          %{kind: :missing, consumed: nil}

        row ->
          decoded = decode_row(row)

          cond do
            decoded == nil ->
              %{kind: :corrupt, consumed: nil}

            row.state == "consumed" ->
              %{kind: :consumed, consumed: retained_snapshot(decoded)}

            row.state == "cancelled" ->
              %{kind: :cancelled, consumed: nil}

            row.state == "pending" ->
              {:ok, _} =
                exec(adapter, "DELETE FROM kiwicaptcha_challenge_records WHERE nonce = ?1", [
                  nonce
                ])

              %{kind: :deleted_pending, consumed: nil}

            true ->
              %{kind: :corrupt, consumed: nil}
          end
      end
    end)
  end

  defp encode_json(value) do
    case Kiwicaptcha.Json.encode(value) do
      {:ok, doc} -> doc
      :error -> raise "json encode failed"
    end
  end

  defp exec(adapter, sql, params) do
    case adapter.exec.(adapter.conn, sql, params) do
      {:ok, _} = ok ->
        ok

      {:error, reason} ->
        raise Kiwicaptcha.StoreUnavailableError,
          message: "sqlite storage failure: #{inspect(reason)}"
    end
  end

  defp write_transition(adapter, what, fun) do
    try do
      {:ok, _} = exec(adapter, "BEGIN IMMEDIATE", [])
    rescue
      e in [Kiwicaptcha.StoreUnavailableError] ->
        raise e

      e ->
        raise Kiwicaptcha.StoreUnavailableError,
          message: "sqlite storage failure during #{what}: #{Exception.message(e)}"
    end

    try do
      result = fun.()
      {:ok, _} = exec(adapter, "COMMIT", [])
      result
    rescue
      e in [Kiwicaptcha.StoreWriteError] ->
        safe_rollback(adapter)
        raise e

      e ->
        safe_rollback(adapter)

        raise Kiwicaptcha.StoreUnavailableError,
          message: "sqlite storage failure during #{what}: #{Exception.message(e)}"
    end
  end

  defp safe_rollback(adapter) do
    adapter.exec.(adapter.conn, "ROLLBACK", [])
    :ok
  rescue
    _ -> :ok
  end

  defp store_now(adapter),
    do: if(adapter.now, do: adapter.now.(), else: System.system_time(:second))

  defp row_by_nonce(adapter, nonce) do
    case exec(adapter, @select_row, [nonce]) do
      {:ok, [raw | _]} -> build_row(raw)
      {:ok, []} -> nil
    end
  end

  defp live_row(adapter, nonce) do
    row = row_by_nonce(adapter, nonce)

    if row && store_now(adapter) < row.retained_until, do: row, else: nil
  end

  defp build_row(raw) when is_list(raw) do
    %{
      nonce: Enum.at(raw, 0),
      record_json: Enum.at(raw, 1),
      state: Enum.at(raw, 2),
      consumed_result_json: Enum.at(raw, 3),
      operation_identity: Enum.at(raw, 4),
      retained_until: to_int(Enum.at(raw, 5))
    }
  end

  defp to_int(v) when is_integer(v), do: v
  defp to_int(v) when is_binary(v), do: String.to_integer(v)
  defp to_int(v) when is_float(v), do: trunc(v)
  defp to_int(nil), do: 0

  defp decode_row(row) do
    with {:ok, record_fields} <- json_decode(row.record_json),
         {:ok, record} <- Kiwicaptcha.Record.from_json(record_fields) do
      result =
        if is_binary(row.consumed_result_json) do
          case json_decode(row.consumed_result_json) do
            {:ok, %{} = candidate} ->
              unknown_keys = Map.keys(candidate) -- ["valid", "binding", "mac"]
              valid = candidate["valid"]

              if unknown_keys == [] and is_boolean(valid) do
                %{
                  valid: valid,
                  binding:
                    if(is_binary(candidate["binding"]), do: candidate["binding"], else: nil),
                  mac: if(is_binary(candidate["mac"]), do: candidate["mac"], else: nil)
                }
              end

            _ ->
              nil
          end
        else
          nil
        end

      identity =
        if is_binary(row.operation_identity) and row.operation_identity != "" do
          row.operation_identity
        end

      %{state: row.state, record: record, result: result, identity: identity}
    else
      _ -> nil
    end
  end

  defp decoded_record(decoded), do: decoded && decoded.record

  defp retained_snapshot(decoded) do
    %{
      record: decoded.record,
      consumed_now: false,
      consumed_before: true,
      consumed_result: decoded.result,
      operation_identity: decoded.identity
    }
  end

  defp json_decode(value), do: Kiwicaptcha.Json.decode(value)

  @doc """
  The schema initializer: WAL journaling, the begin-immediate guarded
  version check and the table plus retention index, mirroring the
  adapters of the other cores. Call once per fresh database file.
  """
  @spec initialize(map()) :: :ok
  def initialize(adapter) do
    {:ok, _} = exec(adapter, "PRAGMA journal_mode = WAL", [])
    {:ok, _} = exec(adapter, "BEGIN IMMEDIATE", [])

    try do
      {:ok, [version]} = exec(adapter, "PRAGMA user_version", [])
      version = parse_version(version)

      if version > @schema_version do
        raise "the database carries schema version #{version}, newer than the #{@schema_version} this adapter supports"
      end

      if version < @schema_version do
        {:ok, _} =
          exec(
            adapter,
            "CREATE TABLE IF NOT EXISTS kiwicaptcha_challenge_records (" <>
              "nonce TEXT PRIMARY KEY, " <>
              "record_json TEXT NOT NULL, " <>
              "state TEXT NOT NULL CHECK (state IN ('pending', 'consumed', 'cancelled')), " <>
              "consumed_result_json TEXT, " <>
              "operation_identity TEXT, " <>
              "resume_owner TEXT, " <>
              "resume_until INTEGER, " <>
              "retained_until INTEGER NOT NULL)",
            []
          )

        {:ok, _} =
          exec(
            adapter,
            "CREATE INDEX IF NOT EXISTS kiwicaptcha_challenge_records_retained_until_idx " <>
              "ON kiwicaptcha_challenge_records (retained_until)",
            []
          )

        {:ok, _} = exec(adapter, "PRAGMA user_version = #{@schema_version}", [])
      end

      {:ok, _} = exec(adapter, "COMMIT", [])
      :ok
    rescue
      e ->
        safe_rollback(adapter)

        raise Kiwicaptcha.StoreUnavailableError,
          message: "sqlite schema initialization failed: #{Exception.message(e)}"
    end
  end

  defp parse_version(v) when is_integer(v), do: v

  defp parse_version(v) when is_binary(v), do: String.to_integer(v)

  defp parse_version([v]), do: parse_version(v)

  defp parse_version(%{} = map) do
    map |> Map.values() |> List.first() |> parse_version()
  end
end
