defmodule Kiwicaptcha.Stores.Memory do
  @moduledoc """
  The in-memory adapter: single-process evaluations, tests and tools.
  The record map is synchronous under a GenServer, so the read-decide-
  write of the consume transition has no interleaving point and
  exactly-once holds naturally.
  """

  use GenServer

  @behaviour Kiwicaptcha.Store.Behaviour

  @doc "Start the store. Each call yields its own isolated row map."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    ttl_margin = Keyword.get(opts, :ttl_margin_secs, Kiwicaptcha.Store.default_ttl_margin_secs())

    GenServer.start_link(__MODULE__, %{
      rows: %{},
      ttl_margin: ttl_margin,
      now: Keyword.get(opts, :now)
    })
  end

  @doc "Start a store and return its server pid."
  @spec start(keyword()) :: {:ok, GenServer.server()} | GenServer.on_start()
  def start(opts \\ []) do
    case start_link(opts) do
      {:ok, pid} -> {:ok, pid}
      {:error, {:already_started, pid}} -> {:ok, pid}
      other -> other
    end
  end

  @doc """
  The fun-map adapter over one started server: the shape the verifier
  drives. The authenticated_result_commit fun answers the store
  capability probe.
  """
  @spec adapter(GenServer.server()) :: map()
  def adapter(server) do
    %{
      store: fn record -> store(server, record) end,
      find: fn nonce -> find(server, nonce) end,
      runtime_state: fn nonce -> runtime_state(server, nonce) end,
      consume: fn nonce, identity -> consume(server, nonce, identity) end,
      commit_result: fn nonce, valid, binding, mac ->
        commit_result(server, nonce, valid, binding, mac)
      end,
      delete_if_pending: fn nonce -> delete_if_pending(server, nonce) end,
      authenticated_result_commit?: fn -> authenticated_result_commit?() end
    }
  end

  @impl true
  def authenticated_result_commit?, do: true

  @impl true
  def store(server, record) do
    envelope =
      record
      |> Kiwicaptcha.Record.to_json_map()
      |> Map.merge(%{"state" => "pending", "consumed_result" => nil, "operation_identity" => nil})

    json = json_encode(envelope)
    retained_until = record.expires_at + server_margin(server)
    GenServer.call(server, {:store, record.nonce, json, retained_until})
  end

  @impl true
  def find(server, nonce) do
    case GenServer.call(server, {:live_json, nonce}) do
      :missing -> nil
      json -> envelope_record(json)
    end
  end

  @impl true
  def runtime_state(server, nonce) do
    case GenServer.call(server, {:live_json, nonce}) do
      :missing -> %{kind: :missing, record: nil, consumed: nil}
      json -> build_state(json)
    end
  end

  @impl true
  def consume(server, nonce, operation_identity) do
    identity = Kiwicaptcha.Store.validated_operation_identity(operation_identity)
    GenServer.call(server, {:consume, nonce, identity})
  end

  @impl true
  def commit_result(server, nonce, valid, binding, mac) do
    GenServer.call(server, {:commit, nonce, valid, binding, mac})
  end

  @impl true
  def delete_if_pending(server, nonce) do
    GenServer.call(server, {:delete_if_pending, nonce})
  end

  # One GenServer per map: the calls serialize, so the read-decide-
  # write has no interleaving point.
  @impl GenServer
  def init(state), do: {:ok, state}

  def handle_call(:margin, _from, state), do: {:reply, state.ttl_margin, state}

  @impl GenServer
  def handle_call({:store, nonce, json, retained_until}, _from, state) do
    now = store_now(state)
    rows = Map.filter(state.rows, fn {_n, row} -> now < row.retained_until end)
    rows = Map.put(rows, nonce, %{json: json, retained_until: retained_until})
    {:reply, :ok, %{state | rows: rows}}
  end

  def handle_call({:live_json, nonce}, _from, state) do
    now = store_now(state)

    case state.rows[nonce] do
      %{json: json, retained_until: until} when now < until -> {:reply, json, state}
      _ -> {:reply, :missing, state}
    end
  end

  def handle_call({:consume, nonce, identity}, _from, state) do
    now = store_now(state)

    case live_row(state.rows, nonce, now) do
      nil ->
        {:reply, nil, state}

      row ->
        case Kiwicaptcha.Store.decode_envelope(row.json) do
          :error ->
            {:reply, nil, state}

          {:ok, decoded} ->
            cond do
              decoded.state == "consumed" ->
                {:reply, retained_snapshot(decoded), state}

              decoded.state != "pending" ->
                # A cancelled row is never consumable.
                {:reply, nil, state}

              pending_marker?(row.json) ->
                # The pending-envelope guard mirrors the Redis script: a
                # pending envelope carrying a result or identity marker
                # is a forged rewrite.
                {:reply, nil, state}

              true ->
                updated = splice_state(row.json, identity)
                rows = Map.put(state.rows, nonce, %{row | json: updated})

                {:reply,
                 %{
                   record: decoded.record,
                   consumed_now: true,
                   consumed_before: false,
                   consumed_result: nil,
                   operation_identity: identity
                 }, %{state | rows: rows}}
            end
        end
    end
  end

  def handle_call({:commit, nonce, valid, binding, mac}, _from, state) do
    now = store_now(state)

    case live_row(state.rows, nonce, now) do
      nil ->
        {:reply, false, state}

      row ->
        case Kiwicaptcha.Store.decode_envelope(row.json) do
          {:ok, decoded} ->
            if decoded.state == "consumed" and decoded.result == nil do
              result = %{"valid" => valid, "binding" => binding}
              result = if mac, do: Map.put(result, "mac", mac), else: result
              updated = splice_consumed_result(row.json, result)
              rows = Map.put(state.rows, nonce, %{row | json: updated})
              {:reply, true, %{state | rows: rows}}
            else
              {:reply, false, state}
            end

          :error ->
            {:reply, false, state}
        end
    end
  end

  def handle_call({:delete_if_pending, nonce}, _from, state) do
    now = store_now(state)

    case live_row(state.rows, nonce, now) do
      nil ->
        {:reply, %{kind: :missing, consumed: nil}, state}

      row ->
        case Kiwicaptcha.Store.decode_envelope(row.json) do
          {:ok, decoded} ->
            case decoded.state do
              "consumed" ->
                {:reply, %{kind: :consumed, consumed: retained_snapshot(decoded)}, state}

              "cancelled" ->
                {:reply, %{kind: :cancelled, consumed: nil}, state}

              "pending" ->
                rows = Map.delete(state.rows, nonce)
                {:reply, %{kind: :deleted_pending, consumed: nil}, %{state | rows: rows}}

              _ ->
                {:reply, %{kind: :corrupt, consumed: nil}, state}
            end

          :error ->
            {:reply, %{kind: :corrupt, consumed: nil}, state}
        end
    end
  end

  defp live_row(rows, nonce, now) do
    case rows[nonce] do
      %{retained_until: until} = row when now < until -> row
      _ -> nil
    end
  end

  defp pending_marker?(json) do
    case json_decode(json) do
      {:ok, envelope} ->
        not is_nil(envelope["consumed_result"]) or not is_nil(envelope["operation_identity"])

      :error ->
        true
    end
  end

  defp splice_state(json, identity) do
    envelope = json_decode!(json)
    json_encode(Map.merge(envelope, %{"state" => "consumed", "operation_identity" => identity}))
  end

  defp splice_consumed_result(json, result) do
    envelope = json_decode!(json)
    json_encode(Map.put(envelope, "consumed_result", result))
  end

  defp json_decode!(json) do
    case Kiwicaptcha.Json.decode(json) do
      {:ok, decoded} -> decoded
      :error -> raise "corrupt envelope"
    end
  end

  defp json_decode(value), do: Kiwicaptcha.Json.decode(value)

  defp json_encode(value) do
    case Kiwicaptcha.Json.encode(value) do
      {:ok, doc} -> doc
      :error -> raise "json encode failed"
    end
  end

  defp envelope_record(json) do
    case Kiwicaptcha.Store.decode_envelope(json) do
      {:ok, decoded} -> decoded.record
      :error -> nil
    end
  end

  defp build_state(json) do
    case Kiwicaptcha.Store.decode_envelope(json) do
      {:ok, decoded} ->
        case decoded.state do
          "cancelled" ->
            %{kind: :cancelled, record: decoded.record, consumed: nil}

          "consumed" ->
            %{kind: :consumed, record: decoded.record, consumed: retained_snapshot(decoded)}

          "pending" ->
            %{kind: :pending, record: decoded.record, consumed: nil}

          _ ->
            %{kind: :missing, record: nil, consumed: nil}
        end

      :error ->
        %{kind: :missing, record: nil, consumed: nil}
    end
  end

  defp retained_snapshot(decoded) do
    %{
      record: decoded.record,
      consumed_now: false,
      consumed_before: true,
      consumed_result: decoded.result,
      operation_identity: decoded.identity
    }
  end

  defp server_margin(server) do
    case GenServer.call(server, :margin, 1000) do
      margin when is_integer(margin) -> margin
      _ -> Kiwicaptcha.Store.default_ttl_margin_secs()
    end
  rescue
    _ -> Kiwicaptcha.Store.default_ttl_margin_secs()
  end

  defp store_now(state), do: if(state.now, do: state.now.(), else: System.system_time(:second))
end
