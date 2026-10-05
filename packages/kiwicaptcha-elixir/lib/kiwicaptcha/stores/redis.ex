defmodule Kiwicaptcha.Stores.Redis do
  @moduledoc """
  The Redis adapter. The record lives under "kiwicaptcha:" plus the
  nonce (the PHP backend key shape) as one flat envelope JSON, so a
  mixed PHP, Node, Ruby and Elixir fleet redeems cross-node. The
  consume and delete-if-pending transitions run as Lua scripts through
  evalsha with an eval fallback when the script cache misses; Redis
  serializes each script, so exactly one racing caller wins the
  pending-to-consumed flip. The scripts splice the raw JSON bytes and
  never re-encode the document, so large integers keep their exact
  spelling.

  The client is duck typed: a Redix connection (start it with
  `Redix.start_link/1`) or any module function pair answering the same
  commands through `apply/3` style callables. The Redix package stays
  an optional dependency of the core.
  """

  @behaviour Kiwicaptcha.Store.Behaviour

  @default_prefix "kiwicaptcha:"

  @spec new(term(), keyword()) :: map()
  def new(client, opts \\ []) do
    prefix = Keyword.get(opts, :prefix, @default_prefix)
    ttl_margin = Keyword.get(opts, :ttl_margin_secs, Kiwicaptcha.Store.default_ttl_margin_secs())
    now = Keyword.get(opts, :now)

    %{
      store: fn record ->
        store(%{client: client, prefix: prefix, ttl_margin: ttl_margin, now: now}, record)
      end,
      find: fn nonce ->
        find(%{client: client, prefix: prefix, ttl_margin: ttl_margin, now: now}, nonce)
      end,
      runtime_state: fn nonce ->
        runtime_state(%{client: client, prefix: prefix, ttl_margin: ttl_margin, now: now}, nonce)
      end,
      consume: fn nonce, identity ->
        consume(
          %{client: client, prefix: prefix, ttl_margin: ttl_margin, now: now},
          nonce,
          identity
        )
      end,
      commit_result: fn nonce, valid, binding, mac ->
        commit_result(
          %{client: client, prefix: prefix, ttl_margin: ttl_margin, now: now},
          nonce,
          valid,
          binding,
          mac
        )
      end,
      delete_if_pending: fn nonce ->
        delete_if_pending(
          %{client: client, prefix: prefix, ttl_margin: ttl_margin, now: now},
          nonce
        )
      end,
      authenticated_result_commit?: fn -> true end
    }
  end

  @impl true
  def authenticated_result_commit?, do: true

  defp consume_script do
    prelude() <>
      """
      local v = redis.call("GET", KEYS[1])
      if not v then
        return nil
      end
      local decoded = kiwiDecodeEnvelope(v)
      if decoded == nil then
        return nil
      end
      if kiwiTopLevelFields(v) == nil then
        return nil
      end
      local state = decoded['state']
      local consumedNow = 0
      local consumedBefore = 0
      local identitySpliced = 0
      if state == 'consumed' then
        consumedBefore = 1
      elseif state == 'pending' then
        if not kiwiNullish(decoded['consumed_result'])
          or not kiwiNullish(decoded['operation_identity']) then
          return nil
        end
        local pttl = redis.call("PTTL", KEYS[1])
        if pttl < 0 then
          return false
        end
        if pttl < 1000 then pttl = 1000 end
        local updated = kiwiReplaceTopLevel(v, 'state', '"consumed"')
        if updated == nil then
          return nil
        end
        if ARGV[1] ~= '' then
          local withIdentity = kiwiReplaceTopLevel(updated, 'operation_identity', ARGV[1])
          if withIdentity ~= nil then
            updated = withIdentity
            identitySpliced = 1
          end
        end
        redis.call("SET", KEYS[1], updated, "PX", pttl)
        consumedNow = 1
        v = updated
      else
        return nil
      end
      local resultJson = 'null'
      local resultSpan = kiwiTopLevelField(v, 'consumed_result')
      if resultSpan ~= nil then
        local value = string.sub(v, resultSpan[2], resultSpan[3])
        if value ~= 'null' then
          resultJson = value
        end
      end
      return {v, consumedNow, consumedBefore, resultJson, identitySpliced}
      """
  end

  defp delete_if_pending_script do
    prelude() <>
      """
      local v = redis.call("GET", KEYS[1])
      if not v then
        return {'missing'}
      end
      local decoded = kiwiDecodeEnvelope(v)
      if decoded == nil then
        return {'corrupt'}
      end
      if kiwiTopLevelFields(v) == nil then
        return {'corrupt'}
      end
      local state = decoded['state']
      if state == 'consumed' then
        return {'consumed', v}
      end
      if state == 'cancelled' then
        return {'cancelled', v}
      end
      if state == 'pending' then
        redis.call("DEL", KEYS[1])
        return {'deleted-pending'}
      end
      return {'corrupt'}
      """
  end

  # The shared envelope prelude: bounded scan of the document with the
  # duplicate-key refusal and the top-level splice helpers, identical
  # to the scripts the other cores ship.
  defp prelude do
    """
    local KIWI_ENVELOPE_MAX_BYTES = 131072
    local KIWI_ENVELOPE_MAX_DEPTH = 32

    local function kiwiNullish(x)
      return x == nil or x == cjson.null
    end

    local function kiwiIsSpace(c)
      return string.find(' \\t\\r\\n', c, 1, true) ~= nil
    end

    local function kiwiSkipSpace(v, i, n)
      while i <= n do
        local c = string.sub(v, i, i)
        if not kiwiIsSpace(c) then break end
        i = i + 1
      end
      return i
    end

    local function kiwiValueEnd(v, s, n)
      local c = string.sub(v, s, s)
      if c == '"' then
        local i = s + 1
        local esc = false
        while i <= n do
          local ci = string.sub(v, i, i)
          if esc then esc = false
          elseif ci == '\\\\' then esc = true
          elseif ci == '"' then return i end
          i = i + 1
        end
        return nil
      elseif c == '{' or c == '[' then
        local open = c
        local close = (c == '{') and '}' or ']'
        local depth = 0
        local i = s
        while i <= n do
          local ci = string.sub(v, i, i)
          if ci == '"' then
            i = i + 1
            local esc2 = false
            while i <= n do
              local cj = string.sub(v, i, i)
              if esc2 then esc2 = false
              elseif cj == '\\\\' then esc2 = true
              elseif cj == '"' then break end
              i = i + 1
            end
            if i > n then return nil end
          elseif ci == open then
            depth = depth + 1
          elseif ci == close then
            depth = depth - 1
            if depth == 0 then return i end
          end
          i = i + 1
        end
        return nil
      end
      local i = s
      while i <= n do
        local ci = string.sub(v, i, i)
        if ci == ',' or ci == '}' or ci == ']' or ci == ' ' or ci == '\\t' or ci == '\\r' or ci == '\\n' then
          break
        end
        i = i + 1
      end
      if i == s then return nil end
      return i - 1
    end

    local function kiwiSkipString(v, i, n)
      i = i + 1
      while i <= n do
        local c = string.sub(v, i, i)
        if c == '\\\\' then
          i = i + 2
        elseif c == '"' then
          return i + 1
        else
          i = i + 1
        end
      end
      return nil
    end

    local kiwiUniqueScanValue
    local kiwiUniqueScanObject
    local kiwiUniqueScanArray

    kiwiUniqueScanValue = function(v, i, n, depth)
      if depth > KIWI_ENVELOPE_MAX_DEPTH then return nil end
      if i > n then return nil end
      local c = string.sub(v, i, i)
      if c == '{' then
        return kiwiUniqueScanObject(v, i + 1, n, depth)
      end
      if c == '[' then
        return kiwiUniqueScanArray(v, i + 1, n, depth)
      end
      if c == '"' then
        return kiwiSkipString(v, i, n)
      end
      local start = i
      while i <= n do
        local c2 = string.sub(v, i, i)
        if c2 == ',' or c2 == '}' or c2 == ']' or kiwiIsSpace(c2) then break end
        i = i + 1
      end
      if i == start then return nil end
      return i
    end

    kiwiUniqueScanObject = function(v, i, n, depth)
      if depth > KIWI_ENVELOPE_MAX_DEPTH then return nil end
      local seen = {}
      i = kiwiSkipSpace(v, i, n)
      if i <= n and string.sub(v, i, i) == '}' then return i + 1 end
      while true do
        i = kiwiSkipSpace(v, i, n)
        if i > n or string.sub(v, i, i) ~= '"' then return nil end
        local keyEnd = kiwiSkipString(v, i, n)
        if keyEnd == nil then return nil end
        local token = string.sub(v, i, keyEnd - 1)
        local ok, key = pcall(cjson.decode, token)
        if not ok or type(key) ~= 'string' then return nil end
        if seen[key] ~= nil then return nil end
        seen[key] = true
        i = kiwiSkipSpace(v, keyEnd, n)
        if i > n or string.sub(v, i, i) ~= ':' then return nil end
        i = kiwiUniqueScanValue(v, kiwiSkipSpace(v, i + 1, n), n, depth + 1)
        if i == nil then return nil end
        i = kiwiSkipSpace(v, i, n)
        if i > n then return nil end
        local sep = string.sub(v, i, i)
        if sep == ',' then
          i = i + 1
        elseif sep == '}' then
          return i + 1
        else
          return nil
        end
      end
    end

    kiwiUniqueScanArray = function(v, i, n, depth)
      if depth > KIWI_ENVELOPE_MAX_DEPTH then return nil end
      i = kiwiSkipSpace(v, i, n)
      if i <= n and string.sub(v, i, i) == ']' then return i + 1 end
      while true do
        i = kiwiUniqueScanValue(v, i, n, depth + 1)
        if i == nil then return nil end
        i = kiwiSkipSpace(v, i, n)
        if i > n then return nil end
        local sep = string.sub(v, i, i)
        if sep == ',' then
          i = i + 1
        elseif sep == ']' then
          return i + 1
        else
          return nil
        end
      end
    end

    local function kiwiDocumentIsUnique(v)
      local n = #v
      if n == 0 or n > KIWI_ENVELOPE_MAX_BYTES then return false end
      local i = kiwiSkipSpace(v, 1, n)
      if i > n or string.sub(v, i, i) ~= '{' then return false end
      local endIndex = kiwiUniqueScanObject(v, i + 1, n, 0)
      if endIndex == nil then return false end
      return kiwiSkipSpace(v, endIndex, n) > n
    end

    local function kiwiTopLevelFields(v)
      local n = #v
      if n > KIWI_ENVELOPE_MAX_BYTES then return nil end
      if not kiwiDocumentIsUnique(v) then return nil end
      local i = 1
      i = kiwiSkipSpace(v, i, n)
      if string.sub(v, i, i) ~= '{' then return nil end
      i = i + 1
      local fields = {}
      while i <= n do
        local c = string.sub(v, i, i)
        if string.find(' \\t\\r\\n,', c, 1, true) then
          i = i + 1
        elseif c == '}' then
          return fields
        elseif c == '"' then
          local j = i + 1
          local esc = false
          while j <= n do
            local cj = string.sub(v, j, j)
            if esc then esc = false
            elseif cj == '\\\\' then esc = true
            elseif cj == '"' then break end
            j = j + 1
          end
          if j > n then return nil end
          local name = string.sub(v, i + 1, j - 1)
          local nameOk, decodedName = pcall(cjson.decode, '"' .. name .. '"')
          if not nameOk or type(decodedName) ~= 'string' then return nil end
          if fields[decodedName] ~= nil then return nil end
          local p = j + 1
          p = kiwiSkipSpace(v, p, n)
          if string.sub(v, p, p) ~= ':' then return nil end
          local s = p + 1
          s = kiwiSkipSpace(v, s, n)
          local e = kiwiValueEnd(v, s, n)
          if e == nil then return nil end
          fields[decodedName] = {i, s, e}
          i = e + 1
        else
          return nil
        end
      end
      return nil
    end

    local function kiwiTopLevelField(v, key)
      local fields = kiwiTopLevelFields(v)
      if fields == nil then return nil end
      return fields[key]
    end

    local function kiwiReplaceTopLevel(v, key, literal)
      local span = kiwiTopLevelField(v, key)
      if span == nil then return nil end
      local head = string.sub(v, 1, span[2] - 1)
      local tail = string.sub(v, span[3] + 1)
      return head .. literal .. tail
    end

    local function kiwiDecodeEnvelope(v)
      if #v > KIWI_ENVELOPE_MAX_BYTES then return nil end
      local ok, decoded = pcall(cjson.decode, v)
      if not ok or type(decoded) ~= 'table' then return nil end
      return decoded
    end
    """
  end

  @impl true
  def store(adapter, record) do
    envelope =
      record
      |> Kiwicaptcha.Record.to_json_map()
      |> Map.merge(%{"state" => "pending", "consumed_result" => nil, "operation_identity" => nil})

    now = store_now(adapter)
    ttl = max(1, record.expires_at - now + adapter.ttl_margin)
    command(adapter, ["SET", key(adapter, record.nonce), encode_json(envelope), "EX", ttl])
    :ok
  end

  @impl true
  def find(adapter, nonce) do
    case raw_get(adapter, nonce) do
      nil -> nil
      raw -> envelope_record(raw)
    end
  end

  @impl true
  def runtime_state(adapter, nonce) do
    case raw_get(adapter, nonce) do
      nil -> %{kind: :missing, record: nil, consumed: nil}
      raw -> build_state(raw)
    end
  end

  @impl true
  def consume(adapter, nonce, operation_identity) do
    identity = Kiwicaptcha.Store.validated_operation_identity(operation_identity)
    identity_arg = if identity, do: encode_json(identity), else: ""

    case eval_script(adapter, consume_script(), [key(adapter, nonce)], [identity_arg]) do
      {:ok, nil} ->
        nil

      {:ok, false} ->
        nil

      {:ok, [json, consumed_now, consumed_before, _result_json, identity_spliced]} ->
        if identity_arg != "" and to_int(consumed_now) == 1 and to_int(identity_spliced) != 1 do
          raise Kiwicaptcha.StoreWriteError,
            message:
              "the consume transition could not record the operation identity on the flipped envelope"
        end

        case Kiwicaptcha.Store.decode_envelope(json) do
          {:ok, decoded} ->
            %{
              record: decoded.record,
              consumed_now: to_int(consumed_now) == 1,
              consumed_before: to_int(consumed_before) == 1,
              consumed_result: decoded.result,
              operation_identity: decoded.identity
            }

          :error ->
            nil
        end

      {:ok, other} ->
        raise Kiwicaptcha.StoreUnavailableError,
          message: "the redis consume script failed: #{inspect(other)}"

      {:error, reason} ->
        raise Kiwicaptcha.StoreUnavailableError,
          message: "the redis consume script failed: #{inspect(reason)}"
    end
  rescue
    e in [Kiwicaptcha.StoreWriteError] ->
      raise e

    e ->
      raise Kiwicaptcha.StoreUnavailableError,
        message: "the redis consume script failed: #{Exception.message(e)}"
  end

  @impl true
  def commit_result(adapter, nonce, valid, binding, mac) do
    case raw_get(adapter, nonce) do
      nil ->
        false

      raw ->
        decoded = Kiwicaptcha.Store.decode_envelope(raw)

        if match?({:ok, %{state: "consumed", result: nil}}, decoded) do
          {:ok, envelope} = Kiwicaptcha.Store.decode_envelope(raw)
          _ = envelope
          result = %{"valid" => valid, "binding" => binding}
          result = if mac, do: Map.put(result, "mac", mac), else: result
          {:ok, envelope_map} = json_decode(raw)

          # Preserve the key's remaining lifetime exactly as the
          # cores' commit does: read the remaining TTL, refuse a
          # persistent foreign key, floor the sub-second remainder.
          case command(adapter, ["PTTL", key(adapter, nonce)]) do
            {:ok, pttl} when pttl >= 0 ->
              updated = Map.put(envelope_map, "consumed_result", result)
              ttl = max(1, ceil(pttl / 1000))

              {:ok, _} =
                command(adapter, ["SET", key(adapter, nonce), encode_json(updated), "EX", ttl])

              true

            _ ->
              false
          end
        else
          false
        end
    end
  end

  @impl true
  def delete_if_pending(adapter, nonce) do
    case eval_script(adapter, delete_if_pending_script(), [key(adapter, nonce)], []) do
      {:ok, ["missing"]} ->
        %{kind: :missing, consumed: nil}

      {:ok, ["deleted-pending"]} ->
        %{kind: :deleted_pending, consumed: nil}

      {:ok, ["cancelled"]} ->
        %{kind: :cancelled, consumed: nil}

      {:ok, ["corrupt"]} ->
        %{kind: :corrupt, consumed: nil}

      {:ok, ["consumed", json]} ->
        case Kiwicaptcha.Store.decode_envelope(json) do
          {:ok, decoded} -> %{kind: :consumed, consumed: retained_snapshot(decoded)}
          :error -> %{kind: :corrupt, consumed: nil}
        end

      _ ->
        %{kind: :corrupt, consumed: nil}
    end
  end

  defp key(adapter, nonce), do: adapter.prefix <> nonce

  defp store_now(adapter),
    do: if(adapter.now, do: adapter.now.(), else: System.system_time(:second))

  defp raw_get(adapter, nonce) do
    case command(adapter, ["GET", key(adapter, nonce)]) do
      {:ok, nil} -> nil
      {:ok, ""} -> nil
      {:ok, raw} when is_binary(raw) -> raw
      _ -> nil
    end
  end

  defp command(%{client: client}, command) do
    cond do
      # A Redix connection: commands never raise, they return tuples.
      redix_loaded?() ->
        apply(Redix, :command, [client, command])

      is_pid(client) or is_atom(client) ->
        GenServer.call(client, {:redis_command, command})

      true ->
        raise Kiwicaptcha.StoreUnavailableError, message: "unsupported redis client"
    end
  rescue
    e in [Kiwicaptcha.StoreUnavailableError] ->
      raise e

    e ->
      raise Kiwicaptcha.StoreUnavailableError,
        message: "redis transport failure: #{Exception.message(e)}"
  end

  defp eval_script(adapter, script, keys, args) do
    sha = :crypto.hash(:sha, script) |> Base.encode16(case: :lower)

    case command(adapter, ["EVALSHA", sha, length(keys)] ++ keys ++ args) do
      {:ok, result} ->
        {:ok, result}

      {:error, %{message: message}} = error ->
        if String.contains?(String.upcase(message), "NOSCRIPT") do
          command(adapter, ["EVAL", script, length(keys)] ++ keys ++ args)
        else
          error
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # The optional backend stays optional: the Redix module is probed,
  # never hard-required, so the core compiles without it.
  defp redix_loaded? do
    Code.ensure_loaded?(Redix) and function_exported?(Redix, :command, 2)
  end

  defp envelope_record(raw) do
    case Kiwicaptcha.Store.decode_envelope(raw) do
      {:ok, decoded} -> decoded.record
      :error -> nil
    end
  end

  defp build_state(raw) do
    case Kiwicaptcha.Store.decode_envelope(raw) do
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

  defp to_int(v) when is_integer(v), do: v
  defp to_int(true), do: 1
  defp to_int(_), do: 0

  defp json_decode(value), do: Kiwicaptcha.Json.decode(value)

  defp encode_json(value) do
    case Kiwicaptcha.Json.encode(value) do
      {:ok, doc} -> doc
      :error -> raise "json encode failed"
    end
  end
end
