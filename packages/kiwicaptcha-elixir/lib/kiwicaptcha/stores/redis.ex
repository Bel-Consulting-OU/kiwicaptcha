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
      local stored = v
      local decoded = kiwiDecodeEnvelope(v)
      if decoded == nil then
        return nil
      end
      local fields = kiwiTopLevelFields(v)
      if fields == nil then
        return nil
      end
      local state = decoded['state']
      local consumedNow = 0
      local consumedBefore = 0
      local identitySpliced = 0
      if state == 'consumed' then
        consumedBefore = 1
      elseif state == 'pending' then
        -- The pending-envelope guard: a genuinely issued pending record
        -- carries only the null markers and no claim lease fields. A
        -- pending envelope that also carries a terminal or claim field
        -- (a non-null consumed_result, a non-null operation_identity, or
        -- any resume_owner / resume_until marker) is a corrupt or forged
        -- rewrite: the state marker was flipped without removing the
        -- carried fields. The transition refuses it with the missing
        -- semantics, so a record another worker holds a claim on is never
        -- consumed a second time.
        if not kiwiNullish(decoded['consumed_result'])
          or not kiwiNullish(decoded['operation_identity'])
          or not kiwiNullish(decoded['resume_owner'])
          or not kiwiNullish(decoded['resume_until']) then
          return nil
        end
        local pttl = redis.call("PTTL", KEYS[1])
        if pttl < 0 then
          return false
        end
        if pttl < 1000 then pttl = 1000 end
        local stateSpan = fields['state']
        if stateSpan == nil then
          return nil
        end
        local edits = {{stateSpan[2], stateSpan[3], '"consumed"'}}
        if ARGV[1] ~= '' then
          local identitySpan = fields['operation_identity']
          if identitySpan ~= nil then
            edits[#edits + 1] = {identitySpan[2], identitySpan[3], ARGV[1]}
            identitySpliced = 1
          end
        end
        local updated = kiwiApplyEdits(v, edits)
        redis.call("SET", KEYS[1], updated, "PX", pttl)
        consumedNow = 1
        v = updated
      else
        return nil
      end
      local resultJson = 'null'
      local resultSpan = fields['consumed_result']
      if resultSpan ~= nil then
        local value = string.sub(stored, resultSpan[2], resultSpan[3])
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

    local KIWI_B_QUOTE = 34
    local KIWI_B_BACKSLASH = 92
    local KIWI_B_OBRACE = 123
    local KIWI_B_CBRACE = 125
    local KIWI_B_OBRACKET = 91
    local KIWI_B_CBRACKET = 93
    local KIWI_B_COLON = 58
    local KIWI_B_COMMA = 44
    local KIWI_B_SPACE = 32
    local KIWI_B_TAB = 9
    local KIWI_B_LF = 10
    local KIWI_B_CR = 13

    local KIWI_VALUE_STOP_PATTERN = '[,}%] \\t\\r\\n]'

    local function kiwiNullish(x)
      return x == nil or x == cjson.null
    end

    local function kiwiSkipSpace(v, i, n)
      while i <= n do
        local b = string.byte(v, i)
        if b ~= KIWI_B_SPACE and b ~= KIWI_B_TAB and b ~= KIWI_B_LF and b ~= KIWI_B_CR then break end
        i = i + 1
      end
      return i
    end

    local function kiwiSkipSpaceBack(v, j)
      while j >= 1 do
        local b = string.byte(v, j)
        if b ~= nil and b ~= KIWI_B_SPACE and b ~= KIWI_B_TAB and b ~= KIWI_B_LF and b ~= KIWI_B_CR then break end
        j = j - 1
      end
      return j
    end

    local function kiwiSkipString(v, i, n)
      local j = i + 1
      while j <= n do
        local q = string.find(v, '"', j, true)
        if q == nil or q > n then return nil end
        local k = q - 1
        while k >= j and string.byte(v, k) == KIWI_B_BACKSLASH do k = k - 1 end
        if (q - 1 - k) % 2 == 0 then return q + 1 end
        j = q + 1
      end
      return nil
    end

    local kiwiUniqueScanValue
    local kiwiUniqueScanObject
    local kiwiUniqueScanArray

    local function kiwiKeyName(v, i, keyEnd)
      local inner = string.sub(v, i + 1, keyEnd - 2)
      if string.find(inner, '\\\\', 1, true) == nil and string.find(inner, '\\0', 1, true) == nil then
        return inner
      end
      local ok, decoded = pcall(cjson.decode, '"' .. inner .. '"')
      if not ok or type(decoded) ~= 'string' then return nil end
      return decoded
    end

    kiwiUniqueScanValue = function(v, i, n, depth)
      if depth > KIWI_ENVELOPE_MAX_DEPTH then return nil end
      if i > n then return nil end
      local b = string.byte(v, i)
      if b == KIWI_B_OBRACE then
        return kiwiUniqueScanObject(v, i + 1, n, depth)
      end
      if b == KIWI_B_OBRACKET then
        return kiwiUniqueScanArray(v, i + 1, n, depth)
      end
      if b == KIWI_B_QUOTE then
        return kiwiSkipString(v, i, n)
      end
      local stop = string.find(v, KIWI_VALUE_STOP_PATTERN, i)
      if stop == nil then stop = n + 1 end
      if stop == i then return nil end
      return stop
    end

    kiwiUniqueScanObject = function(v, i, n, depth)
      if depth > KIWI_ENVELOPE_MAX_DEPTH then return nil end
      local seen = {}
      i = kiwiSkipSpace(v, i, n)
      if i <= n and string.byte(v, i) == KIWI_B_CBRACE then return i + 1 end
      while true do
        i = kiwiSkipSpace(v, i, n)
        if i > n or string.byte(v, i) ~= KIWI_B_QUOTE then return nil end
        local keyEnd = kiwiSkipString(v, i, n)
        if keyEnd == nil then return nil end
        local key = kiwiKeyName(v, i, keyEnd)
        if key == nil then return nil end
        if seen[key] ~= nil then return nil end
        seen[key] = true
        i = kiwiSkipSpace(v, keyEnd, n)
        if i > n or string.byte(v, i) ~= KIWI_B_COLON then return nil end
        i = kiwiUniqueScanValue(v, kiwiSkipSpace(v, i + 1, n), n, depth + 1)
        if i == nil then return nil end
        i = kiwiSkipSpace(v, i, n)
        if i > n then return nil end
        local b = string.byte(v, i)
        if b == KIWI_B_COMMA then
          i = i + 1
        elseif b == KIWI_B_CBRACE then
          return i + 1
        else
          return nil
        end
      end
    end

    kiwiUniqueScanArray = function(v, i, n, depth)
      if depth > KIWI_ENVELOPE_MAX_DEPTH then return nil end
      i = kiwiSkipSpace(v, i, n)
      if i <= n and string.byte(v, i) == KIWI_B_CBRACKET then return i + 1 end
      while true do
        i = kiwiUniqueScanValue(v, i, n, depth + 1)
        if i == nil then return nil end
        i = kiwiSkipSpace(v, i, n)
        if i > n then return nil end
        local b = string.byte(v, i)
        if b == KIWI_B_COMMA then
          i = i + 1
        elseif b == KIWI_B_CBRACKET then
          return i + 1
        else
          return nil
        end
      end
    end

    local function kiwiTopLevelFields(v)
      local n = #v
      if n > KIWI_ENVELOPE_MAX_BYTES then return nil end
      local i = kiwiSkipSpace(v, 1, n)
      if i > n or string.byte(v, i) ~= KIWI_B_OBRACE then return nil end
      i = kiwiSkipSpace(v, i + 1, n)
      if i > n then return nil end
      local fields = {}
      if string.byte(v, i) == KIWI_B_CBRACE then
        if kiwiSkipSpace(v, i + 1, n) <= n then return nil end
        return fields
      end
      while true do
        if string.byte(v, i) ~= KIWI_B_QUOTE then return nil end
        local keyStart = i
        local keyEnd = kiwiSkipString(v, i, n)
        if keyEnd == nil then return nil end
        local name = kiwiKeyName(v, i, keyEnd)
        if name == nil then return nil end
        if fields[name] ~= nil then return nil end
        i = kiwiSkipSpace(v, keyEnd, n)
        if i > n or string.byte(v, i) ~= KIWI_B_COLON then return nil end
        local valueStart = kiwiSkipSpace(v, i + 1, n)
        if valueStart > n then return nil end
        i = kiwiUniqueScanValue(v, valueStart, n, 1)
        if i == nil then return nil end
        fields[name] = {keyStart, valueStart, i - 1}
        i = kiwiSkipSpace(v, i, n)
        if i > n then return nil end
        local b = string.byte(v, i)
        if b == KIWI_B_COMMA then
          i = kiwiSkipSpace(v, i + 1, n)
          if i > n then return nil end
        elseif b == KIWI_B_CBRACE then
          if kiwiSkipSpace(v, i + 1, n) <= n then return nil end
          return fields
        else
          return nil
        end
      end
    end

    local function kiwiApplyEdits(v, edits)
      if #edits > 1 then
        table.sort(edits, function(a, b) return a[1] > b[1] end)
      end
      for k = 1, #edits do
        local e = edits[k]
        if e[4] then
          local n = #v
          local i = kiwiSkipSpace(v, e[2] + 1, n)
          if i <= n and string.byte(v, i) == KIWI_B_COMMA then
            v = string.sub(v, 1, e[1] - 1) .. string.sub(v, i + 1)
          else
            local j = kiwiSkipSpaceBack(v, e[1] - 1)
            if j >= 1 and string.byte(v, j) == KIWI_B_COMMA then
              v = string.sub(v, 1, j - 1) .. string.sub(v, e[2] + 1)
            else
              v = string.sub(v, 1, e[1] - 1) .. string.sub(v, e[2] + 1)
            end
          end
        else
          v = string.sub(v, 1, e[1] - 1) .. e[3] .. string.sub(v, e[2] + 1)
        end
      end
      return v
    end

    local function kiwiAppendTopLevel(v, literal)
      local n = #v
      local first = kiwiSkipSpace(v, 1, n)
      if first > n or string.byte(v, first) ~= KIWI_B_OBRACE then return nil end
      local depth = 0
      local last = nil
      local i = first
      while i <= n do
        local b = string.byte(v, i)
        if b == KIWI_B_QUOTE then
          local e = kiwiSkipString(v, i, n)
          if e == nil then return nil end
          i = e
        elseif b == KIWI_B_OBRACE or b == KIWI_B_OBRACKET then
          depth = depth + 1
          i = i + 1
        elseif b == KIWI_B_CBRACE or b == KIWI_B_CBRACKET then
          depth = depth - 1
          if depth == 0 then last = i break end
          i = i + 1
        else
          i = i + 1
        end
      end
      if last == nil then return nil end
      local p = kiwiSkipSpaceBack(v, last - 1)
      if p == first then
        return string.sub(v, 1, last - 1) .. literal .. string.sub(v, last)
      end
      return string.sub(v, 1, last - 1) .. ',' .. literal .. string.sub(v, last)
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
