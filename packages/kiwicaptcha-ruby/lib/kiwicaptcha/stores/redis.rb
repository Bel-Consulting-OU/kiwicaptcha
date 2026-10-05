# frozen_string_literal: true

require 'digest'
require 'digest/sha1'
require 'json'

module KiwiCaptcha
  # The Redis adapter. The record lives under "kiwicaptcha:" plus the
  # nonce (the PHP backend key shape) as one flat envelope JSON, so a
  # mixed PHP, Node, Ruby and Elixir fleet redeems cross-node. The
  # consume and delete-if-pending transitions run as Lua scripts
  # through evalsha with an eval fallback when the script cache misses;
  # Redis serializes each script, so exactly one racing caller wins the
  # pending-to-consumed flip. The scripts splice the raw JSON bytes and
  # never re-encode the document, so large integers keep their exact
  # spelling.
  #
  # The client is duck typed: any object answering get, set, del, pttl,
  # eval, evalsha and script works (the redis gem client, or a test
  # fake). The gem stays an optional dependency of the core.
  class RedisStore
    attr_reader :authenticated_result_commit

    ENVELOPE_LUA_PRELUDE = <<~LUA
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
    LUA

    CONSUME_SCRIPT = ENVELOPE_LUA_PRELUDE + <<~LUA
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
    LUA

    DELETE_IF_PENDING_SCRIPT = ENVELOPE_LUA_PRELUDE + <<~LUA
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
    LUA

    DEFAULT_PREFIX = 'kiwicaptcha:'

    def initialize(client, prefix: DEFAULT_PREFIX, ttl_margin_secs: Store::DEFAULT_TTL_MARGIN_SECS, now: nil)
      raise RangeError, 'ttl_margin_secs must be >= 0' if ttl_margin_secs.negative?

      @authenticated_result_commit = true
      @client = client
      @prefix = prefix
      @ttl_margin_secs = ttl_margin_secs
      @now = now || -> { Time.now.to_i }
      @script_sha = {
        consume: Digest::SHA1.hexdigest(CONSUME_SCRIPT),
        delete_if_pending: Digest::SHA1.hexdigest(DELETE_IF_PENDING_SCRIPT)
      }
    end

    def store(record)
      envelope = Record.to_json_record(record).merge(
        'state' => 'pending', 'consumed_result' => nil, 'operation_identity' => nil
      )
      ttl = [1, record.expires_at - @now.call + @ttl_margin_secs].max
      @client.set(record_key(record.nonce), JSON.generate(envelope), ex: ttl)
      nil
    end

    def find(nonce)
      decoded = decode_raw(@client.get(record_key(nonce)))
      decoded&.record
    end

    def runtime_state(nonce)
      decoded = decode_raw(@client.get(record_key(nonce)))
      if decoded.nil?
        return Store::RuntimeStateSnapshot.new(kind: 'missing', record: nil, consumed: nil)
      end

      case decoded.state
      when 'cancelled'
        Store::RuntimeStateSnapshot.new(kind: 'cancelled', record: decoded.record, consumed: nil)
      when 'consumed'
        Store::RuntimeStateSnapshot.new(kind: 'consumed', record: decoded.record, consumed: retained_snapshot(decoded))
      when 'pending'
        Store::RuntimeStateSnapshot.new(kind: 'pending', record: decoded.record, consumed: nil)
      else
        Store::RuntimeStateSnapshot.new(kind: 'missing', record: nil, consumed: nil)
      end
    end

    def consume(nonce, operation_identity = nil)
      identity = Store.validated_operation_identity(operation_identity)
      identity_arg = identity.nil? ? '' : JSON.generate(identity)
      raw = eval_script(:consume, CONSUME_SCRIPT, [record_key(nonce)], [identity_arg])
      return nil if raw.nil? || raw == false || !raw.is_a?(Array)

      identity_spliced = raw[4].to_i
      if identity_arg != '' && raw[1].to_i == 1 && identity_spliced != 1
        raise StoreWriteError, 'the consume transition could not record the operation identity on the flipped envelope'
      end

      decoded = decode_raw(raw[0].to_s)
      return nil if decoded.nil?

      Store::ConsumedRecordSnapshot.new(
        record: decoded.record,
        consumed_now: raw[1].to_i == 1,
        consumed_before: raw[2].to_i == 1,
        consumed_result: decoded.result,
        operation_identity: decoded.identity
      )
    rescue StoreWriteError
      raise
    rescue StandardError => e
      raise StoreUnavailableError, "the redis consume script failed: #{e.message}"
    end

    def commit_result(nonce, valid, binding, mac)
      raw = @client.get(record_key(nonce))
      decoded = decode_raw(raw)
      return false if raw.nil? || decoded.nil? || decoded.state != 'consumed' || !decoded.result.nil?

      envelope = JSON.parse(raw)
      result = { 'valid' => valid, 'binding' => binding }
      result['mac'] = mac unless mac.nil?
      envelope['consumed_result'] = result
      # Preserve the key's remaining lifetime exactly as the cores'
      # commit does: read the remaining TTL, refuse a persistent
      # foreign key, floor the sub-second remainder.
      pttl = @client.pttl(record_key(nonce))
      return false if pttl.negative?

      @client.set(record_key(nonce), JSON.generate(envelope), ex: [1, (pttl.to_f / 1000).ceil].max)
      true
    end

    def delete_if_pending(nonce)
      raw = eval_script(:delete_if_pending, DELETE_IF_PENDING_SCRIPT, [record_key(nonce)], [])
      return Store::DeleteIfPendingOutcome.new(kind: 'corrupt', consumed: nil) unless raw.is_a?(Array) && !raw.empty?

      kind = raw[0].to_s
      case kind
      when 'missing' then Store::DeleteIfPendingOutcome.new(kind: 'missing', consumed: nil)
      when 'deleted-pending' then Store::DeleteIfPendingOutcome.new(kind: 'deleted_pending', consumed: nil)
      when 'cancelled' then Store::DeleteIfPendingOutcome.new(kind: 'cancelled', consumed: nil)
      when 'consumed'
        decoded = decode_raw(raw[1].to_s)
        if decoded.nil?
          Store::DeleteIfPendingOutcome.new(kind: 'corrupt', consumed: nil)
        else
          Store::DeleteIfPendingOutcome.new(kind: 'consumed', consumed: retained_snapshot(decoded))
        end
      else
        Store::DeleteIfPendingOutcome.new(kind: 'corrupt', consumed: nil)
      end
    rescue StandardError => e
      raise StoreUnavailableError, "the redis cleanup script failed: #{e.message}"
    end

    private

    def record_key(nonce)
      "#{@prefix}#{nonce}"
    end

    def decode_raw(raw)
      return nil if raw.nil? || raw == ''

      Store.decode_envelope(raw)
    end

    def retained_snapshot(decoded)
      Store::ConsumedRecordSnapshot.new(
        record: decoded.record, consumed_now: false, consumed_before: true,
        consumed_result: decoded.result, operation_identity: decoded.identity
      )
    end

    def eval_script(name, script, keys, args)
      sha = @script_sha[name]
      begin
        @client.evalsha(sha, keys: keys, argv: args)
      rescue StandardError => e
        raise unless e.message.to_s.upcase.include?('NOSCRIPT')

        @client.eval(script, keys: keys, argv: args)
      end
    end
  end
end
