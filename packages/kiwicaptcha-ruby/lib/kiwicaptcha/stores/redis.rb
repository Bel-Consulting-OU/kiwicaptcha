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
    LUA

    CONSUME_SCRIPT = ENVELOPE_LUA_PRELUDE + <<~LUA
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
