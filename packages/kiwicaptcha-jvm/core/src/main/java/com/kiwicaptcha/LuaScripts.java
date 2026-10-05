package com.kiwicaptcha;

/**
 * The Redis transition scripts, extracted verbatim from the php
 * RedisStorage and byte-identical with the Go and Python adapters'
 * copies, so every adapter classifies and mutates the same stored
 * envelopes with the same Lua. The scripts carry the strict top-level
 * field scanner, the semantic-duplicate rejection and the raw-splice
 * rule that never re-encodes a stored document through a json codec.
 */
public final class LuaScripts {
    private LuaScripts() {}

    /** The shared envelope inspection prelude. */
    static final String ENVELOPE_PRELUDE = """
            -- Shared envelope inspection for the runtime transition scripts.
            --
            -- The runtime state is classified from the decoded top-level envelope,
            -- never from a whole-document byte search: a corrupt or foreign value
            -- that merely CONTAINS a nested "state":"pending" (or consumed /
            -- cancelled) string can never drive a transition. The mutations still
            -- splice the raw JSON bytes (the record is never re-encoded through
            -- cjson, so large integers never switch to scientific notation), and
            -- every splice targets the top-level field span located by the scanner
            -- below, so a nested occurrence can never be rewritten either. The
            -- byte ceiling bounds the JSON parse before it happens.
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

            local function kiwiSkipSpaceBack(v, j)
              while j >= 1 do
                local c = string.sub(v, j, j)
                if not kiwiIsSpace(c) then break end
                j = j - 1
              end
              return j
            end

            -- The index of the LAST byte of the JSON value starting at s, or nil
            -- when the value is malformed.
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
                    local esc = false
                    while i <= n do
                      local cj = string.sub(v, i, i)
                      if esc then esc = false
                      elseif cj == '\\\\' then esc = true
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

            -- The recursive semantic-duplicate scan of a whole stored document: a
            -- JSON object may not carry two members whose keys decode to the same
            -- name at ANY nesting level (an escaped alias such as "st\\u0061te" is
            -- the same field as "state"). This is the same authority the Symfony
            -- persisted-state predicate (PersistedJsonLuaPredicate) applies, so the
            -- core envelope and the state machines share one cleanliness rule.
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

            -- True when the whole document is one well-formed JSON object with no
            -- semantic duplicate key at any nesting level and no trailing bytes.
            local function kiwiDocumentIsUnique(v)
              local n = #v
              if n == 0 or n > KIWI_ENVELOPE_MAX_BYTES then return false end
              local i = kiwiSkipSpace(v, 1, n)
              if i > n or string.sub(v, i, i) ~= '{' then return false end
              local endIndex = kiwiUniqueScanObject(v, i + 1, n, 0)
              if endIndex == nil then return false end
              return kiwiSkipSpace(v, endIndex, n) > n
            end

            -- The spans of every TOP-LEVEL field of the JSON object v, indexed by
            -- the field's DECODED (semantic) name as {key_start, value_start,
            -- value_end}. Returns nil when v is not a JSON object, the document
            -- exceeds the byte ceiling, the document is malformed, or two members
            -- decode to the same name: JSON keys may carry escapes ("st\\u0061te"
            -- is the key `state`), and cjson.decode() resolves them, so the
            -- spelling the classifier sees must also be the spelling the scanner
            -- keys on. An envelope with a semantic duplicate is ambiguous
            -- corruption and is never classified or mutated by a transition —
            -- exactly like the HTTP layer's duplicate-key scanner.
            local function kiwiTopLevelFields(v)
              local n = #v
              if n > KIWI_ENVELOPE_MAX_BYTES then return nil end
              -- The WHOLE document must be semantically unique at every nesting
              -- level before any top-level span is trusted (one cleanliness rule
              -- across the core envelope and the persisted-state machines).
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

            -- The spans of the top-level field `key`, or nil when it is absent,
            -- duplicated, or the document is malformed or oversized. Depth-,
            -- string- and escape-aware, so a nested field with the same name can
            -- never be mistaken for the envelope's own.
            local function kiwiTopLevelField(v, key)
              local fields = kiwiTopLevelFields(v)
              if fields == nil then return nil end
              return fields[key]
            end

            -- Replace the value of the top-level field `key` with the raw literal,
            -- or nil when the field is absent, duplicated or the document is
            -- malformed.
            local function kiwiReplaceTopLevel(v, key, literal)
              local span = kiwiTopLevelField(v, key)
              if span == nil then return nil end
              local head = string.sub(v, 1, span[2] - 1)
              local tail = string.sub(v, span[3] + 1)
              return head .. literal .. tail
            end

            -- Remove the top-level field `key` (with one adjacent comma), or nil
            -- when the field is absent, duplicated or the document is malformed.
            local function kiwiRemoveTopLevel(v, key)
              local span = kiwiTopLevelField(v, key)
              if span == nil then return nil end
              local i = span[3] + 1
              i = kiwiSkipSpace(v, i, #v)
              if string.sub(v, i, i) == ',' then
                return string.sub(v, 1, span[1] - 1) .. string.sub(v, i + 1)
              end
              local j = span[1] - 1
              j = kiwiSkipSpaceBack(v, j)
              if string.sub(v, j, j) == ',' then
                return string.sub(v, 1, j - 1) .. string.sub(v, span[3] + 1)
              end
              return string.sub(v, 1, span[1] - 1) .. string.sub(v, span[3] + 1)
            end

            -- Append a raw field literal before the object's closing brace, or nil
            -- when the document is not a JSON object.
            local function kiwiAppendTopLevel(v, literal)
              local n = #v
              local i = 1
              i = kiwiSkipSpace(v, i, n)
              if string.sub(v, i, i) ~= '{' then return nil end
              local depth = 0
              local last = nil
              local first = i
              while i <= n do
                local c = string.sub(v, i, i)
                if c == '"' then
                  i = i + 1
                  local esc = false
                  while i <= n do
                    local ci = string.sub(v, i, i)
                    if esc then esc = false
                    elseif ci == '\\\\' then esc = true
                    elseif ci == '"' then break end
                    i = i + 1
                  end
                  if i > n then return nil end
                elseif c == '{' or c == '[' then
                  depth = depth + 1
                elseif c == '}' or c == ']' then
                  depth = depth - 1
                  if depth == 0 then last = i break end
                end
                i = i + 1
              end
              if last == nil then return nil end
              local p = last - 1
              p = kiwiSkipSpaceBack(v, p)
              if p == first then
                return string.sub(v, 1, last - 1) .. literal .. string.sub(v, last)
              end
              return string.sub(v, 1, last - 1) .. ',' .. literal .. string.sub(v, last)
            end

            -- The decoded top-level envelope, or nil when the value exceeds the
            -- byte ceiling or is not a JSON object.
            local function kiwiDecodeEnvelope(v)
              if #v > KIWI_ENVELOPE_MAX_BYTES then return nil end
              local ok, decoded = pcall(cjson.decode, v)
              if not ok or type(decoded) ~= 'table' then return nil end
              return decoded
            end
            """;

    /** The consume transition. */
    public static final String CONSUME_SCRIPT = ENVELOPE_PRELUDE + """
            -- kiwicaptcha consume transition
            --
            -- CRITICAL: the record is never re-encoded through cjson — re-encoding
            -- rewrites large integers (issued_at_ns ~ 1.7e15) in scientific notation
            -- and breaks both strict parsers. The runtime state is classified from
            -- the decoded top-level envelope and every splice targets the top-level
            -- field span, so neither a nested state marker nor a nested
            -- `"state":"pending"` string can drive or redirect the transition. The
            -- logical-operation identity is spliced into the top-level
            -- `operation_identity` field in the same script when a non-empty
            -- identity argument is given; the splice is reported back (reply
            -- element 5): a non-empty identity that finds no top-level field leaves
            -- the flip in place but tells the caller, which refuses the transition
            -- result instead of silently dropping the identity. The identity has
            -- passed the shared OperationIdentity::validate() gate BEFORE the eval:
            -- 1..128 bytes of [A-Za-z0-9_-], so the replacement splice can never be
            -- interpreted as a Lua template. The transition winner receives the
            -- UPDATED bytes, so the recorded identity rides back on its own
            -- ConsumedRecord.
            local v = redis.call("GET", KEYS[1])
            if not v then
              return nil
            end
            local decoded = kiwiDecodeEnvelope(v)
            if decoded == nil then
              return nil
            end
            -- A semantically duplicated top-level field (an escaped alias such as
            -- "st\\u0061te") makes the envelope ambiguous corruption: no transition
            -- may classify or mutate it. kiwiTopLevelFields() rejects it, and the
            -- states below are still read from the decoded view when it is unique.
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
              -- The pending-envelope guard: a genuinely issued pending record
              -- carries only the null markers ("consumed_result":null and
              -- "operation_identity":null) and no claim lease fields. A pending
              -- envelope that ALSO carries a terminal or claim field (a non-null
              -- consumed_result, a non-null operation_identity, or any
              -- resume_owner / resume_until marker) is a corrupt or forged rewrite:
              -- the state marker was flipped without removing the carried fields.
              -- The transition REFUSES it with the missing/undecodable semantics
              -- (nil), so the verifier fails the token closed instead of
              -- re-deriving a fresh grant or installing the carried result. Only
              -- the consume transition itself may introduce these fields, and only
              -- into the envelope it just flipped.
              if not kiwiNullish(decoded['consumed_result'])
                or not kiwiNullish(decoded['operation_identity'])
                or not kiwiNullish(decoded['resume_owner'])
                or not kiwiNullish(decoded['resume_until']) then
                return nil
              end
              -- Lease preservation in milliseconds. PTTL < 0 means the key carries
              -- NO expiry (a persistent foreign key): the transition refuses
              -- without touching the bytes — rewriting it with a synthesized TTL
              -- would silently attach a lifetime to data its owner never gave one.
              -- A sub-second remainder is floored at 1000 ms so the flip can never
              -- mint an already-expired key.
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
              -- A cancelled record (or any other non-pending state) is never
              -- consumable: the transition reports the record as missing (nil) and
              -- the verifier fails the token closed instead of ever redeeming it.
              return nil
            end
            -- The committed result payload: the raw bytes of the top-level
            -- consumed_result value, or 'null' when the field is absent or null.
            local resultJson = 'null'
            local resultSpan = kiwiTopLevelField(v, 'consumed_result')
            if resultSpan ~= nil then
              local value = string.sub(v, resultSpan[2], resultSpan[3])
              if value ~= 'null' then
                resultJson = value
              end
            end
            return {v, consumedNow, consumedBefore, resultJson, identitySpliced}
            """;

    /** The atomic cheap-failure cleanup. */
    public static final String DELETE_IF_PENDING_SCRIPT = ENVELOPE_PRELUDE + """
            -- kiwicaptcha delete-if-pending (atomic cleanup)
            --
            -- The runtime state is classified from the decoded top-level envelope,
            -- never from a whole-document byte search: a value whose top-level
            -- state is unknown (or undecodable) is corrupt, reported without
            -- mutating the record, and a nested "state":"pending" string inside a
            -- corrupt value can never trigger the delete. A consumed record is
            -- returned verbatim and kept. A cancelled record is returned verbatim
            -- and kept too: the cancelled challenge is dead but retained until its
            -- TTL, never eagerly deleted. Only the exact pending state is deleted.
            --
            -- The DEL is a durability-critical write: the caller applies the same
            -- verified WAIT barrier as the other transitions, so a burned challenge
            -- that only vanished from the primary is substantially less likely to
            -- be resurrected as pending by a promoted stale replica (WAIT is
            -- durability hardening, not a consensus guarantee: Redis replication
            -- remains eventually consistent across every failover pattern).
            local v = redis.call("GET", KEYS[1])
            if not v then
              return {'missing'}
            end
            local decoded = kiwiDecodeEnvelope(v)
            if decoded == nil then
              return {'corrupt'}
            end
            -- A semantically duplicated top-level field (an escaped alias such as
            -- "st\\u0061te") makes the envelope ambiguous corruption: no transition
            -- may classify or mutate it. kiwiTopLevelFields() rejects it, and the
            -- states below are still read from the decoded view when it is unique.
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
            """;

    /** The terminal cancellation marker transition. */
    public static final String CANCEL_SCRIPT = ENVELOPE_PRELUDE + """
            -- kiwicaptcha cancel transition
            --
            -- CRITICAL: the record is never re-encoded through cjson — re-encoding
            -- rewrites large integers (issued_at_ns ~ 1.7e15) in scientific notation
            -- and breaks both strict parsers. The runtime state is classified from
            -- the decoded top-level envelope and the flip targets the top-level
            -- state field span, mirroring the consume transition. A consumed record
            -- is terminal and never cancellable; a cancelled record is idempotent;
            -- any other state is refused. The flip preserves the key's remaining
            -- lifetime in milliseconds; a key without an expiry (PTTL < 0) is
            -- refused untouched, never rewritten with a synthesized lifetime.
            local v = redis.call("GET", KEYS[1])
            if not v then
              return nil
            end
            local decoded = kiwiDecodeEnvelope(v)
            if decoded == nil then
              return nil
            end
            -- A semantically duplicated top-level field (an escaped alias such as
            -- "st\\u0061te") makes the envelope ambiguous corruption: no transition
            -- may classify or mutate it. kiwiTopLevelFields() rejects it, and the
            -- states below are still read from the decoded view when it is unique.
            if kiwiTopLevelFields(v) == nil then
              return nil
            end
            local state = decoded['state']
            if state == 'consumed' then
              return {'consumed'}
            end
            if state == 'cancelled' then
              return {'cancelled'}
            end
            if state ~= 'pending' then
              return nil
            end
            local pttl = redis.call("PTTL", KEYS[1])
            if pttl < 0 then
              return false
            end
            if pttl < 1000 then pttl = 1000 end
            local updated = kiwiReplaceTopLevel(v, 'state', '"cancelled"')
            if updated == nil then
              return nil
            end
            redis.call("SET", KEYS[1], updated, "PX", pttl)
            return {'cancelled-now'}
            """;

    /** The committed result write. */
    public static final String COMMIT_SCRIPT = ENVELOPE_PRELUDE + """
            -- kiwicaptcha commit result
            --
            -- CRITICAL: the record is never re-encoded through cjson — re-encoding
            -- rewrites large integers (issued_at_ns ~ 1.7e15) in scientific notation
            -- and breaks both strict parsers. The `consumed_result` field is
            -- replaced through its top-level span and the state is classified from
            -- the decoded top-level envelope, so a nested marker can never fake a
            -- committed or resultless record. Only the small result object is
            -- encoded — valid must be a REAL JSON boolean (matching the Rust commit
            -- Lua and the strict ConsumedResult parser), binding a string or null.
            --
            -- The resume-path claim is an optional fencing precondition carried in
            -- ARGV[4]: when non-empty, the envelope must hold a LIVE claim owned by
            -- exactly this token before the protected mutation is written. ARGV[5],
            -- when non-empty, is the server-state MAC stored inside the result.
            -- Ownership lost (missing, expired, or owned by a different token)
            -- returns 2 with no write, so a stale owner whose claim expired
            -- mid-derivation can never commit, and the successful write clears the
            -- claim fields in the same atomic transition. The lease expiry
            -- `resume_until` is epoch MICROSECONDS; the liveness comparison runs
            -- on the same microsecond clock (TIME with the microsecond part), so a
            -- claim TTL of N seconds fences for exactly N seconds. The claim is
            -- embedded in the record envelope, so this script touches exactly one
            -- key (single-slot on a Redis Cluster, never CROSSSLOT). Callers
            -- without a claim pass ARGV[4] = '': byte-identical behavior.
            -- A key without an expiry (PTTL < 0) is refused with 0 untouched,
            -- never rewritten with a synthesized lifetime; the result write
            -- preserves the key's remaining lifetime in milliseconds.
            local v = redis.call("GET", KEYS[1])
            if not v then
              return 0
            end
            local decoded = kiwiDecodeEnvelope(v)
            if decoded == nil then
              return 0
            end
            -- A semantically duplicated top-level field (an escaped alias such as
            -- "st\\u0061te") makes the envelope ambiguous corruption: no transition
            -- may classify or mutate it. kiwiTopLevelFields() rejects it, and the
            -- states below are still read from the decoded view when it is unique.
            if kiwiTopLevelFields(v) == nil then
              return 0
            end
            if decoded['state'] ~= 'consumed' then
              return 0
            end
            if not kiwiNullish(decoded['consumed_result']) then
              return 0
            end
            local claim = (ARGV[4] ~= nil) and (ARGV[4] ~= '')
            if claim then
              if decoded['resume_owner'] ~= ARGV[4] then
                return 2
              end
              local untilVal = tonumber(decoded['resume_until'])
              local t = redis.call("TIME")
              local nowUs = tonumber(t[1]) * 1000000 + tonumber(t[2])
              if untilVal == nil or untilVal <= nowUs then
                return 2
              end
            end
            local pttl = redis.call("PTTL", KEYS[1])
            if pttl < 0 then
              return 0
            end
            if pttl < 1000 then pttl = 1000 end
            local encoded
            if ARGV[5] ~= nil and ARGV[5] ~= '' then
              -- The server-state MAC (64 lowercase hex, validated by the caller)
              -- rides inside the result object verbatim.
              encoded = cjson.encode({
                valid = (ARGV[1] == '1'),
                binding = (ARGV[3] == "0") and cjson.null or ARGV[2],
                mac = ARGV[5]
              })
            else
              encoded = cjson.encode({
                valid = (ARGV[1] == '1'),
                binding = (ARGV[3] == "0") and cjson.null or ARGV[2]
              })
            end
            local updated = kiwiReplaceTopLevel(v, 'consumed_result', encoded)
            if updated == nil then
              return 0
            end
            if claim then
              local cleared = kiwiRemoveTopLevel(updated, 'resume_until')
              if cleared == nil then
                return 0
              end
              cleared = kiwiRemoveTopLevel(cleared, 'resume_owner')
              if cleared == nil then
                return 0
              end
              updated = cleared
            end
            redis.call("SET", KEYS[1], updated, "PX", pttl)
            return 1
            """;
}
