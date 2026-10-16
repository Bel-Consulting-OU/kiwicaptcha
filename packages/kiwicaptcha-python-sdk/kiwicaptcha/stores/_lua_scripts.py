"""The Redis transition scripts, extracted verbatim from the PHP
RedisStorage (packages/kiwicaptcha-php/src/Storage/RedisStorage.php).

The heredoc bodies are byte-identical to the PHP constants, so both
adapters classify and mutate the same stored envelopes with the same
Lua. The scripts carry the strict top-level field scanner, the
semantic-duplicate rejection and the raw-splice rule that never
re-encodes a stored document through a JSON codec. The literals are raw strings: the
backslash escapes inside belong to the Lua source, never to Python.
"""

ENVELOPE_LUA_PRELUDE = r'''-- Shared envelope inspection for the runtime transition scripts.
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
--
-- The classifier and the splice targets come from ONE walk of the
-- stored bytes: kiwiTopLevelFields() proves the document semantically
-- unique at every nesting level and returns the span of every
-- top-level field, and kiwiApplyEdits() lands the transition's edits
-- on those spans right to left, so no step re-walks the document. The
-- walk compares bytes (string.byte) and jumps between structural
-- characters with plain string.find searches; a substring allocation
-- per byte is what a JSON scanner of this kind cannot afford.
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

-- The byte classes the scans search for: the bytes that end a scalar
-- value (any bracket, comma or JSON whitespace byte).
local KIWI_VALUE_STOP_PATTERN = '[,}%] \t\r\n]'

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

-- i points at an opening quote; returns the index AFTER the matching
-- closing quote, or nil when the string is unterminated. The scan jumps
-- quote to quote with one plain search each and only counts the
-- backslash run in front of a quote to decide whether it is escaped.
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

-- The recursive semantic-duplicate scan of a whole stored document: a
-- JSON object may not carry two members whose keys decode to the same
-- name at ANY nesting level (an escaped alias such as "st\u0061te" is
-- the same field as "state"). This is the same authority the Symfony
-- persisted-state predicate (PersistedJsonLuaPredicate) applies, so the
-- core envelope and the state machines share one cleanliness rule.
local kiwiUniqueScanValue
local kiwiUniqueScanObject
local kiwiUniqueScanArray

-- The DECODED name of the quoted key token spanning [i, keyEnd - 1]. A
-- token carrying neither a backslash escape nor a raw NUL decodes to
-- exactly its inner bytes (cjson accepts every other byte verbatim, so
-- the plain read is exact); every other token is decoded through cjson
-- and refused when it does not decode.
local function kiwiKeyName(v, i, keyEnd)
  local inner = string.sub(v, i + 1, keyEnd - 2)
  if string.find(inner, '\\', 1, true) == nil and string.find(inner, '\0', 1, true) == nil then
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

-- The spans of every TOP-LEVEL field of the JSON object v, indexed by
-- the field's DECODED (semantic) name as {key_start, value_start,
-- value_end}. Returns nil when v is not a JSON object, the document
-- exceeds the byte ceiling, the document is malformed, or two members
-- decode to the same name: JSON keys may carry escapes ("st\u0061te"
-- is the key `state`), and cjson.decode() resolves them, so the
-- spelling the classifier sees must also be the spelling the scanner
-- keys on. An envelope with a semantic duplicate is ambiguous
-- corruption and is never classified or mutated by a transition —
-- exactly like the HTTP layer's duplicate-key scanner.
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

-- Apply the transition's edits to the stored bytes in ONE walk: every
-- span was measured on the SAME v by kiwiTopLevelFields, so no edit
-- re-inspects the document. Each edit is {from, to, literal, remove}:
-- a value splice carries the replacement literal, a field removal
-- carries the flag and drops the field with one adjacent comma, whose
-- side is decided on the bytes as they stand when the edit runs (a
-- right-to-left application never moves the bytes at or before `from`,
-- so every span stays exact).
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

-- Append a raw field literal before the object's closing brace, or nil
-- when the document is not a JSON object.
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

-- The decoded top-level envelope, or nil when the value exceeds the
-- byte ceiling or is not a JSON object.
local function kiwiDecodeEnvelope(v)
  if #v > KIWI_ENVELOPE_MAX_BYTES then return nil end
  local ok, decoded = pcall(cjson.decode, v)
  if not ok or type(decoded) ~= 'table' then return nil end
  return decoded
end
'''

CONSUME_SCRIPT = ENVELOPE_LUA_PRELUDE + r'''-- kiwicaptcha consume transition
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
local stored = v
local decoded = kiwiDecodeEnvelope(v)
if decoded == nil then
  return nil
end
-- ONE walk proves the document semantically unique at every nesting
-- level and locates every top-level span the transition splices below.
-- A semantically duplicated top-level field (an escaped alias such as
-- "st\u0061te") makes the envelope ambiguous corruption: no transition
-- may classify or mutate it.
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
  -- The flip and the identity splice land on spans measured on the
  -- same bytes; kiwiApplyEdits() applies them right to left, so the
  -- flip can never redirect the identity splice or the other way round.
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
  -- A cancelled record (or any other non-pending state) is never
  -- consumable: the transition reports the record as missing (nil) and
  -- the verifier fails the token closed instead of ever redeeming it.
  return nil
end
-- The committed result payload: the raw bytes of the top-level
-- consumed_result value, or 'null' when the field is absent or null.
local resultJson = 'null'
local resultSpan = fields['consumed_result']
if resultSpan ~= nil then
  -- Read from the stored bytes: the splices above never touch the
  -- consumed_result value, so its span still describes it exactly.
  local value = string.sub(stored, resultSpan[2], resultSpan[3])
  if value ~= 'null' then
    resultJson = value
  end
end
return {v, consumedNow, consumedBefore, resultJson, identitySpliced}
'''

DELETE_IF_PENDING_SCRIPT = ENVELOPE_LUA_PRELUDE + r'''-- kiwicaptcha delete-if-pending (atomic cleanup)
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
-- ONE walk proves the document semantically unique at every nesting
-- level while locating the top-level spans. A semantically duplicated
-- top-level field (an escaped alias such as "st\u0061te") makes the
-- envelope ambiguous corruption: no transition may classify or mutate
-- it.
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
'''

CANCEL_SCRIPT = ENVELOPE_LUA_PRELUDE + r'''-- kiwicaptcha cancel transition
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
-- ONE walk proves the document semantically unique at every nesting
-- level and locates every top-level span the flip below targets. A
-- semantically duplicated top-level field (an escaped alias such as
-- "st\u0061te") makes the envelope ambiguous corruption: no
-- transition may classify or mutate it.
local fields = kiwiTopLevelFields(v)
if fields == nil then
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
local stateSpan = fields['state']
if stateSpan == nil then
  return nil
end
local updated = kiwiApplyEdits(v, {{stateSpan[2], stateSpan[3], '"cancelled"'}})
redis.call("SET", KEYS[1], updated, "PX", pttl)
return {'cancelled-now'}
'''

COMMIT_SCRIPT = ENVELOPE_LUA_PRELUDE + r'''-- kiwicaptcha commit result
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
-- ONE walk proves the document semantically unique at every nesting
-- level and locates every top-level span the mutation below targets. A
-- semantically duplicated top-level field (an escaped alias such as
-- "st\u0061te") makes the envelope ambiguous corruption: no
-- transition may classify or mutate it.
local fields = kiwiTopLevelFields(v)
if fields == nil then
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
-- The result splice and, on the resume path, the claim clear land on
-- spans measured on the stored bytes: kiwiApplyEdits() applies them
-- right to left in one pass.
local resultSpan = fields['consumed_result']
if resultSpan == nil then
  return 0
end
local edits = {{resultSpan[2], resultSpan[3], encoded}}
if claim then
  local untilSpan = fields['resume_until']
  local ownerSpan = fields['resume_owner']
  if untilSpan == nil or ownerSpan == nil then
    return 0
  end
  edits[#edits + 1] = {untilSpan[1], untilSpan[3], nil, true}
  edits[#edits + 1] = {ownerSpan[1], ownerSpan[3], nil, true}
end
local updated = kiwiApplyEdits(v, edits)
redis.call("SET", KEYS[1], updated, "PX", pttl)
return 1
'''

