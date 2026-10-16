<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The Lua half of the strict persisted-JSON authority: a recursive
 * duplicate-key scanner over the RAW stored bytes, with the same
 * semantic rule as the PHP {@see \KiwiCaptcha\Storage\StrictJson}
 * decoder and the HTTP request-body scanner.
 *
 * cjson.decode collapses two members whose keys decode to the same name:
 * an escaped alias such as `"st\u0061te"` is the same field as
 * `"state"`. Every transition that decodes a persisted chain,
 * disposition or SiteVerify record must call `decodeUniqueObject()`
 * instead of cjson.decode directly. A malformed, oversized, over-deep
 * or semantically duplicated document returns nil, and the caller
 * fails closed exactly like a corrupt record.
 *
 * The scanner follows the core envelope scanner in
 * {@see \KiwiCaptcha\Storage\RedisStorage}: the walk compares bytes
 * (string.byte) and jumps between structural characters with plain
 * string.find searches, so no substring is allocated per byte. The
 * uniqueness proof and the structural walk are one forward traversal of
 * the document; the decoded table comes from the single cjson.decode
 * the caller needs anyway.
 */
final class PersistedJsonLuaPredicate
{
    /** The shared 128 KiB byte ceiling (PHP StrictJson, Rust decoder, envelope parser). */
    public const MAX_BYTES = 131072;

    /** The recursive depth ceiling of the scanner. */
    public const MAX_DEPTH = 32;

    public const LUA = <<<'LUA'
-- Shared strict persisted-JSON decoding (the Lua half of the authority).
--
-- The walk compares bytes (string.byte) and jumps between structural
-- characters with plain string.find searches, the shape the core
-- envelope scanner in RedisStorage.php uses: a substring allocation per
-- byte is what a JSON scanner of this kind cannot afford. One forward
-- traversal proves the document semantically unique at every nesting
-- level, bounds the recursion and finds the end of the top-level
-- object; the decoded table comes from the single cjson.decode the
-- caller needs anyway.
local KIWI_PERSISTED_MAX_BYTES = 131072
local KIWI_PERSISTED_MAX_DEPTH = 32

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

-- The byte class that ends a scalar value: any bracket, comma or JSON
-- whitespace byte. The scans jump to it with one plain search each.
local KIWI_PERSISTED_VALUE_STOP_PATTERN = '[,}%] \t\r\n]'

local function kiwiPersistedSkipWs(v, i, n)
  while i <= n do
    local b = string.byte(v, i)
    if b ~= KIWI_B_SPACE and b ~= KIWI_B_TAB and b ~= KIWI_B_LF and b ~= KIWI_B_CR then break end
    i = i + 1
  end
  return i
end

-- i points at the opening quote; returns the index AFTER the matching
-- closing quote, or nil when the string is unterminated. The scan jumps
-- quote to quote with one plain search each and only counts the
-- backslash run in front of a quote to decide whether it is escaped.
local function kiwiPersistedScanString(v, i, n)
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

local kiwiPersistedScanValue
local kiwiPersistedScanObject
local kiwiPersistedScanArray

-- The DECODED name of the quoted key token spanning [i, keyEnd - 1]. A
-- token carrying neither a backslash escape nor a raw NUL decodes to
-- exactly its inner bytes (cjson accepts every other byte verbatim, so
-- the plain read is exact); every other token is decoded through cjson
-- and refused when it does not decode.
local function kiwiPersistedKeyName(v, i, keyEnd)
  local inner = string.sub(v, i + 1, keyEnd - 2)
  if string.find(inner, '\\', 1, true) == nil and string.find(inner, '\0', 1, true) == nil then
    return inner
  end
  local ok, decoded = pcall(cjson.decode, '"' .. inner .. '"')
  if not ok or type(decoded) ~= 'string' then return nil end
  return decoded
end

kiwiPersistedScanValue = function(v, i, n, depth)
  if depth > KIWI_PERSISTED_MAX_DEPTH then return nil end
  if i > n then return nil end
  local b = string.byte(v, i)
  if b == KIWI_B_OBRACE then
    return kiwiPersistedScanObject(v, i + 1, n, depth)
  end
  if b == KIWI_B_OBRACKET then
    return kiwiPersistedScanArray(v, i + 1, n, depth)
  end
  if b == KIWI_B_QUOTE then
    return kiwiPersistedScanString(v, i, n)
  end
  local stop = string.find(v, KIWI_PERSISTED_VALUE_STOP_PATTERN, i)
  if stop == nil then stop = n + 1 end
  if stop == i then return nil end
  return stop
end

kiwiPersistedScanObject = function(v, i, n, depth)
  if depth > KIWI_PERSISTED_MAX_DEPTH then return nil end
  local seen = {}
  i = kiwiPersistedSkipWs(v, i, n)
  if i <= n and string.byte(v, i) == KIWI_B_CBRACE then return i + 1 end
  while true do
    i = kiwiPersistedSkipWs(v, i, n)
    if i > n or string.byte(v, i) ~= KIWI_B_QUOTE then return nil end
    local keyEnd = kiwiPersistedScanString(v, i, n)
    if keyEnd == nil then return nil end
    -- The key is compared SEMANTICALLY: cjson.decode resolves the
    -- escapes, so an escaped alias is the same field (and a second
    -- occurrence is an ambiguous document).
    local key = kiwiPersistedKeyName(v, i, keyEnd)
    if key == nil then return nil end
    if seen[key] ~= nil then return nil end
    seen[key] = true
    i = kiwiPersistedSkipWs(v, keyEnd, n)
    if i > n or string.byte(v, i) ~= KIWI_B_COLON then return nil end
    i = kiwiPersistedScanValue(v, kiwiPersistedSkipWs(v, i + 1, n), n, depth + 1)
    if i == nil then return nil end
    i = kiwiPersistedSkipWs(v, i, n)
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

kiwiPersistedScanArray = function(v, i, n, depth)
  if depth > KIWI_PERSISTED_MAX_DEPTH then return nil end
  i = kiwiPersistedSkipWs(v, i, n)
  if i <= n and string.byte(v, i) == KIWI_B_CBRACKET then return i + 1 end
  while true do
    i = kiwiPersistedScanValue(v, i, n, depth + 1)
    if i == nil then return nil end
    i = kiwiPersistedSkipWs(v, i, n)
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

-- The strict decode of one persisted JSON object: nil when the document
-- is not a single well-formed object, exceeds the byte/depth ceilings,
-- or carries two members with the same decoded name. Callers must treat
-- nil exactly like corrupt state and perform zero writes.
local function decodeUniqueObject(raw)
  if type(raw) ~= 'string' then return nil end
  local n = #raw
  if n == 0 or n > KIWI_PERSISTED_MAX_BYTES then return nil end
  local i = kiwiPersistedSkipWs(raw, 1, n)
  if i > n or string.byte(raw, i) ~= KIWI_B_OBRACE then return nil end
  local endIndex = kiwiPersistedScanObject(raw, i + 1, n, 0)
  if endIndex == nil then return nil end
  if kiwiPersistedSkipWs(raw, endIndex, n) <= n then return nil end
  local ok, decoded = pcall(cjson.decode, raw)
  if not ok or type(decoded) ~= 'table' then return nil end
  return decoded
end

-- The one present-key lifetime read of persisted security state: the
-- value, the Lua boolean false when the key is genuinely ABSENT, or the
-- string 'corrupt' when a PRESENT key is damaged (an empty value, or a
-- key without a lifetime: PTTL -1 means a stripped TTL, a bad restore,
-- or a foreign writer). The PTTL sentinels are exact: a live key with a
-- sub-second remainder legitimately reports PTTL 0 and is LIVE, never
-- corrupt. A persistent key must never be treated as live
-- authorization-bearing state: every caller fails closed with zero
-- mutations exactly like a structural record violation, the same
-- present-key rule the chain store's chainKeyLifetimeMissing() applies.
-- GET and PTTL run in the same script, so no expiry can interleave
-- between them. Only Redis's missing sentinel means absent: a present
-- empty value proceeds to the corruption answer, so damaged state is
-- never healed into a fresh state machine.
local function readLivePersistedKey(key)
  local existing = redis.call('GET', key)
  if not existing then return false end
  if existing == '' then return 'corrupt' end
  local pttl = tonumber(redis.call('PTTL', key))
  if pttl == nil or pttl == -1 then return 'corrupt' end
  if pttl == -2 then return false end
  if pttl < 0 then return 'corrupt' end
  return existing
end

LUA;
}
