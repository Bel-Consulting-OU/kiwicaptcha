-- Principal first-seen network tags: one atomic seen/record/trust.
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     1 (the principal's tag hash; {kiwi:<ns>} tag)
--   max Redis calls:      5 (1 TIME + 1 HGET/HGETALL + 1 HSET + 1 HDEL +
--                           1 PEXPIRE on the record path; strictly fewer
--                           on the read paths)
--   max collection cardinality: 224 hash fields (32 session + 16 device
--                           + 64 net + 64 asn + 32+16+64+64 trust flags)
--
-- KEYS[1] principal tag hash (key form kiwi:<ns>:pnet:{<principal_hex>}).
-- ARGV[1] operation: 'seen', 'record', or 'has_trusted'.
-- ARGV[2] tag (net:<hex>, asn:<decimal>, session:<hex>, device:<hex>).
-- ARGV[3] class_ttl_ms (record only).
-- ARGV[4] class_cap (record only).
-- ARGV[5] trust ('1' = mint trust on record, '' or absent = do not).
--
-- The hash holds two kinds of field per tag: the bare tag carries the
-- last-use ms (Redis TIME, never a client clock), and a `t:` prefixed
-- mirror carries the trust flag ('1'). Trust is minted only on an Allow
-- or a completed step-up — a Deny path can never create a `t:` field.
-- has_trusted checks both the bare tag (for expiry) and the trust flag.
--
-- Class policy (validated against the TTL/cap bounds below):
--   session:  cap 32, TTL = 2x the continuity cookie TTL (default 3600 s)
--   device:   cap 16, TTL = the trusted-device TTL (default 90 days)
--   net/asn:  cap 64 each, TTL = 400 days
--
-- LRU: the record path evicts the least-recently-used entries in the
-- same class above the cap, reading the last-use value (never insertion
-- order). A trust flag is evicted with its tag.
--
-- PEXPIRE is set to the largest class TTL present after the write, so
-- the key expires when its oldest class would.
--
-- Every argument is validated BEFORE the first write: a hostile tag,
-- TTL or cap errors with the hash untouched. RESP2 false/nil is
-- treated as absent, matching assess_v2.
local EXPIRY_CEILING_MS = 2147483647 * 1000
local MIN_TTL_MS = 1
local MAX_CAP = 256

-- Class bounds: the TTL range each class may request and its cap ceiling.
local CLASS_TTL_MIN = {
    session = 60000,        -- 1 minute
    device = 60000,
    net = 86400000,         -- 1 day
    asn = 86400000,
}
local CLASS_TTL_MAX = {
    session = 86400000,     -- 1 day (2x a 12-hour cookie at most)
    device = 31536000000,   -- 365 days
    net = 34560000000,      -- 400 days
    asn = 34560000000,
}

local function classify(tag)
    local prefix = string.match(tag, '^([a-z]+):')
    if prefix == 'net' or prefix == 'session' or prefix == 'device' or prefix == 'asn' then
        return prefix
    end
    return nil
end

local function valid_tag(tag)
    if tag == nil or tag == '' or #tag > 80 then
        return false
    end
    -- net:<hex 1-64>, session:<hex 1-64>, device:<hex 1-64>
    if string.match(tag, '^net:[0-9a-f]+$') and #tag > 4 and #tag <= 68 then
        return true
    end
    if string.match(tag, '^session:[0-9a-f]+$') and #tag > 8 and #tag <= 72 then
        return true
    end
    if string.match(tag, '^device:[0-9a-f]+$') and #tag > 7 and #tag <= 71 then
        return true
    end
    -- asn:<decimal 1-10>
    if string.match(tag, '^asn:[0-9]+$') and #tag > 4 and #tag <= 14 then
        return true
    end
    return false
end

local op = ARGV[1]
if op ~= 'seen' and op ~= 'record' and op ~= 'has_trusted' then
    return redis.error_reply('pnet: op must be seen, record or has_trusted')
end

local tag = ARGV[2]
if not valid_tag(tag) then
    return redis.error_reply('pnet: tag must match net|session|device:<hex> or asn:<decimal>')
end

local class = classify(tag)

-- Distributed clock authority: Redis TIME.
local time = redis.call('TIME')
local now_ms = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)

local trust_key = 't:' .. tag

if op == 'seen' then
    local v = redis.call('HGET', KEYS[1], tag)
    if not v then
        return 0
    end
    local last = tonumber(v)
    if last == nil then
        return 0
    end
    local class_ttl = CLASS_TTL_MAX[class] or CLASS_TTL_MAX.net
    if now_ms - last > class_ttl then
        return 0
    end
    return 1
end

if op == 'has_trusted' then
    local v = redis.call('HGET', KEYS[1], tag)
    if not v then
        return 0
    end
    local last = tonumber(v)
    if last == nil then
        return 0
    end
    local class_ttl = CLASS_TTL_MAX[class] or CLASS_TTL_MAX.net
    if now_ms - last > class_ttl then
        return 0
    end
    local t = redis.call('HGET', KEYS[1], trust_key)
    if not t then
        return 0
    end
    return 1
end

-- op == 'record'
local ttl_ms = tonumber(ARGV[3])
local cap = tonumber(ARGV[4])
if ttl_ms == nil or ttl_ms < MIN_TTL_MS or ttl_ms > EXPIRY_CEILING_MS or ttl_ms ~= math.floor(ttl_ms) then
    return redis.error_reply('pnet: ttl_ms must be a positive integer within bounds')
end
if cap == nil or cap < 1 or cap > MAX_CAP or cap ~= math.floor(cap) then
    return redis.error_reply('pnet: cap must be a positive integer within bounds')
end
local class_min = CLASS_TTL_MIN[class] or CLASS_TTL_MIN.net
local class_max = CLASS_TTL_MAX[class] or CLASS_TTL_MAX.net
if ttl_ms < class_min or ttl_ms > class_max then
    return redis.error_reply('pnet: ttl_ms outside the class range')
end
local trust = ARGV[5]
if trust == nil then
    trust = '0'
end

-- Upsert the tag (SET NX semantics: first write wins).
local existed = redis.call('HGET', KEYS[1], tag)
redis.call('HSET', KEYS[1], tag, tostring(now_ms))
if trust == '1' then
    redis.call('HSET', KEYS[1], trust_key, '1')
end

-- LRU eviction within the class: collect class tags with their last-use,
-- evict the oldest above the cap.
local all = redis.call('HGETALL', KEYS[1])
local class_tags = {}
for i = 1, #all, 2 do
    local f = all[i]
    if f ~= trust_key and string.sub(f, 1, 2) ~= 't:' then
        local fclass = classify(f)
        if fclass == class then
            class_tags[#class_tags + 1] = { f, tonumber(all[i + 1]) or 0 }
        end
    end
end
if #class_tags > cap then
    -- Sort ascending by last-use (oldest first).
    table.sort(class_tags, function(a, b) return a[2] < b[2] end)
    local to_evict = #class_tags - cap
    for i = 1, to_evict do
        local victim = class_tags[i][1]
        redis.call('HDEL', KEYS[1], victim)
        redis.call('HDEL', KEYS[1], 't:' .. victim)
    end
end

-- PEXPIRE to the largest class TTL present.
local max_class_ttl = ttl_ms
for i = 1, #all, 2 do
    local f = all[i]
    if f ~= trust_key and string.sub(f, 1, 2) ~= 't:' then
        local fclass = classify(f)
        local fttl = CLASS_TTL_MAX[fclass] or CLASS_TTL_MAX.net
        if fttl > max_class_ttl then
            max_class_ttl = fttl
        end
    end
end
if max_class_ttl > EXPIRY_CEILING_MS then
    max_class_ttl = EXPIRY_CEILING_MS
end
redis.call('PEXPIRE', KEYS[1], max_class_ttl)

if existed then
    return 0
end
return 1
