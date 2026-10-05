-- Long-memory outcome marks: one atomic mark write.
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     1
--   max Redis calls:      4 (HSET + HSETNX + HINCRBY + PEXPIRE)
--   max collection cardinality: 4 hash fields
--
-- KEYS[1] mark; ARGV[1] kind (the outcome name), ARGV[2] now (epoch ms),
-- ARGV[3] mark TTL (milliseconds).
--
-- The mark is the hash {kind, count, first_ms, last_ms}: kind carries
-- the most recent outcome name, count the total writes (monotone; only
-- the erasure path removes a mark), first_ms the first write's
-- timestamp (written once) and last_ms the most recent one. Every write
-- refreshes the whole-key TTL, so an identity that keeps earning marks
-- never silently expires while a marked-and-forgotten one disappears
-- after exactly one window.
--
-- Every argument is validated BEFORE the first write, like the sibling
-- outcome-ledger scripts: a hostile kind or TTL must error with the
-- mark untouched instead of aborting after the mutation (Redis does
-- not roll back).
local EXPIRY_CEILING_MS = 2147483647 * 1000

if ARGV[1] == nil or ARGV[1] == '' or #ARGV[1] > 64 then
    return redis.error_reply('marks: kind must be a non-empty value of at most 64 bytes')
end
local now_ms = tonumber(ARGV[2])
if now_ms == nil or now_ms < 0 or now_ms ~= math.floor(now_ms) then
    return redis.error_reply('marks: now_ms must be a non-negative integer')
end
local ttl_ms = tonumber(ARGV[3])
if ttl_ms == nil or ttl_ms < 1 or ttl_ms > EXPIRY_CEILING_MS or ttl_ms ~= math.floor(ttl_ms) then
    return redis.error_reply('marks: ttl_ms must be a positive integer no greater than 2147483647000')
end

redis.call('HSET', KEYS[1], 'kind', ARGV[1], 'last_ms', now_ms)
redis.call('HSETNX', KEYS[1], 'first_ms', now_ms)
local count = redis.call('HINCRBY', KEYS[1], 'count', 1)
redis.call('PEXPIRE', KEYS[1], ttl_ms)
return count
