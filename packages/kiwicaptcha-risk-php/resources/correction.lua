-- Calibration correction: flip the outcome ledger + reverse/redo the
-- bucket contribution, ATOMICALLY (canonical, shared PHP/Rust).
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     2
--   max Redis calls:      15 (1 GET + 4 HINCRBYFLOAT + 4 HGET + 4 HSET +
--                            1 EXPIRE + 1 SET)
--   max collection cardinality: none (cjson decode of the bounded ledger
--                           string only)
--
-- KEYS[1]  outcome ledger entry (STRING, JSON {"o","scope","hour","score","w"})
-- KEYS[2]  DECISION-TIME calibration bucket (scope, ledger.hour)
-- ARGV[1]  new outcome ('L' = legitimate, 'A' = abuse)
-- ARGV[2]  weight (decimal string; the inverse sampling probability, 1
--          otherwise; validated)
-- ARGV[3]  bucket TTL (seconds)
-- ARGV[4]  outcome ledger TTL (seconds)
-- ARGV[5]  expected scope (must equal ledger.scope)
-- ARGV[6]  expected decision_hour (must equal ledger.hour)
--
-- The correction REVERSES the original contribution using the exact
-- weight recorded by the first confirmation (ledger.w) and adds the
-- corrected contribution: abuse_count/abuse_score_sum <-> legit_count/
-- legit_score_sum. If the decision-time bucket has already expired
-- (outside the calibration window), the ledger still flips — the
-- corrected outcome is authoritative for future events while the superseded
-- ephemeral reputation pressure is left to decay naturally (Kiwi does
-- not pretend to reverse already-decayed leaky counters). Reversed
-- fields are clamped at zero.
--
-- Returns 1 when the correction was applied, 0 when the decision is
-- unknown/expired or already carries the target outcome.

local raw = redis.call('GET', KEYS[1])
if not raw then
    return 0
end
local ledger = cjson.decode(raw)
if type(ledger) ~= 'table' or not ledger.o then
    return 0
end
if ledger.o ~= 'P' and ledger.o ~= 'L' and ledger.o ~= 'A' then
    return 0
end
if tonumber(ledger.scope or 0) ~= tonumber(ARGV[5])
   or tonumber(ledger.hour or 0) ~= tonumber(ARGV[6]) then
    return 0
end

local new_o = ARGV[1]
if new_o ~= 'L' and new_o ~= 'A' then
    return redis.error_reply('invalid correction outcome')
end
if ledger.o == new_o then
    return 0
end

local weight = tonumber(ARGV[2])
if not weight or weight <= 0 or weight ~= weight or weight == math.huge then
    return redis.error_reply('invalid correction weight')
end

local score = tonumber(ledger.score or 0)
if score < 0 then score = 0 end
if score > 1000 then score = 1000 end

-- Reverse the original contribution (exact recorded weight).
local old_w = tonumber(ledger.w or 1)

-- PRODUCT GUARD (pre-mutation, the calibration.lua non-finite-guard style):
-- both bucket contributions are score * weight products (the reversal uses
-- the ledger's recorded weight, the redo the caller's). A finite-but-huge
-- weight (>= ~1.7e305) or a tampered ledger weight ("1e999" -> +Inf) makes
-- the product +Inf/NaN and HINCRBYFLOAT errors mid-script with no
-- rollback. Any weight that is not a finite number, or any product that is
-- NaN or beyond ±1e100 (score is bounded 0..1000, so a legitimate product
-- is bounded by ~1e100), rejects the whole correction BEFORE the first
-- bucket mutation, leaving the ledger and bucket untouched for a retry
-- with a sane weight.
if not old_w or old_w < 0 or old_w ~= old_w or old_w == math.huge then
    return redis.error_reply('invalid calibration weight product')
end
local product_old = score * old_w
local product_new = score * weight
if not (product_old == product_old) or product_old > 1e100 or product_old < -1e100
   or not (product_new == product_new) or product_new > 1e100 or product_new < -1e100 then
    return redis.error_reply('invalid calibration weight product')
end

if ledger.o == 'L' then
    redis.call('HINCRBYFLOAT', KEYS[2], 'legit_count', -old_w)
    redis.call('HINCRBYFLOAT', KEYS[2], 'legit_score_sum', -(score * old_w))
else
    redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_count', -old_w)
    redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_score_sum', -(score * old_w))
end

-- Clamp the reversed fields at zero.
local function clamp_field(field)
    local v = tonumber(redis.call('HGET', KEYS[2], field) or '0')
    if v < 0 then
        redis.call('HSET', KEYS[2], field, 0)
    end
end
clamp_field('legit_count')
clamp_field('legit_score_sum')
clamp_field('abuse_count')
clamp_field('abuse_score_sum')

-- Add the corrected contribution.
if new_o == 'L' then
    redis.call('HINCRBYFLOAT', KEYS[2], 'legit_count', weight)
    redis.call('HINCRBYFLOAT', KEYS[2], 'legit_score_sum', score * weight)
else
    redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_count', weight)
    redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_score_sum', score * weight)
end
redis.call('EXPIRE', KEYS[2], tonumber(ARGV[3]))

ledger.o = new_o
ledger.w = weight
redis.call('SET', KEYS[1], cjson.encode(ledger), 'EX', tonumber(ARGV[4]))

return 1
