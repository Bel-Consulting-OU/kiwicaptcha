-- Outcome ledger confirm: PENDING -> L/A exactly once.
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     1
--   max Redis calls:      2 (GET + SET)
--   max collection cardinality: none
--
-- KEYS[1] ledger; ARGV[1] outcome ('L'/'A'), ARGV[2] outcome TTL
--
-- Every argument is validated BEFORE the first write, like the sibling
-- calibration scripts: a caller passing a hostile outcome or TTL must get
-- an error and leave the ledger untouched, never mutate it to an
-- unconfirmable state or abort after the mutation on an invalid `EX`.
local EXPIRY_CEILING_SECS = 2147483647

if ARGV[1] ~= 'L' and ARGV[1] ~= 'A' then
    return redis.error_reply('outcome_confirm: outcome must be L or A')
end
local outcome_ttl = tonumber(ARGV[2])
if outcome_ttl == nil or outcome_ttl < 1 or outcome_ttl > EXPIRY_CEILING_SECS or outcome_ttl ~= math.floor(outcome_ttl) then
    return redis.error_reply('outcome_confirm: outcome_ttl_s must be a positive integer no greater than 2147483647')
end

local raw = redis.call('GET', KEYS[1])
if not raw then
    return 0
end
local ledger = cjson.decode(raw)
if type(ledger) ~= 'table' or ledger.o ~= 'P' then
    return 0
end
ledger.o = ARGV[1]
redis.call('SET', KEYS[1], cjson.encode(ledger), 'EX', outcome_ttl)
return 1
