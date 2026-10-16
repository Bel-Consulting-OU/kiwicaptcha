import { createHash } from 'node:crypto';
import type { ChallengeRecord } from '../record.js';
import { challengeRecordToJson } from '../record.js';
import {
  DEFAULT_TTL_MARGIN_SECS,
  StoreUnavailableError,
  StoreWriteError,
  decodeEnvelope,
  validatedOperationIdentity,
  type ConsumedRecordSnapshot,
  type DeleteIfPendingOutcome,
  type RuntimeStateSnapshot,
  type StoreAdapter,
} from '../store.js';

/**
 * The Redis adapter. The record lives under `kiwicaptcha:<nonce>` (the
 * PHP backend's key) as one flat envelope JSON, so a mixed PHP and Node
 * fleet redeems cross-node. The consume and delete-if-pending
 * transitions run as Lua scripts through EVALSHA with a NOSCRIPT
 * fallback to EVAL; Redis serializes each script, so exactly one
 * racing caller wins the pending-to-consumed flip. The scripts splice
 * the raw JSON bytes and never re-encode the document, so large
 * integers (issued_at_ns) keep their exact spelling.
 */

/**
 * The structural shape of a Redis client this adapter drives: the
 * ioredis and node-redis method surface the scripts need. Declared
 * structurally so the core package carries zero runtime dependencies.
 */
export interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode: 'EX', ttl: number): Promise<unknown>;
  del(key: string): Promise<unknown>;
  pttl(key: string): Promise<number>;
  eval(script: string, numKeys: number, ...args: string[]): Promise<unknown>;
  evalsha(sha1: string, numKeys: number, ...args: string[]): Promise<unknown>;
  script(subcommand: 'LOAD', script: string): Promise<unknown>;
}

export interface RedisStoreOptions {
  /** Key prefix; the default matches the PHP RedisStorage key. */
  prefix?: string;
  /** Extra retention past the signed expiry. */
  ttlMarginSecs?: number;
  /** The storage clock in epoch seconds; a test seam. */
  now?: () => number;
}

const ENVELOPE_LUA_PRELUDE = `
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
`;

const CONSUME_SCRIPT = ENVELOPE_LUA_PRELUDE + `
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
`;

const DELETE_IF_PENDING_SCRIPT = ENVELOPE_LUA_PRELUDE + `
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
`;

function sha1(text: string): string {
  return createHash('sha1').update(text).digest('hex');
}

export class RedisStore implements StoreAdapter {
  readonly authenticatedResultCommit = true;

  private readonly client: RedisLike;
  private readonly prefix: string;
  private readonly ttlMarginSecs: number;
  private readonly now: () => number;
  private readonly scriptSha = {
    consume: sha1(CONSUME_SCRIPT),
    deleteIfPending: sha1(DELETE_IF_PENDING_SCRIPT),
  };

  constructor(client: RedisLike, options: RedisStoreOptions = {}) {
    this.client = client;
    this.prefix = options.prefix ?? 'kiwicaptcha:';
    this.ttlMarginSecs = options.ttlMarginSecs ?? DEFAULT_TTL_MARGIN_SECS;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  private recordKey(nonce: string): string {
    return `${this.prefix}${nonce}`;
  }

  private async evalScript(
    name: 'consume' | 'deleteIfPending',
    script: string,
    keys: string[],
    args: string[],
  ): Promise<unknown> {
    const sha = this.scriptSha[name];
    try {
      return await this.client.evalsha(sha, keys.length, ...keys, ...args);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!message.toUpperCase().includes('NOSCRIPT')) {
        throw error;
      }
      return this.client.eval(script, keys.length, ...keys, ...args);
    }
  }

  async store(record: ChallengeRecord): Promise<void> {
    const envelope = {
      ...challengeRecordToJson(record),
      state: 'pending',
      consumed_result: null,
      operation_identity: null,
    };
    const ttl = Math.max(1, record.expiresAt - this.now() + this.ttlMarginSecs);
    await this.client.set(this.recordKey(record.nonce), JSON.stringify(envelope), 'EX', ttl);
  }

  private decodeRaw(raw: string | null): ReturnType<typeof decodeEnvelope> {
    if (raw === null || raw === '') {
      return null;
    }
    return decodeEnvelope(raw);
  }

  async find(nonce: string): Promise<ChallengeRecord | null> {
    const decoded = this.decodeRaw(await this.client.get(this.recordKey(nonce)));
    return decoded === null ? null : decoded.record;
  }

  async runtimeState(nonce: string): Promise<RuntimeStateSnapshot> {
    const decoded = this.decodeRaw(await this.client.get(this.recordKey(nonce)));
    if (decoded === null) {
      return { kind: 'missing', record: null, consumed: null };
    }
    if (decoded.state === 'cancelled') {
      return { kind: 'cancelled', record: decoded.record, consumed: null };
    }
    if (decoded.state === 'consumed') {
      return {
        kind: 'consumed',
        record: decoded.record,
        consumed: {
          record: decoded.record,
          consumedNow: false,
          consumedBefore: true,
          consumedResult: decoded.result,
          operationIdentity: decoded.identity,
        },
      };
    }
    if (decoded.state === 'pending') {
      return { kind: 'pending', record: decoded.record, consumed: null };
    }
    return { kind: 'missing', record: null, consumed: null };
  }

  async consume(nonce: string, operationIdentity?: string | null): Promise<ConsumedRecordSnapshot | null> {
    const identity = validatedOperationIdentity(operationIdentity);
    const identityArg = identity === null ? '' : JSON.stringify(identity);
    let raw: unknown;
    try {
      raw = await this.evalScript('consume', CONSUME_SCRIPT, [this.recordKey(nonce)], [identityArg]);
    } catch (error) {
      throw new StoreUnavailableError('the redis consume script failed', { cause: error });
    }
    if (raw === null || raw === false || !Array.isArray(raw)) {
      // nil = missing/cancelled/corrupt, false = persistent foreign key.
      return null;
    }
    const [json, consumedNow, consumedBefore] = raw as [string, number, number];
    const identitySpliced = Number(raw[4] ?? 0);
    if (identityArg !== '' && Number(consumedNow) === 1 && identitySpliced !== 1) {
      throw new StoreWriteError(
        'the consume transition could not record the operation identity on the flipped envelope',
      );
    }
    const decoded = this.decodeRaw(String(json));
    if (decoded === null) {
      return null;
    }
    return {
      record: decoded.record,
      consumedNow: Number(consumedNow) === 1,
      consumedBefore: Number(consumedBefore) === 1,
      consumedResult: decoded.result,
      operationIdentity: decoded.identity,
    };
  }

  async commitResult(
    nonce: string,
    valid: boolean,
    binding: string | null,
    mac: string | null,
  ): Promise<boolean> {
    const raw = await this.client.get(this.recordKey(nonce));
    const decoded = this.decodeRaw(raw);
    if (raw === null || decoded === null || decoded.state !== 'consumed' || decoded.result !== null) {
      return false;
    }
    const envelope = JSON.parse(raw) as Record<string, unknown>;
    const result: Record<string, unknown> = { valid, binding };
    if (mac !== null) {
      result.mac = mac;
    }
    envelope.consumed_result = result;
    // Preserve the key's remaining lifetime exactly as the core's
    // commit does: read PTTL, refuse a persistent foreign key, floor
    // the sub-second remainder.
    const pttl = await this.client.pttl(this.recordKey(nonce));
    if (pttl < 0) {
      return false;
    }
    await this.client.set(this.recordKey(nonce), JSON.stringify(envelope), 'EX', Math.max(1, Math.ceil(pttl / 1000)));
    return true;
  }

  async deleteIfPending(nonce: string): Promise<DeleteIfPendingOutcome> {
    let raw: unknown;
    try {
      raw = await this.evalScript('deleteIfPending', DELETE_IF_PENDING_SCRIPT, [this.recordKey(nonce)], []);
    } catch (error) {
      throw new StoreUnavailableError('the redis cleanup script failed', { cause: error });
    }
    if (!Array.isArray(raw) || raw.length === 0) {
      return { kind: 'corrupt' };
    }
    const kind = String(raw[0]);
    if (kind === 'missing') {
      return { kind: 'missing' };
    }
    if (kind === 'deleted-pending') {
      return { kind: 'deleted-pending' };
    }
    if (kind === 'cancelled') {
      return { kind: 'cancelled' };
    }
    if (kind === 'corrupt') {
      return { kind: 'corrupt' };
    }
    const decoded = this.decodeRaw(String(raw[1]));
    if (kind !== 'consumed' || decoded === null) {
      return { kind: 'corrupt' };
    }
    return {
      kind: 'consumed',
      consumed: {
        record: decoded.record,
        consumedNow: false,
        consumedBefore: true,
        consumedResult: decoded.result,
        operationIdentity: decoded.identity,
      },
    };
  }
}
