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
`;

const CONSUME_SCRIPT = ENVELOPE_LUA_PRELUDE + `
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
