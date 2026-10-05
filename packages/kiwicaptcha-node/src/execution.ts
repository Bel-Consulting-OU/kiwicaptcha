import { createHash, createHmac } from 'node:crypto';
import { decodeStdBase64, encodeStdBase64 } from './base64.js';

/**
 * The ExecutionChallengeV1 interpreter: the verifier-side decoder,
 * deterministic simulator and submitted-trace walker of the armed
 * execution dimension, mirroring the PHP ExecutionChallengeGenerator
 * and the Rust execution module. A program is a self-describing
 * bytecode blob; a submitted trace is the joined op(result) entry list
 * a real browser produced. The deterministic entries must equal the
 * simulation exactly; the browser-observed entries must satisfy their
 * construction-determined rules.
 */

export const EXECUTION_LABEL = 'kiwi-execution-v1';
export const EXECUTION_FORMAT_VERSION = 1;
export const EXECUTION_MAX_VERSION = 5;
export const EXECUTION_MIN_OPS = 8;
export const EXECUTION_MAX_OPS = 24;
export const EXECUTION_MAX_PROGRAM_BASE64 = 4096;
export const SRCDOC_PREEXISTING_BODY_ELEMENTS = 1;
export const SRCDOC_URL_DIGEST = '4a81696362b26de48692e5978ff373d7d11106d55b14b26f0a193e7e1ac94da2';

export const OP_ADD = 0;
export const OP_SUB = 1;
export const OP_MUL = 2;
export const OP_XOR = 3;
export const OP_AND = 4;
export const OP_OR = 5;
export const OP_SHL = 6;
export const OP_SHR = 7;
export const OP_U8_CREATE = 8;
export const OP_U8_WRITE = 9;
export const OP_U8_READ = 10;
export const OP_U8_ROTATE = 11;
export const OP_STR_LEN = 12;
export const OP_STR_CHARCODE = 13;
export const OP_STR_CODEPOINT = 14;
export const OP_STR_SLICE = 15;
export const OP_DOM_CREATE = 16;
export const OP_DOM_SET_ATTR = 17;
export const OP_DOM_APPEND = 18;
export const OP_DOM_QUERY = 19;
export const OP_DOM_GET_ATTR = 20;
export const OP_DOM_DATASET_SET = 21;
export const OP_DOM_DATASET_GET = 22;
export const OP_DOM_CLASS_ADD = 23;
export const OP_DOM_CLASS_CONTAINS = 24;
export const OP_DOM_PARENT = 25;
export const OP_DOM_DISPATCH = 26;
export const OP_DOM_SERIALIZE = 27;
export const OP_DOM_QUERY_REAL = 28;
export const OP_DOM_GEOMETRY = 29;
export const OP_DOM_POINT = 30;
export const OP_DOM_EVENT_REAL = 31;
export const OP_DOM_SERIALIZE_REAL = 32;
export const OP_DOM_OBSERVE = 33;
export const OP_DOM_SIBLING_INDEX = 34;
export const OP_DOM_CHILD = 35;
export const OP_DOM_DEPTH = 36;
export const OP_DOM_FRAGMENT_APPEND = 37;
export const OP_DOM_CLONE = 38;
export const OP_DOM_REPARENT = 39;
export const OP_DOM_ATTR_REFLECT = 40;
export const OP_DOM_EVENT_PHASE = 41;
export const OP_DOM_URL_CANON = 42;
export const OP_DOM_TEXT_MUTATE = 43;
export const OP_DOM_SELECT_DEP = 44;
export const OP_COUNT = 45;

export const TRACE_NAMES: readonly string[] = [
  'add', 'sub', 'mul', 'xor', 'and', 'or', 'shl', 'shr',
  'u8c', 'u8w', 'u8r', 'u8rot',
  'slen', 'schar', 'scode', 'sslice',
  'dcreate', 'dattr', 'dappend', 'dqsel', 'dget', 'dset', 'dgetd',
  'cadd', 'ccont', 'dparent', 'ddispatch', 'dserialize',
  'qreal', 'geom', 'point', 'evreal', 'sreal', 'obs', 'dsib', 'dchild', 'ddepth',
  'dfrag', 'dclone', 'drepar', 'dreflec', 'dphase', 'durlc', 'dmutate', 'dsdep',
];

export const ATTR_NAMES: readonly string[] = ['data-kiwi', 'data-a', 'data-b', 'title', 'data-x'];

export interface ExecutedOp {
  readonly op: number;
  readonly operands: Record<string, number | string>;
}

export interface ExecutionProgram {
  readonly format: number;
  readonly scope: string;
  readonly action: string;
  readonly opVersion: number;
  readonly ops: readonly ExecutedOp[];
}

/** The decoded program bytes keyed lookup memo (bounded, like the cores). */
const decodeMemo = new Map<string, ExecutionProgram | null>();
const DECODE_MEMO_LIMIT = 8;

/** Whether a program blob is well-formed: canonical base64 within the ceiling and fully parseable. */
export function isValidProgram(programB64: string): boolean {
  return decodeProgram(programB64) !== null;
}

/** Parse a program blob, memoized per wire string. Null when malformed. */
export function decodeProgram(programB64: string): ExecutionProgram | null {
  if (decodeMemo.has(programB64)) {
    return decodeMemo.get(programB64) ?? null;
  }
  const decoded = decodeProgramInner(programB64);
  if (decodeMemo.size >= DECODE_MEMO_LIMIT) {
    decodeMemo.clear();
  }
  decodeMemo.set(programB64, decoded);
  return decoded;
}

class Reader {
  pos = 0;
  constructor(private readonly bytes: Buffer) {}
  read(n: number): Buffer | null {
    if (this.pos + n > this.bytes.length) {
      return null;
    }
    const chunk = this.bytes.subarray(this.pos, this.pos + n);
    this.pos += n;
    return chunk;
  }
  readByte(): number | null {
    const b = this.read(1);
    return b === null ? null : b.readUInt8(0);
  }
  rest(): boolean {
    return this.pos === this.bytes.length;
  }
}

type NumOperands = Record<string, number | string>;

function num(operands: NumOperands, key: string): number {
  const value = operands[key];
  return typeof value === 'number' ? value : 0;
}

function str(operands: NumOperands, key: string): string {
  const value = operands[key];
  return typeof value === 'string' ? value : '';
}

function decodeProgramInner(programB64: string): ExecutionProgram | null {
  if (programB64.length > EXECUTION_MAX_PROGRAM_BASE64) {
    return null;
  }
  const bytes = decodeStdBase64(programB64);
  if (bytes === null) {
    return null;
  }
  const reader = new Reader(bytes);
  const format = reader.readByte();
  if (format !== EXECUTION_FORMAT_VERSION) {
    return null;
  }
  const scopeLen = reader.readByte();
  if (scopeLen === null) {
    return null;
  }
  const scopeBytes = reader.read(scopeLen);
  if (scopeBytes === null) {
    return null;
  }
  const scope = scopeBytes.toString('latin1');
  if (scope === '' || scope.length > 128 || !/^[A-Za-z0-9._:-]+$/.test(scope)) {
    return null;
  }
  const actionLen = reader.readByte();
  if (actionLen === null) {
    return null;
  }
  const actionBytes = reader.read(actionLen);
  if (actionBytes === null) {
    return null;
  }
  const action = actionBytes.toString('latin1');
  if (action === '' || action.length > 32 || !/^[A-Za-z0-9._:-]+$/.test(action)) {
    return null;
  }
  const opVersion = reader.readByte();
  if (opVersion === null || opVersion < 1 || opVersion > EXECUTION_MAX_VERSION) {
    return null;
  }
  const opCount = reader.readByte();
  if (opCount === null || opCount < EXECUTION_MIN_OPS || opCount > EXECUTION_MAX_OPS) {
    return null;
  }
  const maxOpcode = opVersion === 1 ? 33 : opVersion === 2 ? 34 : opVersion === 3 ? 35 : opVersion === 4 ? 37 : OP_COUNT;
  const ops: ExecutedOp[] = [];
  for (let i = 0; i < opCount; i++) {
    const opcode = reader.readByte();
    if (opcode === null || opcode >= maxOpcode) {
      return null;
    }
    const operands = readOperands(reader, opcode);
    if (operands === null) {
      return null;
    }
    ops.push({ op: opcode, operands });
  }
  if (!reader.rest()) {
    return null;
  }
  return { format: EXECUTION_FORMAT_VERSION, scope, action, opVersion, ops };
}

function readStringOperands(reader: Reader, min: number, max: number): { len: number; s: string } | null {
  const lenByte = reader.readByte();
  if (lenByte === null) {
    return null;
  }
  if (lenByte < min || lenByte > max) {
    return null;
  }
  const bytes = reader.read(lenByte);
  if (bytes === null) {
    return null;
  }
  return { len: lenByte, s: bytes.toString('latin1') };
}

function readIdKeyed(reader: Reader): { id: string } | null {
  const value = readStringOperands(reader, 4, 16);
  return value === null ? null : { id: value.s };
}

function readU32Pair(reader: Reader): NumOperands | null {
  const a = readFixed(reader, 4);
  const b = readFixed(reader, 4);
  return a === null || b === null ? null : { a, b };
}

function readFixed(reader: Reader, n: number): number | null {
  const bytes = reader.read(n);
  if (bytes === null) {
    return null;
  }
  let value = 0;
  for (const byte of bytes) {
    value = value * 256 + byte;
  }
  return value;
}

function readOperands(reader: Reader, opcode: number): NumOperands | null {
  switch (opcode) {
    case OP_ADD: case OP_SUB: case OP_MUL: case OP_XOR:
    case OP_AND: case OP_OR: case OP_SHL: case OP_SHR:
      return readU32Pair(reader);
    case OP_U8_CREATE: {
      const lenByte = reader.readByte();
      return lenByte === null ? null : { len: 8 + (lenByte % 57) };
    }
    case OP_U8_WRITE: {
      const idx = reader.readByte();
      const val = reader.readByte();
      return idx === null || val === null ? null : { idx: idx % 64, val };
    }
    case OP_U8_READ: {
      const idx = reader.readByte();
      return idx === null ? null : { idx: idx % 64 };
    }
    case OP_U8_ROTATE: {
      const k = reader.readByte();
      return k === null ? null : { k: k % 8 };
    }
    case OP_STR_LEN:
      return readStringOperands(reader, 1, 16);
    case OP_STR_CHARCODE: case OP_STR_CODEPOINT: {
      const value = readStringOperands(reader, 1, 16);
      if (value === null) {
        return null;
      }
      const idx = reader.readByte();
      return idx === null ? null : { len: value.len, s: value.s, idx };
    }
    case OP_STR_SLICE: {
      const value = readStringOperands(reader, 1, 16);
      if (value === null) {
        return null;
      }
      const tail = reader.read(2);
      if (tail === null) {
        return null;
      }
      return {
        len: value.len,
        s: value.s,
        start: tail.readUInt8(0) % (value.len + 1),
        count: tail.readUInt8(1) % 32,
      };
    }
    case OP_DOM_CREATE: {
      const tagByte = reader.readByte();
      if (tagByte === null) {
        return null;
      }
      const id = readStringOperands(reader, 4, 16);
      return id === null ? null : { tag: tagByte % 4, id: id.s };
    }
    case OP_DOM_SET_ATTR: {
      const nameByte = reader.readByte();
      if (nameByte === null) {
        return null;
      }
      const value = readStringOperands(reader, 1, 32);
      return value === null ? null : { name: nameByte % 5, val: value.s };
    }
    case OP_DOM_QUERY: {
      const id = readStringOperands(reader, 4, 16);
      return id === null ? null : { s: id.s };
    }
    case OP_DOM_GET_ATTR: case OP_DOM_ATTR_REFLECT: {
      const name = reader.readByte();
      return name === null ? null : { name: name % 5 };
    }
    case OP_DOM_DATASET_SET: {
      const keyByte = reader.readByte();
      if (keyByte === null || keyByte < 1 || keyByte > 16) {
        return null;
      }
      const key = reader.read(keyByte);
      if (key === null) {
        return null;
      }
      const value = readStringOperands(reader, 1, 32);
      return value === null ? null : { s: key.toString('latin1'), val: value.s };
    }
    case OP_DOM_DATASET_GET:
      return readStringOperands(reader, 1, 16);
    case OP_DOM_CLASS_ADD: case OP_DOM_CLASS_CONTAINS: {
      const value = readStringOperands(reader, 1, 12);
      return value === null ? null : { s: value.s };
    }
    case OP_DOM_APPEND: case OP_DOM_PARENT: case OP_DOM_DISPATCH:
    case OP_DOM_SERIALIZE: case OP_DOM_SERIALIZE_REAL: case OP_DOM_URL_CANON:
      return {};
    case OP_DOM_QUERY_REAL: case OP_DOM_GEOMETRY: case OP_DOM_EVENT_REAL:
    case OP_DOM_SIBLING_INDEX: case OP_DOM_DEPTH:
      return readIdKeyed(reader);
    case OP_DOM_POINT: {
      const x = reader.readByte();
      const y = reader.readByte();
      return x === null || y === null ? null : { x, y };
    }
    case OP_DOM_OBSERVE: {
      const id = readIdKeyed(reader);
      if (id === null) {
        return null;
      }
      const idx = reader.readByte();
      return idx === null ? null : { id: id.id, idx: idx % 64 };
    }
    case OP_DOM_CHILD: {
      const tag = reader.readByte();
      if (tag === null) {
        return null;
      }
      const id = readIdKeyed(reader);
      return id === null ? null : { tag: tag % 4, id: id.id };
    }
    case OP_DOM_CLONE: case OP_DOM_REPARENT: {
      const id = readIdKeyed(reader);
      if (id === null) {
        return null;
      }
      const cell = reader.readByte();
      return cell === null ? null : { id: id.id, cell: cell % 64 };
    }
    case OP_DOM_FRAGMENT_APPEND: {
      const slot = reader.readByte();
      const cell = reader.readByte();
      return slot === null || cell === null ? null : { s: slot % 4, cell: cell % 64 };
    }
    case OP_DOM_EVENT_PHASE: {
      const cell = reader.readByte();
      return cell === null ? null : { cell: cell % 64 };
    }
    case OP_DOM_TEXT_MUTATE: {
      const value = readStringOperands(reader, 1, 32);
      if (value === null) {
        return null;
      }
      const cell = reader.readByte();
      return cell === null ? null : { val: value.s, cell: cell % 64 };
    }
    case OP_DOM_SELECT_DEP: {
      const b0 = reader.readByte();
      const b1 = reader.readByte();
      const b2 = reader.readByte();
      return b0 === null || b1 === null || b2 === null ? null : { b0, b1, b2 };
    }
    default:
      return null;
  }
}

interface NodeRecord {
  id: string;
  attrs: Record<string, string>;
  dataset: Record<string, string>;
  classes: Record<string, boolean>;
  appended: boolean;
  parent?: string;
  text?: string;
}

interface GraphContext {
  nodes: Map<string, { parent: string | null; children: string[]; appended: boolean }>;
  body: string[];
  frags: string[][];
}

interface SimState {
  u8: number[];
  cur: NodeRecord | null;
  docIds: Set<string>;
  ctx: GraphContext | null;
}

function newGraph(): GraphContext {
  return { nodes: new Map(), body: [], frags: [[], [], [], []] };
}

function u32(value: number): number {
  return value >>> 0;
}

function mul32(a: number, b: number): number {
  // a*b mod 2^32 without 64-bit overflow: split both factors into
  // 16-bit halves; the high-high term vanishes modulo 2^32.
  const lo = (a & 0xffff) * (b & 0xffff);
  const cross = ((a >> 16) & 0xffff) * (b & 0xffff) + (a & 0xffff) * ((b >> 16) & 0xffff);
  return (u32(lo) + u32((cross & 0xffff) << 16)) >>> 0;
}

function checksum(u8: number[]): number {
  let sum = 0;
  for (const b of u8) {
    sum = (sum + b) & 0xff;
  }
  return sum;
}

function byteAt(text: string, index: number): number {
  return index < text.length ? text.charCodeAt(index) & 0xff : 0;
}

function writeV5Cell(u8: number[], cell: number, entry: number): void {
  if (cell < u8.length) {
    u8[cell] = entry & 0xff;
  }
}

function sortedEntries(record: Record<string, string>): [string, string][] {
  return Object.keys(record).sort().map((key) => [key, record[key]] as [string, string]);
}

function canonicalNodeString(cur: NodeRecord | null, ctx: GraphContext | null): string {
  if (cur === null) {
    return '';
  }
  const parts: string[] = [];
  for (const [name, value] of sortedEntries(cur.attrs)) {
    parts.push(`${name}=${value}`);
  }
  if (ctx !== null) {
    for (const [key, value] of sortedEntries(cur.dataset)) {
      parts.push(`${key}=${value}`);
    }
    for (const cls of Object.keys(cur.classes).sort()) {
      parts.push(cls);
    }
    if (cur.text !== undefined && cur.text !== '') {
      parts.push(cur.text);
    }
  }
  return parts.join(';');
}

function graphDetach(ctx: GraphContext, id: string): void {
  const record = ctx.nodes.get(id);
  if (record === undefined) {
    return;
  }
  if (record.parent !== null) {
    const parent = ctx.nodes.get(record.parent);
    if (parent !== undefined) {
      parent.children = parent.children.filter((child) => child !== id);
    }
  }
  const bodyPos = ctx.body.indexOf(id);
  if (bodyPos >= 0) {
    ctx.body.splice(bodyPos, 1);
  }
  for (const slot of ctx.frags) {
    const slotPos = slot.indexOf(id);
    if (slotPos >= 0) {
      slot.splice(slotPos, 1);
    }
  }
  record.parent = null;
  record.appended = false;
}

function graphAttachToBody(ctx: GraphContext, id: string): void {
  graphDetach(ctx, id);
  const record = ctx.nodes.get(id);
  if (record !== undefined) {
    record.parent = null;
    record.appended = true;
  }
  ctx.body.push(id);
}

function graphIsAttached(ctx: GraphContext, id: string): boolean {
  const record = ctx.nodes.get(id);
  if (record === undefined) {
    return false;
  }
  if (ctx.body.includes(id)) {
    return true;
  }
  let guard = 0;
  let cursor = record.parent;
  while (cursor !== null && ctx.nodes.has(cursor) && guard++ < 4096) {
    if (ctx.body.includes(cursor)) {
      return true;
    }
    cursor = ctx.nodes.get(cursor)?.parent ?? null;
  }
  return false;
}

function graphNodeIsAncestorOf(ctx: GraphContext, ancestorId: string, id: string): boolean {
  let guard = 0;
  let cursor = ctx.nodes.get(id)?.parent ?? null;
  while (cursor !== null && ctx.nodes.has(cursor) && guard++ < 4096) {
    if (cursor === ancestorId) {
      return true;
    }
    cursor = ctx.nodes.get(cursor)?.parent ?? null;
  }
  return false;
}

function graphSubtreeElementCount(ctx: GraphContext, id: string): number {
  let total = 1;
  const children = ctx.nodes.get(id)?.children ?? [];
  for (const childId of children) {
    total += ctx.nodes.has(childId) ? graphSubtreeElementCount(ctx, childId) : 1;
  }
  return total;
}

function nodeTag(cur: NodeRecord | null, id: string): 'div' | 'span' {
  return cur !== null && cur.id === id ? 'div' : 'span';
}

function realReadback(cur: NodeRecord | null): string {
  if (cur === null) {
    return 'none';
  }
  const parts = sortedEntries(cur.attrs).map(([name, value]) => `${name}=${value}`);
  return `div|${parts.join(';')}`;
}

function opQueryRealExpected(operands: NumOperands, state: SimState): string {
  const id = str(operands, 'id');
  if (!state.docIds.has(id)) {
    return 'none';
  }
  return realReadback(state.cur !== null && state.cur.id === id ? state.cur : null);
}

function opSerializeRealExpected(state: SimState): string {
  if (state.cur === null || !state.cur.appended) {
    return createHash('sha256').update('').digest('hex');
  }
  return createHash('sha256').update(canonicalNodeString(state.cur, state.ctx), 'latin1').digest('hex');
}

function b64(text: string): string {
  return encodeStdBase64(Buffer.from(text, 'latin1'));
}

/**
 * The deterministic execution of one op against the shared state
 * machine. Returns the op's canonical trace value (decimal, 1/0, hex
 * digest, or standard base64). The browser-observed probes return
 * their construction-determined expected values; the layout and
 * pointer placeholders (geom, point, obs, dsib, ddepth, durlc) are
 * validated by the submitted-trace walker instead.
 */
function simulateOp(op: number, operands: NumOperands, state: SimState): string {
  const { u8, ctx } = state;
  let cur = state.cur;
  switch (op) {
    case OP_ADD:
      return String(u32(num(operands, 'a') + num(operands, 'b')));
    case OP_SUB:
      return String(u32(num(operands, 'a') - num(operands, 'b')));
    case OP_MUL:
      return String(mul32(num(operands, 'a'), num(operands, 'b')));
    case OP_XOR:
      return String((num(operands, 'a') ^ num(operands, 'b')) >>> 0);
    case OP_AND:
      return String((num(operands, 'a') & num(operands, 'b')) >>> 0);
    case OP_OR:
      return String((num(operands, 'a') | num(operands, 'b')) >>> 0);
    case OP_SHL:
      return String(u32(num(operands, 'a') << (num(operands, 'b') & 31)));
    case OP_SHR:
      return String(u32(num(operands, 'a') >>> (num(operands, 'b') & 31)));
    case OP_U8_CREATE: {
      state.u8 = new Array<number>(num(operands, 'len')).fill(0);
      return String(checksum(state.u8));
    }
    case OP_U8_WRITE: {
      const idx = num(operands, 'idx');
      if (idx < state.u8.length) {
        state.u8[idx] = num(operands, 'val') & 0xff;
      }
      return String(checksum(state.u8));
    }
    case OP_U8_READ: {
      const idx = num(operands, 'idx');
      return String((idx < state.u8.length ? state.u8[idx] ?? 0 : 0) & 0xff);
    }
    case OP_U8_ROTATE: {
      const n = state.u8.length;
      const k = num(operands, 'k') % 8;
      if (n > 0 && k > 0) {
        const rotated = new Array<number>(n);
        for (let i = 0; i < n; i++) {
          rotated[i] = state.u8[(i + k) % n] ?? 0;
        }
        state.u8 = rotated;
      }
      return String(checksum(state.u8));
    }
    case OP_STR_LEN:
      return String(Buffer.byteLength(str(operands, 's'), 'latin1'));
    case OP_STR_CHARCODE: case OP_STR_CODEPOINT:
      return String(byteAt(str(operands, 's'), num(operands, 'idx')));
    case OP_STR_SLICE: {
      const text = str(operands, 's');
      const slice = text.substring(num(operands, 'start'), num(operands, 'start') + num(operands, 'count'));
      return encodeStdBase64(Buffer.from(slice, 'latin1'));
    }
    case OP_DOM_CREATE: {
      const id = str(operands, 'id');
      cur = { id, attrs: { id }, dataset: {}, classes: {}, appended: false };
      if (ctx !== null) {
        ctx.nodes.set(id, { parent: null, children: [], appended: false });
      }
      state.cur = cur;
      return b64(id);
    }
    case OP_DOM_SET_ATTR: {
      const name = ATTR_NAMES[num(operands, 'name')] ?? '';
      if (cur !== null) {
        cur.attrs[name] = str(operands, 'val');
      }
      return b64(name);
    }
    case OP_DOM_APPEND: {
      if (cur !== null) {
        cur.appended = true;
        state.docIds.add(cur.id);
        if (ctx !== null) {
          graphAttachToBody(ctx, cur.id);
        }
      }
      return '1';
    }
    case OP_DOM_QUERY:
      return state.docIds.has(str(operands, 's')) ? '1' : '0';
    case OP_DOM_GET_ATTR: {
      const name = ATTR_NAMES[num(operands, 'name')] ?? '';
      return b64(cur !== null ? cur.attrs[name] ?? '' : '');
    }
    case OP_DOM_DATASET_SET: {
      const key = str(operands, 's');
      if (cur !== null) {
        cur.dataset[key] = str(operands, 'val');
      }
      return b64(key);
    }
    case OP_DOM_DATASET_GET: {
      const key = str(operands, 's');
      return b64(cur !== null ? cur.dataset[key] ?? '' : '');
    }
    case OP_DOM_CLASS_ADD: {
      const cls = str(operands, 's');
      if (cur !== null) {
        cur.classes[cls] = true;
      }
      return b64(cls);
    }
    case OP_DOM_CLASS_CONTAINS:
      return cur !== null && cur.classes[str(operands, 's')] === true ? '1' : '0';
    case OP_DOM_PARENT:
      return cur !== null && cur.appended ? '1' : '0';
    case OP_DOM_DISPATCH:
      return '1';
    case OP_DOM_SERIALIZE: {
      if (cur !== null) {
        cur.appended = true;
        state.docIds.add(cur.id);
        if (ctx !== null && !graphIsAttached(ctx, cur.id)) {
          graphAttachToBody(ctx, cur.id);
        }
      }
      return b64(canonicalNodeString(cur, ctx));
    }
    case OP_DOM_QUERY_REAL:
      return opQueryRealExpected(operands, state);
    case OP_DOM_GEOMETRY:
      return 'geom';
    case OP_DOM_POINT:
      return 'point';
    case OP_DOM_EVENT_REAL:
      return state.docIds.has(str(operands, 'id'))
        ? `kiwi-ev:${nodeTag(cur, str(operands, 'id'))}`
        : 'none';
    case OP_DOM_SERIALIZE_REAL:
      return opSerializeRealExpected(state);
    case OP_DOM_OBSERVE:
      return 'obs';
    case OP_DOM_SIBLING_INDEX:
      return 'dsib';
    case OP_DOM_CHILD: {
      const id = str(operands, 'id');
      const newCur: NodeRecord = { id, attrs: { id }, dataset: {}, classes: {}, appended: true };
      const parentId = cur !== null ? cur.id : undefined;
      if (cur !== null && parentId !== id) {
        newCur.parent = parentId;
      }
      if (ctx !== null) {
        ctx.nodes.set(id, { parent: parentId ?? null, children: [], appended: true });
        if (parentId !== undefined) {
          const parent = ctx.nodes.get(parentId);
          if (parent !== undefined) {
            parent.children.push(id);
          }
        }
      }
      state.cur = newCur;
      return b64(id);
    }
    case OP_DOM_DEPTH:
      return 'ddepth';
    case OP_DOM_FRAGMENT_APPEND: {
      let entry = 0;
      if (ctx !== null) {
        entry = (ctx.frags[num(operands, 's')] ?? []).length;
      }
      if (cur !== null && ctx !== null && ctx.nodes.has(cur.id)) {
        const id = cur.id;
        graphDetach(ctx, id);
        const slot = ctx.frags[num(operands, 's')] ?? [];
        slot.push(id);
        entry = slot.length;
        cur.appended = false;
        state.docIds.delete(id);
      }
      writeV5Cell(state.u8, num(operands, 'cell'), entry);
      return String(entry);
    }
    case OP_DOM_CLONE: {
      let entry = 0;
      if (cur !== null && ctx !== null && ctx.nodes.has(cur.id)) {
        const sourceId = cur.id;
        const cloneId = str(operands, 'id');
        const source = ctx.nodes.get(sourceId);
        if (source !== undefined) {
          entry = graphSubtreeElementCount(ctx, sourceId);
          const copy: NodeRecord = { ...cur, attrs: { ...cur.attrs } };
          copy.id = cloneId;
          copy.attrs.id = cloneId;
          copy.parent = source.parent ?? undefined;
          copy.appended = source.appended;
          ctx.nodes.set(cloneId, {
            parent: source.parent,
            children: [...source.children],
            appended: source.appended,
          });
          if (source.appended) {
            state.docIds.add(cloneId);
            const parentId = source.parent;
            if (parentId !== null && ctx.nodes.has(parentId)) {
              const siblings = ctx.nodes.get(parentId)?.children ?? [];
              const at = siblings.indexOf(sourceId);
              const insertAt = at === -1 ? siblings.length : at + 1;
              siblings.splice(insertAt, 0, cloneId);
            } else {
              const at = ctx.body.indexOf(sourceId);
              const insertAt = at === -1 ? ctx.body.length : at + 1;
              ctx.body.splice(insertAt, 0, cloneId);
            }
          }
          state.cur = copy;
        }
      }
      writeV5Cell(state.u8, num(operands, 'cell'), entry);
      return String(entry);
    }
    case OP_DOM_REPARENT: {
      let entry = 0;
      const targetId = str(operands, 'id');
      if (cur !== null && ctx !== null && ctx.nodes.has(cur.id) && ctx.nodes.has(targetId)) {
        const curId = cur.id;
        entry = ctx.nodes.get(targetId)?.children.length ?? 0;
        const valid = curId !== targetId && !graphNodeIsAncestorOf(ctx, curId, targetId);
        if (valid) {
          const targetAttached = graphIsAttached(ctx, targetId);
          graphDetach(ctx, curId);
          const moved = ctx.nodes.get(curId);
          if (moved !== undefined) {
            moved.parent = targetId;
            moved.appended = targetAttached;
          }
          ctx.nodes.get(targetId)?.children.push(curId);
          cur.parent = targetId;
          cur.appended = targetAttached;
          if (targetAttached) {
            state.docIds.add(curId);
          } else {
            state.docIds.delete(curId);
          }
          entry = ctx.nodes.get(targetId)?.children.length ?? 0;
        }
      }
      writeV5Cell(state.u8, num(operands, 'cell'), entry);
      return String(entry);
    }
    case OP_DOM_ATTR_REFLECT: {
      const name = ATTR_NAMES[num(operands, 'name')] ?? '';
      return b64(cur !== null ? cur.attrs[name] ?? '' : '');
    }
    case OP_DOM_EVENT_PHASE: {
      let count = 0;
      if (cur !== null && ctx !== null && ctx.nodes.has(cur.id)) {
        count = 1;
        let guard = 0;
        let cursor = ctx.nodes.get(cur.id)?.parent ?? null;
        while (cursor !== null && ctx.nodes.has(cursor) && guard++ < 4096) {
          count += 1;
          cursor = ctx.nodes.get(cursor)?.parent ?? null;
        }
      }
      writeV5Cell(state.u8, num(operands, 'cell'), count);
      return String(count);
    }
    case OP_DOM_URL_CANON:
      return 'durlc';
    case OP_DOM_TEXT_MUTATE: {
      let len = 0;
      if (cur !== null) {
        const value = str(operands, 'val');
        cur.text = value;
        len = Buffer.byteLength(value, 'latin1');
        if (ctx !== null) {
          const record = ctx.nodes.get(cur.id);
          if (record !== undefined && record.children.length > 0) {
            const attached = graphIsAttached(ctx, cur.id);
            for (const childId of [...record.children]) {
              graphDetach(ctx, childId);
              if (attached) {
                state.docIds.delete(childId);
              }
            }
          }
        }
      }
      writeV5Cell(state.u8, num(operands, 'cell'), len);
      return String(len);
    }
    case OP_DOM_SELECT_DEP: {
      let completed = 0;
      if (cur !== null && ctx !== null && ctx.nodes.has(cur.id)) {
        let levelId = cur.id;
        for (const key of ['b0', 'b1', 'b2']) {
          const children = ctx.nodes.get(levelId)?.children ?? [];
          if (children.length === 0) {
            break;
          }
          levelId = children[num(operands, key) % children.length] ?? levelId;
          completed += 1;
          if (!ctx.nodes.has(levelId)) {
            break;
          }
        }
      }
      return String(completed);
    }
    default:
      return '0';
  }
}

interface OpStateExtras {
  readonly u8: number[];
  readonly cur: NodeRecord | null;
  readonly docIds: Set<string>;
  readonly ctx: GraphContext | null;
}

function traceName(op: number): string {
  const name = TRACE_NAMES[op];
  if (name === undefined) {
    throw new RangeError(`unknown execution opcode: ${op}`);
  }
  return name;
}

function freshState(opVersion: number): SimState {
  return { u8: [], cur: null, docIds: new Set(), ctx: opVersion >= 5 ? newGraph() : null };
}

/**
 * The canonical op trace of a program: the joined opname(result)
 * entries of every op, simulated against the shared state machine. A
 * pure function of the program.
 */
export function canonicalTrace(program: ExecutionProgram): string {
  const state = freshState(program.opVersion);
  const entries: string[] = [];
  for (const record of program.ops) {
    entries.push(`${traceName(record.op)}(${simulateOp(record.op, record.operands, state)})`);
  }
  return entries.join(';');
}

/** The expected execution digest of a program for a challenge nonce. */
export function expectedDigest(programB64: string, nonce: string): string | null {
  const bytes = decodeStdBase64(programB64);
  const program = decodeProgram(programB64);
  if (bytes === null || program === null) {
    return null;
  }
  const trace = canonicalTrace(program);
  return digestOverTraceInner(bytes, nonce, program, trace);
}

/** The execution digest over a submitted trace (the V2 evidence path). */
export function digestOverTrace(programB64: string, nonce: string, trace: string): string | null {
  const bytes = decodeStdBase64(programB64);
  const program = decodeProgram(programB64);
  if (bytes === null || program === null) {
    return null;
  }
  return digestOverTraceInner(bytes, nonce, program, trace);
}

function digestOverTraceInner(
  key: Buffer,
  nonce: string,
  program: ExecutionProgram,
  trace: string,
): string {
  const message = `${EXECUTION_LABEL}|${nonce}|${program.scope}|${program.action}|${program.opVersion}|${trace}`;
  return createHmac('sha256', key).update(Buffer.from(message, 'latin1')).digest('hex');
}

/**
 * Verify a submitted execution trace against a program. Returns the
 * canonical trace used for the digest when the trace verifies, null
 * otherwise. Deterministic entries are compared byte-exact against the
 * simulation; the browser-observed entries must satisfy their rules:
 * geometry monotonic with height at least one, the topmost-point tag,
 * the exact sibling rank and ancestor depth, the observe replay into
 * the u8 state, and the pinned sandbox URL digest.
 */
export function verifyExecutedTrace(
  programB64: string,
  nonce: string,
  trace: string,
): string | null {
  const program = decodeProgram(programB64);
  if (program === null || trace === '') {
    return null;
  }
  // First pass: the append order the point probe reads.
  const first = freshState(program.opVersion);
  const construction: string[] = [];
  for (const record of program.ops) {
    simulateOp(record.op, record.operands, first);
    if (record.op === OP_DOM_APPEND) {
      construction.push(first.cur?.id ?? '');
    }
  }
  // Second pass from fresh state: the first pass left the mutable
  // simulation at its end state, and a deterministic trace replays
  // from the same initial conditions.
  const state = freshState(program.opVersion);
  const appendRank = new Map<string, number>();
  const parent = new Map<string, string>();
  let pos = 0;
  let prevTop = -1;
  const lastIndex = program.ops.length - 1;
  for (let i = 0; i < program.ops.length; i++) {
    const record = program.ops[i];
    if (record === undefined) {
      return null;
    }
    const op = record.op;
    const operands = record.operands;
    if (op === OP_DOM_APPEND && state.cur !== null && !appendRank.has(state.cur.id)) {
      appendRank.set(state.cur.id, appendRank.size);
    }
    if (op === OP_DOM_CHILD && state.cur !== null) {
      parent.set(str(operands, 'id'), state.cur.id);
    }
    const sim = simulateOp(op, operands, state);
    const name = traceName(op);
    if (trace.startsWith(`${name}(`, pos) !== true) {
      return null;
    }
    pos += name.length + 1;
    if (op === OP_DOM_GEOMETRY) {
      const m = /^\d+,\d+\)/.exec(trace.slice(pos));
      if (m === null) {
        return null;
      }
      const [topText, heightText] = m[0].slice(0, -1).split(',');
      const top = Number(topText);
      const height = Number(heightText);
      if (height < 1 || top < prevTop) {
        return null;
      }
      prevTop = top;
      pos += m[0].length;
    } else if (op === OP_DOM_POINT) {
      const topTag = construction.length > 0 ? 'div' : 'none';
      if (!trace.startsWith(`${topTag})`, pos)) {
        return null;
      }
      pos += topTag.length + 1;
    } else if (op === OP_DOM_SIBLING_INDEX) {
      const expectedRank = appendRank.get(str(operands, 'id'));
      const m = /^\d+\)/.exec(trace.slice(pos));
      if (
        expectedRank === undefined ||
        m === null ||
        Number(m[0].slice(0, -1)) !== expectedRank + SRCDOC_PREEXISTING_BODY_ELEMENTS
      ) {
        return null;
      }
      pos += m[0].length;
    } else if (op === OP_DOM_DEPTH) {
      let depth = 0;
      let cursorId = operands['id'] === undefined ? undefined : str(operands, 'id');
      while (cursorId !== undefined && parent.has(cursorId)) {
        depth += 1;
        cursorId = parent.get(cursorId);
      }
      const m = /^\d+\)/.exec(trace.slice(pos));
      if (m === null || Number(m[0].slice(0, -1)) !== depth) {
        return null;
      }
      pos += m[0].length;
    } else if (op === OP_DOM_OBSERVE) {
      const m = /^\d+,\d+\)/.exec(trace.slice(pos));
      if (m === null) {
        return null;
      }
      const [dstText, observedText] = m[0].slice(0, -1).split(',');
      const dst = Number(dstText);
      const observed = Number(observedText);
      if (!state.docIds.has(str(operands, 'id')) || dst !== num(operands, 'idx') || observed < 1 || observed > 255) {
        return null;
      }
      if (dst < state.u8.length) {
        state.u8[dst] = observed;
      }
      pos += m[0].length;
    } else if (op === OP_DOM_URL_CANON) {
      if (trace.slice(pos, pos + 64) !== SRCDOC_URL_DIGEST || trace[pos + 64] !== ')') {
        return null;
      }
      pos += 65;
    } else {
      const simEntry = `${sim})`;
      if (!trace.startsWith(simEntry, pos)) {
        return null;
      }
      pos += simEntry.length;
    }
    if (i < lastIndex) {
      if (trace[pos] !== ';') {
        return null;
      }
      pos += 1;
    }
  }
  if (pos !== trace.length) {
    return null;
  }
  return trace;
}
