/**
 * The trusted client-IP resolver: the canonical client IP of a request
 * is its socket peer unless the peer sits inside the configured
 * trusted-proxy CIDR list. An empty list trusts nobody, so a client
 * supplied forwarding header can never move the IP binding. With a
 * trusted peer, the X-Forwarded-For chain is walked right to left:
 * entries inside the trust list are skipped, the first untrusted entry
 * wins, and an entry that fails strict IP parsing terminates the walk
 * and falls back to the peer. X-Real-IP is honored only when the peer
 * is trusted and no forwarded chain exists. The algorithm ports the
 * Symfony bundle's ClientIpResolver trusted-chain walk, so every SDK
 * binds the same canonical IP for the same request.
 */

/** One canonical IP or CIDR text after parsing. */
interface Parsed {
  bytes: Uint8Array;
  bits: number;
}

const CONTROL_BYTES = /[\u0000-\u001F\u007F]/;

function parseIp(text: string): Parsed | null {
  if (text.includes(':')) {
    return parseIpv6(text);
  }
  return parseIpv4(text);
}

/** The strict dotted-quad grammar: no shorthand, no leading zeros. */
function parseIpv4(text: string): Parsed | null {
  const parts = text.split('.');
  if (parts.length !== 4) {
    return null;
  }
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const part = parts[i];
    if (part === undefined) {
      return null;
    }
    if (part.length === 0 || part.length > 3 || (part.length > 1 && part[0] === '0')) {
      return null;
    }
    if (!/^\d+$/.test(part)) {
      return null;
    }
    const value = Number(part);
    if (value > 255) {
      return null;
    }
    bytes[i] = value;
  }
  return { bytes, bits: 32 };
}

function parseIpv6(text: string): Parsed | null {
  // A trailing embedded IPv4 splits off and is folded back in after
  // the group expansion, so the placeholder rides the last 2 groups.
  let rest = text;
  let tail: Parsed | null = null;
  const lastColon = text.lastIndexOf(':');
  const tailText = text.slice(lastColon + 1);
  if (tailText.includes('.')) {
    tail = parseIpv4(tailText);
    if (tail === null) {
      return null;
    }
    rest = `${text.slice(0, lastColon + 1)}0:0`;
  }
  const doubleColon = rest.indexOf('::');
  let head: string[];
  let foot: string[];
  if (doubleColon >= 0) {
    if (rest.indexOf('::', doubleColon + 1) >= 0) {
      return null;
    }
    head = rest.slice(0, doubleColon).split(':').filter((p) => p !== '');
    foot = rest.slice(doubleColon + 2).split(':').filter((p) => p !== '');
    // The compression must cover at least one group.
    if (head.length + foot.length > (tail !== null ? 6 : 7)) {
      return null;
    }
  } else {
    head = rest.split(':').filter((p) => p !== '');
    foot = [];
    if (head.length !== (tail !== null ? 6 : 8)) {
      return null;
    }
  }
  if (head.length + foot.length > 8) {
    return null;
  }
  const groups: number[] = [];
  for (const group of head) {
    const value = parseHexGroup(group);
    if (value === null) {
      return null;
    }
    groups.push(value);
  }
  for (let i = 8 - head.length - foot.length; i > 0; i--) {
    groups.push(0);
  }
  for (const group of foot) {
    const value = parseHexGroup(group);
    if (value === null) {
      return null;
    }
    groups.push(value);
  }
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const group = groups[i] ?? 0;
    bytes[i * 2] = group >> 8;
    bytes[i * 2 + 1] = group & 0xff;
  }
  if (tail !== null) {
    bytes[12] = tail.bytes[0] ?? 0;
    bytes[13] = tail.bytes[1] ?? 0;
    bytes[14] = tail.bytes[2] ?? 0;
    bytes[15] = tail.bytes[3] ?? 0;
  }
  return { bytes, bits: 128 };
}

function parseHexGroup(group: string): number | null {
  if (group.length === 0 || group.length > 4 || !/^[0-9a-fA-F]+$/.test(group)) {
    return null;
  }
  return parseInt(group, 16);
}

/** The strict CIDR grammar; host bits set beyond the prefix are masked. */
function parseCidr(cidr: string): { network: Parsed; prefixLength: number } | null {
  const slash = cidr.lastIndexOf('/');
  if (slash < 0) {
    const addr = parseIp(cidr);
    return addr === null ? null : { network: addr, prefixLength: addr.bits };
  }
  const network = parseIp(cidr.slice(0, slash).trim());
  const lengthText = cidr.slice(slash + 1).trim();
  if (network === null || !/^\d+$/.test(lengthText)) {
    return null;
  }
  const prefixLength = Number(lengthText);
  if (prefixLength > network.bits) {
    return null;
  }
  return { network, prefixLength };
}

function cidrContains(cidr: string, addr: Parsed): boolean {
  const parsed = parseCidr(cidr);
  if (parsed === null) {
    return false;
  }
  // Both sides normalize: an IPv4-mapped IPv6 address (or network)
  // matches in its IPv4 form, so family comparisons stay exact.
  let network = parsed.network;
  let address = addr;
  if (isV4Mapped(address)) {
    address = v4MappedOf(address);
  }
  if (isV4Mapped(network)) {
    network = v4MappedOf(network);
  }
  if (network.bits !== address.bits || parsed.prefixLength > network.bits) {
    return false;
  }
  const prefixLength = parsed.prefixLength;
  const fullBytes = Math.floor(prefixLength / 8);
  for (let i = 0; i < fullBytes && i < address.bytes.length; i++) {
    if ((network.bytes[i] ?? 0) !== (address.bytes[i] ?? 0)) {
      return false;
    }
  }
  const remainder = prefixLength % 8;
  if (remainder !== 0 && fullBytes < address.bytes.length) {
    const mask = (0xff << (8 - remainder)) & 0xff;
    return ((network.bytes[fullBytes] ?? 0) & mask) === ((address.bytes[fullBytes] ?? 0) & mask);
  }
  return true;
}

function isV4Mapped(addr: Parsed): boolean {
  if (addr.bits !== 128 || addr.bytes.length !== 16) {
    return false;
  }
  for (let i = 0; i < 10; i++) {
    if ((addr.bytes[i] ?? 0) !== 0) {
      return false;
    }
  }
  return (addr.bytes[10] ?? 0) === 0xff && (addr.bytes[11] ?? 0) === 0xff;
}

function v4MappedOf(addr: Parsed): Parsed {
  const bytes = new Uint8Array(addr.bytes.length === 16 ? 4 : addr.bytes.length);
  bytes[0] = addr.bytes[12] ?? 0;
  bytes[1] = addr.bytes[13] ?? 0;
  bytes[2] = addr.bytes[14] ?? 0;
  bytes[3] = addr.bytes[15] ?? 0;
  return { bytes, bits: 32 };
}

function formatIpv4(bytes: Uint8Array): string {
  return `${bytes[0] ?? 0}.${bytes[1] ?? 0}.${bytes[2] ?? 0}.${bytes[3] ?? 0}`;
}

/** The canonical compressed IPv6 text (RFC 5952 style, lowercase). */
function formatIpv6(bytes: Uint8Array): string {
  if (isV4Mapped({ bytes, bits: 128 })) {
    return `::ffff:${formatIpv4(bytes.subarray(12))}`;
  }
  const groups: string[] = [];
  for (let i = 0; i < 8; i++) {
    const high = bytes[i * 2] ?? 0;
    const low = bytes[i * 2 + 1] ?? 0;
    groups.push(((high << 8) | low).toString(16));
  }
  let bestStart = -1;
  let bestLength = 0;
  let currentStart = -1;
  let currentLength = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === '0') {
      if (currentStart < 0) {
        currentStart = i;
      }
      currentLength++;
      if (currentLength > bestLength) {
        bestStart = currentStart;
        bestLength = currentLength;
      }
    } else {
      currentStart = -1;
      currentLength = 0;
    }
  }
  if (bestLength < 2) {
    return groups.join(':');
  }
  const head = groups.slice(0, bestStart).join(':');
  const foot = groups.slice(bestStart + bestLength).join(':');
  return `${head}::${foot}`;
}

function formatParsed(addr: Parsed): string {
  if (addr.bits === 32) {
    return formatIpv4(addr.bytes);
  }
  return formatIpv6(addr.bytes);
}

/**
 * The canonical text of one forwarded node, or null when the node is
 * not a genuine address. Handles bare IPv4, IPv4 with a port,
 * bracketed IPv6 with an optional port, rejects unknown, obfuscated
 * tokens and malformed ports, and normalizes IPv4-mapped IPv6 to its
 * IPv4 form.
 */
export function canonicalIp(identifier: string): string | null {
  const value = identifier.trim();
  if (value === '' || value === 'unknown' || value.startsWith('_')) {
    return null;
  }
  let candidate = value;
  if (candidate.startsWith('[')) {
    const closing = candidate.indexOf(']');
    if (closing < 0) {
      return null;
    }
    const suffix = candidate.slice(closing + 1);
    if (suffix !== '' && !isPortSuffix(suffix)) {
      return null;
    }
    candidate = candidate.slice(1, closing);
  } else if (candidate.split(':').length - 1 === 1) {
    // IPv4 with a port: the port splits only when the left side is a
    // valid IPv4 and the port is a genuine number.
    const parts = candidate.split(':');
    const left = parts[0];
    const right = parts[1];
    if (left !== undefined && right !== undefined && parseIpv4(left) !== null && isPortSuffix(`:${right}`)) {
      candidate = left;
    }
  }
  const colonCount = candidate.split(':').length - 1;
  if (candidate.includes(':') && colonCount < 2) {
    const parts = candidate.split(':');
    const last = parts[parts.length - 1];
    if (last !== undefined && parseIpv4(last) !== null) {
      candidate = parts.slice(0, -1).join(':');
    }
  }
  const addr = parseIp(candidate);
  if (addr === null) {
    return null;
  }
  if (isV4Mapped(addr)) {
    return formatIpv4(v4MappedOf(addr).bytes);
  }
  return formatParsed(addr);
}

/** Exactly ":" plus a decimal port in the 1..65535 range. */
function isPortSuffix(suffix: string): boolean {
  if (suffix.length < 2 || suffix[0] !== ':') {
    return false;
  }
  const digits = suffix.slice(1);
  if (!/^\d+$/.test(digits) || digits.length > 5) {
    return false;
  }
  const port = Number(digits);
  return port >= 1 && port <= 65535;
}

/** A raw control byte refuses the whole header, never trims into an address. */
function hasControlBytes(header: string): boolean {
  return CONTROL_BYTES.test(header);
}

export interface ResolveClientIpInput {
  /** The socket peer text (host only, no port). */
  peer: string;
  /** Every X-Forwarded-For header line the surface can see. */
  xffLines: readonly string[] | null;
  /** The X-Real-IP header value, when present. */
  realIp: string | null;
  /** The trusted-proxy CIDR list; empty trusts nobody. */
  trustedProxies: readonly string[];
}

/**
 * Whether one IP text sits inside any trusted CIDR. Host bits set in
 * a CIDR are masked away, and an IPv4-mapped IPv6 address matches in
 * its IPv4 form.
 */
export function ipInTrusted(ipText: string, trustedProxies: readonly string[]): boolean {
  const addr = parseIp(ipText.trim());
  if (addr === null) {
    return false;
  }
  return trustedProxies.some((cidr) => cidrContains(cidr, addr));
}

/**
 * The canonical client IP per the shared trusted-proxy contract. A
 * repeated forwarding header line is parser ambiguity: the peer wins.
 */
export function resolveClientIp(input: ResolveClientIpInput): string {
  const peer = (input.peer ?? '').trim();
  const trusted = input.trustedProxies.filter((c) => c !== null && c !== undefined && String(c).trim() !== '');
  if (trusted.length === 0) {
    return peer;
  }
  const peerAddr = peer === '' ? null : parseIp(peer.replace(/^\[/, '').replace(/\]$/, ''));
  const peerTrusted = peerAddr !== null && trusted.some((cidr) => cidrContains(cidr, peerAddr));

  const lines = input.xffLines ?? [];
  const visible = lines.filter((line) => typeof line === 'string' && line !== '');
  // A repeated forwarding header is parser ambiguity: one intermediary
  // reads the first line, another the last, so the peer wins.
  if (visible.length > 1) {
    return peer;
  }
  const first = visible[0];
  const xff = visible.length === 1 && first !== undefined ? first.trim() : '';
  if (xff === '') {
    if (!peerTrusted || input.realIp === null || input.realIp === undefined) {
      return peer;
    }
    const realIp = input.realIp.trim();
    if (realIp === '' || hasControlBytes(realIp)) {
      return peer;
    }
    const canonical = canonicalIp(realIp);
    return canonical ?? peer;
  }
  if (hasControlBytes(xff) || !peerTrusted) {
    return peer;
  }
  const parts = xff.split(',');
  for (let i = parts.length - 1; i >= 0; i--) {
    const part = parts[i];
    const canonical = canonicalIp(part ?? '');
    if (canonical === null) {
      // An unparsable hop terminates the trust chain: who lies beyond
      // it cannot be established, so the peer falls back.
      return peer;
    }
    if (!ipInTrusted(canonical, trusted)) {
      return canonical;
    }
  }
  return peer;
}
