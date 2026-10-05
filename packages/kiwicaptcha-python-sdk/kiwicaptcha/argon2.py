"""Pure-stdlib Argon2id (version 1.3) over hashlib.blake2b.

Python ships no Argon2 binding, so the proof-phase recompute for
argon2id records is implemented here per RFC 9106 and the reference
implementation. Every exported profile the protocol allows is
computed: one to four lanes and one to sixteen passes, with the memory
parameter in KiB exactly like the PHP verifier's libsodium call
(sodium_crypto_pwhash with memlimit = m_kib * 1024, a 32-byte tag).

The compression function works on blocks of 128 unsigned 64-bit words.
A block is therefore a plain Python list of ints and the whole memory
matrix a list of such lists, addressed by lane and index. The Argon2id
addressing rule is honored exactly: the first two slices of the first
pass use the data-independent address generator, every later segment
reads its pseudo-random word from the previous block. Index selection
follows index_alpha() from the reference implementation, including the
uint32 wrap when the reference area underflows (only reachable off the
same lane).

Pure Python is slow for large memory profiles; a 64 MiB challenge takes
minutes here against milliseconds under libsodium. Correctness is
unaffected: the verifier budget gate caps the accepted profiles and the
test suite pins byte-exact vectors at the protocol's m_kib = 64 floor.
"""

import hashlib

TYPE_ARGON2ID = 2
VERSION_13 = 0x13
_SYNC_POINTS = 4
_ADDRESSES_IN_BLOCK = 128
_BLOCK_QWORDS = 128
_MASK64 = (1 << 64) - 1
_MASK32 = (1 << 32) - 1

_ZERO_BLOCK = [0] * _BLOCK_QWORDS


def _rotr(value: int, bits: int) -> int:
    return ((value >> bits) | (value << (64 - bits))) & _MASK64


def _gb(a: int, b: int, c: int, d: int):
    """One Blake2b mixing round over four 64-bit words."""
    a = (a + b + 2 * ((a & 0xFFFFFFFF) * (b & 0xFFFFFFFF))) & _MASK64
    d = _rotr(d ^ a, 32)
    c = (c + d + 2 * ((c & 0xFFFFFFFF) * (d & 0xFFFFFFFF))) & _MASK64
    b = _rotr(b ^ c, 24)
    a = (a + b + 2 * ((a & 0xFFFFFFFF) * (b & 0xFFFFFFFF))) & _MASK64
    d = _rotr(d ^ a, 16)
    c = (c + d + 2 * ((c & 0xFFFFFFFF) * (d & 0xFFFFFFFF))) & _MASK64
    b = _rotr(b ^ c, 63)
    return a, b, c, d


def _p(v):
    """The 128-byte permutation P over sixteen 64-bit words."""
    v0, v1, v2, v3 = v[0], v[1], v[2], v[3]
    v4, v5, v6, v7 = v[4], v[5], v[6], v[7]
    v8, v9, v10, v11 = v[8], v[9], v[10], v[11]
    v12, v13, v14, v15 = v[12], v[13], v[14], v[15]
    v0, v4, v8, v12 = _gb(v0, v4, v8, v12)
    v1, v5, v9, v13 = _gb(v1, v5, v9, v13)
    v2, v6, v10, v14 = _gb(v2, v6, v10, v14)
    v3, v7, v11, v15 = _gb(v3, v7, v11, v15)
    v0, v5, v10, v15 = _gb(v0, v5, v10, v15)
    v1, v6, v11, v12 = _gb(v1, v6, v11, v12)
    v2, v7, v8, v13 = _gb(v2, v7, v8, v13)
    v3, v4, v9, v14 = _gb(v3, v4, v9, v14)
    return [
        v0, v1, v2, v3, v4, v5, v6, v7,
        v8, v9, v10, v11, v12, v13, v14, v15,
    ]


def _fill_block(prev_block, ref_block, old_next):
    """fill_block: with_xor = the old next block is not None."""
    r = [pi ^ ri for pi, ri in zip(prev_block, ref_block)]
    tmp = list(r)
    if old_next is not None:
        tmp = [ti ^ ni for ti, ni in zip(tmp, old_next)]
    z = _compress_into(r)
    return [ti ^ zi for ti, zi in zip(tmp, z)]


def _compress_into(r):
    """Apply G's two P passes in place over R and return the result Z."""
    t = list(r)
    for i in range(8):
        base = 16 * i
        t[base:base + 16] = _p(t[base:base + 16])
    for i in range(8):
        base = 2 * i
        column = [
            t[base], t[base + 1],
            t[base + 16], t[base + 17],
            t[base + 32], t[base + 33],
            t[base + 48], t[base + 49],
            t[base + 64], t[base + 65],
            t[base + 80], t[base + 81],
            t[base + 96], t[base + 97],
            t[base + 112], t[base + 113],
        ]
        out = _p(column)
        for k in range(8):
            t[base + 16 * k] = out[2 * k]
            t[base + 16 * k + 1] = out[2 * k + 1]
    return t


class _Argon2idError(ValueError):
    """Raised when the requested parameters leave the implementable space."""


def _le32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def _h0(lanes, out_len, m_cost, t_cost, password, salt, secret, ad):
    h = hashlib.blake2b(digest_size=64)
    for value in (lanes, out_len, m_cost, t_cost, VERSION_13, TYPE_ARGON2ID):
        h.update(_le32(value))
    h.update(_le32(len(password)))
    h.update(password)
    h.update(_le32(len(salt)))
    h.update(salt)
    h.update(_le32(len(secret)))
    h.update(secret)
    h.update(_le32(len(ad)))
    h.update(ad)
    return h.digest()


def _hprime(t_len, data):
    """The variable-length hash H'(T, A), mirroring blake2b_long."""
    if t_len <= 64:
        return hashlib.blake2b(
            _le32(t_len) + data, digest_size=t_len
        ).digest()
    v = hashlib.blake2b(_le32(t_len) + data, digest_size=64).digest()
    out = bytearray(v[:32])
    to_produce = t_len - 32
    while to_produce > 64:
        v = hashlib.blake2b(v, digest_size=64).digest()
        out += v[:32]
        to_produce -= 32
    out += hashlib.blake2b(v, digest_size=to_produce).digest()
    return bytes(out)


def _load_block(raw: bytes):
    return [
        int.from_bytes(raw[i * 8:(i + 1) * 8], "little")
        for i in range(_BLOCK_QWORDS)
    ]


def _store_block(block) -> bytes:
    return b"".join(word.to_bytes(8, "little") for word in block)


def _index_alpha(pick_pass, pick_slice, index, seg_len, lane_length,
                 pseudo_rand, same_lane):
    """index_alpha(): map a pseudo-random word to a reference index."""
    if pick_pass == 0:
        if pick_slice == 0:
            ras = index - 1
        elif same_lane:
            ras = pick_slice * seg_len + index - 1
        else:
            ras = pick_slice * seg_len + (-1 if index == 0 else 0)
    elif same_lane:
        ras = lane_length - seg_len + index - 1
    else:
        ras = lane_length - seg_len + (-1 if index == 0 else 0)
    ras &= _MASK32
    rel = (pseudo_rand * pseudo_rand) >> 32
    rel = (ras - 1 - ((ras * rel) >> 32)) & _MASK32
    start = 0
    if pick_pass != 0 and pick_slice != _SYNC_POINTS - 1:
        start = (pick_slice + 1) * seg_len
    return (start + rel) % lane_length


def _next_addresses(input_block, counter_cell):
    counter_cell[0] += 1
    input_block[6] = counter_cell[0]
    address = _fill_block(_ZERO_BLOCK, input_block, None)
    return _fill_block(_ZERO_BLOCK, address, None)


def derive(password: bytes, salt: bytes, t_cost: int, m_cost: int,
           lanes: int = 1, out_len: int = 32,
           secret: bytes = b"", ad: bytes = b"") -> bytes:
    """Derive an Argon2id tag, byte-identical to the reference build."""
    if t_cost < 1:
        raise _Argon2idError("argon2 passes must be at least 1")
    if lanes < 1 or lanes > 0xFFFFFF:
        raise _Argon2idError("argon2 lanes out of range")
    if m_cost < 8 * lanes:
        raise _Argon2idError("argon2 memory must cover eight blocks per lane")
    m_prime = (4 * lanes) * (m_cost // (4 * lanes))
    lane_length = m_prime // lanes
    seg_len = lane_length // _SYNC_POINTS
    # A tiny profile can leave a segment empty (the RFC vector runs
    # lane_length 2): the reference build accepts it and only fills the
    # two initial blocks per lane, so no lower bound here.
    memory = [None] * m_prime
    # H0 covers the requested m_cost; only the matrix uses m_prime.
    h0 = _h0(lanes, out_len, m_cost, t_cost, password, salt, secret, ad)
    for lane in range(lanes):
        base = lane * lane_length
        for first_word in (0, 1):
            seed = h0 + _le32(first_word) + _le32(lane)
            memory[base + first_word] = _load_block(_hprime(1024, seed))
    for pick_pass in range(t_cost):
        for pick_slice in range(_SYNC_POINTS):
            for lane in range(lanes):
                _fill_segment(memory, lanes, lane_length, seg_len,
                              pick_pass, pick_slice, lane, t_cost, m_prime)
    final = list(memory[lane_length - 1])
    for lane in range(1, lanes):
        last = memory[lane * lane_length + lane_length - 1]
        final = [fi ^ li for fi, li in zip(final, last)]
    return _hprime(out_len, _store_block(final))


def _fill_segment(memory, lanes, lane_length, seg_len,
                  pick_pass, pick_slice, lane, t_cost, m_prime):
    independent = pick_pass == 0 and pick_slice < _SYNC_POINTS // 2
    input_block = [0] * _BLOCK_QWORDS
    counter_cell = [0]
    if independent:
        input_block[0] = pick_pass
        input_block[1] = lane
        input_block[2] = pick_slice
        input_block[3] = m_prime
        input_block[4] = t_cost
        input_block[5] = TYPE_ARGON2ID
    address = None
    start = 0
    if pick_pass == 0 and pick_slice == 0:
        start = 2
        if independent:
            address = _next_addresses(input_block, counter_cell)
    curr = lane * lane_length + pick_slice * seg_len + start
    if curr % lane_length == 0:
        prev = curr + lane_length - 1
    else:
        prev = curr - 1
    i = start
    while i < seg_len:
        if curr % lane_length == 1:
            prev = curr - 1
        if independent:
            if i % _ADDRESSES_IN_BLOCK == 0:
                address = _next_addresses(input_block, counter_cell)
            pseudo_rand = address[i % _ADDRESSES_IN_BLOCK]
        else:
            pseudo_rand = memory[prev][0]
        ref_lane = (pseudo_rand >> 32) % lanes
        if pick_pass == 0 and pick_slice == 0:
            ref_lane = lane
        same_lane = ref_lane == lane
        ref_index = _index_alpha(pick_pass, pick_slice, i, seg_len,
                                 lane_length, pseudo_rand & _MASK32,
                                 same_lane)
        ref_block = memory[ref_lane * lane_length + ref_index]
        prev_block = memory[prev]
        if pick_pass == 0:
            memory[curr] = _fill_block(prev_block, ref_block, None)
        else:
            memory[curr] = _fill_block(prev_block, ref_block, memory[curr])
        i += 1
        curr += 1
        prev += 1
