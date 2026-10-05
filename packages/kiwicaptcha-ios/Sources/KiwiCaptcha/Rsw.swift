import Foundation

/// Fixed-width 2048-bit Montgomery arithmetic with 32-bit limbs, for
/// the rsw time lock (`x^(2^T) mod n`). Every intermediate is one UInt64
/// (two 32-bit words plus a carry), so no 128-bit type is needed and the
/// package keeps its iOS 15 deployment target.
///
/// The core is the interleaved CIOS loop (Koç, Acar, Kaliski) over an
/// (s+2)-limb accumulator, whose bound analysis guarantees no lost
/// carry: per round the accumulator stays below 2nR and both carries
/// are absorbed by the two top words.
public enum Rsw {

    /// Limbs per 2048-bit value (32-bit words).
    public static let limbs = 64

    /// The issued modulus n: exactly 256 bytes, top bit set, odd.
    public struct Modulus {
        public let words: [UInt32] // little-endian, 64 limbs
        /// -n^-1 mod 2^32, the CIOS reduction constant.
        public let nprime: UInt32

        public init(_ bytes: [UInt8]) {
            precondition(bytes.count == 256, "the rsw modulus must be 256 bytes")
            var words = [UInt32](repeating: 0, count: Rsw.limbs)
            for i in 0..<Rsw.limbs {
                // Big-endian bytes, little-endian limbs: limb 0 is the
                // LAST four bytes, its low byte the final byte.
                let base = 256 - 4 * (i + 1)
                words[i] =
                    (UInt32(bytes[base]) << 24)
                    | (UInt32(bytes[base + 1]) << 16)
                    | (UInt32(bytes[base + 2]) << 8)
                    | UInt32(bytes[base + 3])
            }
            self.words = words
            self.nprime = Modulus.nPrime(words[0])
        }

        /// Newton iteration for the inverse of n0 modulo 2^32, negated.
        /// Five doublings take a 1-bit seed to full 32-bit precision.
        static func nPrime(_ n0: UInt32) -> UInt32 {
            var inverse: UInt32 = 1
            for _ in 0..<5 {
                inverse = inverse &* (2 &- n0 &* inverse)
            }
            return 0 &- inverse
        }
    }

    /// CIOS Montgomery multiplication: a * y * R^-1 mod n, with R =
    /// 2^2048. An a already in Montgomery form gives a*y mod n back in
    /// Montgomery form. Only valid for an odd modulus.
    public static func montMultiply(_ a: [UInt32], _ y: [UInt32], modulus: Modulus) -> [UInt32] {
        let b = modulus.words
        var s = [UInt32](repeating: 0, count: Rsw.limbs + 2)
        for i in 0..<Rsw.limbs {
            // Phase 1: S += a[i] * y, through the two top words.
            var carry: UInt32 = 0
            for j in 0..<Rsw.limbs {
                let total = UInt64(s[j])
                    + UInt64(a[i]) * UInt64(y[j])
                    + UInt64(carry)
                s[j] = UInt32(truncatingIfNeeded: total)
                carry = UInt32(truncatingIfNeeded: total >> 32)
            }
            var total = UInt64(s[Rsw.limbs]) + UInt64(carry)
            s[Rsw.limbs] = UInt32(truncatingIfNeeded: total)
            let topA = UInt32(truncatingIfNeeded: total >> 32)
            total = UInt64(s[Rsw.limbs + 1]) + UInt64(topA)
            s[Rsw.limbs + 1] = UInt32(truncatingIfNeeded: total)

            // Phase 2: fold in m*n with m = S[0] * nprime mod 2^32, and
            // shift one limb down in the same pass.
            let m = s[0] &* modulus.nprime
            total = UInt64(s[0]) + UInt64(m) * UInt64(b[0])
            carry = UInt32(truncatingIfNeeded: total >> 32)
            for j in 1..<Rsw.limbs {
                total = UInt64(s[j])
                    + UInt64(m) * UInt64(b[j])
                    + UInt64(carry)
                s[j - 1] = UInt32(truncatingIfNeeded: total)
                carry = UInt32(truncatingIfNeeded: total >> 32)
            }
            total = UInt64(s[Rsw.limbs]) + UInt64(carry)
            s[Rsw.limbs - 1] = UInt32(truncatingIfNeeded: total)
            s[Rsw.limbs] = s[Rsw.limbs + 1] + UInt32(truncatingIfNeeded: total >> 32)
            s[Rsw.limbs + 1] = 0
        }
        var result = Array(s[0..<Rsw.limbs])
        // The accumulator is below 2n: one conditional subtract, with
        // the extra top word folded into the decision.
        if s[Rsw.limbs] != 0 || greaterOrEqual(result, b) {
            result = subtract(result, b).0
        }
        return result
    }

    public static func greaterOrEqual(_ a: [UInt32], _ b: [UInt32]) -> Bool {
        for i in stride(from: a.count - 1, through: 0, by: -1) {
            if a[i] != b[i] { return a[i] > b[i] }
        }
        return true
    }

    public static func add(_ a: [UInt32], _ b: [UInt32]) -> ([UInt32], UInt32) {
        var out = [UInt32](repeating: 0, count: a.count)
        var carry: UInt32 = 0
        for i in 0..<a.count {
            let (s1, o1) = a[i].addingReportingOverflow(b[i])
            let (s2, o2) = s1.addingReportingOverflow(carry)
            out[i] = s2
            carry = (o1 ? 1 : 0) + (o2 ? 1 : 0)
        }
        return (out, carry)
    }

    public static func subtract(_ a: [UInt32], _ b: [UInt32]) -> ([UInt32], UInt32) {
        var out = [UInt32](repeating: 0, count: a.count)
        var borrow: UInt32 = 0
        for i in 0..<a.count {
            let (d1, u1) = a[i].subtractingReportingOverflow(b[i])
            let (d2, u2) = d1.subtractingReportingOverflow(borrow)
            out[i] = d2
            borrow = (u1 ? 1 : 0) + (u2 ? 1 : 0)
        }
        return (out, borrow)
    }

    /// A Montgomery-form value mod n.
    public struct Value {
        public var words: [UInt32] // little-endian, 64 limbs, Montgomery form

        /// Enter Montgomery form from a plain big-endian byte string
        /// (< n): reduce, then double 2048 times (a * 2^2048 = a * R).
        public init(_ plainBytes: [UInt8], modulus: Modulus) {
            precondition(plainBytes.count <= 256)
            var words = [UInt32](repeating: 0, count: Rsw.limbs)
            for i in 0..<Rsw.limbs {
                let msbIndex = plainBytes.count - 1 - 4 * i
                var word: UInt32 = 0
                for b in 0..<4 {
                    let idx = msbIndex - b
                    if idx >= 0 {
                        word |= UInt32(plainBytes[idx]) << (8 * UInt32(b))
                    }
                }
                words[i] = word
            }
            if greaterOrEqual(words, modulus.words) {
                words = subtract(words, modulus.words).0
            }
            var value = words
            for _ in 0..<2048 {
                // Double with the carry-out folded back in: 2v is below
                // 2n (v < n before the round, n above half the range),
                // so two conditional subtracts always reduce it.
                let (sum, carry) = Rsw.add(value, value)
                value = sum
                if carry != 0 || greaterOrEqual(value, modulus.words) {
                    value = subtract(value, modulus.words).0
                }
                if greaterOrEqual(value, modulus.words) {
                    value = subtract(value, modulus.words).0
                }
            }
            self.words = value
        }

        init(words: [UInt32]) {
            self.words = words
        }

        /// T sequential modular squarings, the rsw proof of time.
        public func squared(times t: Int, modulus: Modulus) -> Value {
            var value = words
            for _ in 0..<t {
                value = Rsw.montMultiply(value, value, modulus: modulus)
            }
            return Value(words: value)
        }

        /// Leave Montgomery form and render the 512-hex wire form:
        /// multiply by 1, which divides out exactly one factor of R.
        public func proofHex(modulus: Modulus) -> String {
            var one = [UInt32](repeating: 0, count: Rsw.limbs)
            one[0] = 1
            let plain = Rsw.montMultiply(words, one, modulus: modulus)
            var bytes = [UInt8](repeating: 0, count: 256)
            for i in 0..<Rsw.limbs {
                let w = plain[i]
                let base = 256 - 4 * (i + 1)
                bytes[base] = UInt8((w >> 24) & 0xff)
                bytes[base + 1] = UInt8((w >> 16) & 0xff)
                bytes[base + 2] = UInt8((w >> 8) & 0xff)
                bytes[base + 3] = UInt8(w & 0xff)
            }
            return bytes.map { String(format: "%02x", $0) }.joined()
        }
    }
}
