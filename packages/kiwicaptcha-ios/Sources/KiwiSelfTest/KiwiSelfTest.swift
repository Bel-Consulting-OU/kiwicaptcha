import Foundation
import KiwiCaptcha

/// The local self-test runner: the same vectors the XCTest suite pins,
/// runnable without Xcode (`swift run kiwi-selftest`). Exits non-zero on
/// the first failure.
@main
struct KiwiSelfTest {
    static var failures = 0

    static func check(_ name: String, _ condition: Bool) {
        if condition {
            print("ok   \(name)")
        } else {
            failures += 1
            print("FAIL \(name)")
        }
    }

    static func main() async {
        let encoder = { (s: String) in Array(s.utf8) }

        // SHA-256 via CryptoKit: the standard vectors.
        check("sha256 abc", SHA256Hash.digest(encoder("abc")).map { String(format: "%02x", $0) }.joined()
            == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        check("sha256 empty", SHA256Hash.digest([]).map { String(format: "%02x", $0) }.joined()
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        // Base64 round trip and known vectors.
        check("base64 foobar", Base64.encode(Array("foobar".utf8)) == "Zm9vYmFy")
        check("base64 foob", Base64.encode(Array("foob".utf8)) == "Zm9vYg==")
        check("base64 decode", Base64.decode("Zm9vYmFy") == Array("foobar".utf8))

        // leading zero bits, the shared difficulty notion.
        check("zeros 23", KiwiSolver.leadingZeroBits([0, 0, 1]) == 23)
        check("zeros 4", KiwiSolver.leadingZeroBits([0x0f]) == 4)

        // The sha256 search over a fixed challenge.
        let challenge = KiwiChallenge(
            nonce: String(repeating: "A", count: 43) + "=",
            salt: "AAECAw==",
            algorithm: "sha256",
            mKib: 0, t: 1, p: 1,
            targetBits: 8,
            prefix: "kiwi|login|")
        do {
            let solution = try KiwiSolver.solve(challenge: challenge)
            check("sha256 solve counter", solution.counter == 45)
            check("sha256 solve digest",
                  solution.hashHex == "00f9718e2a0397b3ca8fe75c44499fccee788e243173dadea546bd4e45af6982")
        } catch {
            failures += 1
            print("FAIL sha256 solve threw \(error)")
        }

        // Token grammar pinned byte-exactly.
        let token = KiwiToken.encode(
            nonce: challenge.nonce, counter: 78, durationMs: 1200, telemetry: "{\"t\":1}")
        let plain = String(data: Data(base64: token) ?? Data(), encoding: .utf8) ?? ""
        check("token grammar", plain == "\(challenge.nonce).78.1200.{\"t\":1}")

        // Validation refusals.
        check("refuse execution",
              (try? KiwiSolver.validate(variant(challenge, executionProgram: "YQ=="))) == nil)
        check("refuse argon parameters outside the profile",
              (try? KiwiSolver.validate(argonChallenge(mKib: 4))) == nil
                  && (try? KiwiSolver.validate(argonChallenge(t: 7))) == nil)
        check("refuse nonce",
              (try? KiwiSolver.validate(variant(challenge, nonce: "short"))) == nil)
        check("refuse bits",
              (try? KiwiSolver.validate(variant(challenge, targetBits: 21))) == nil)

        // Argon2id against the vendored reference implementation. The
        // first vector is RFC 9106 section 5.3 (Argon2id, version 1.3,
        // m=32 KiB, t=3, p=4, secret and associated data set), the only
        // public vector exercising the full reference context. The
        // second is the solver framing cross-checked against PHP's
        // libsodium (sodium_crypto_pwhash, ARGON2ID13): password
        // "kiwi|login|1", salt 000102..0f, t=3, m=16384 KiB, p=1.
        do {
            let rfc = try Argon2Bridge.argon2idContext(
                passes: 3, mKib: 32, lanes: 4,
                password: [UInt8](repeating: 0x01, count: 32),
                salt: [UInt8](repeating: 0x02, count: 16),
                secret: [UInt8](repeating: 0x03, count: 8),
                associatedData: [UInt8](repeating: 0x04, count: 12),
                length: 32)
            check("argon2id RFC 9106 vector",
                  rfc.map { String(format: "%02x", $0) }.joined()
                      == "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        } catch {
            failures += 1
            print("FAIL argon2id RFC 9106 vector threw \(error)")
        }
        do {
            let issued = argonChallenge()
            let solution = try KiwiSolver.solve(challenge: issued)
            check("argon2id libsodium cross-check",
                  solution.counter == 24
                      && solution.hashHex
                          == "0da72e6764530f4b23995bb62933f0df60d8694c9ad42df09c42ee558c320c57")
        } catch {
            failures += 1
            print("FAIL argon2id libsodium cross-check threw \(error)")
        }

        // rsw: modulus shapes and a real squaring sequence.
        let n = composite2048()
        let rswChallenge = KiwiChallenge(
            nonce: challenge.nonce, salt: challenge.salt, algorithm: "rsw",
            mKib: 0, t: 10_000, p: 1, targetBits: 1,
            prefix: "kiwi|login|", rswModulus: Base64.encode(n))
        check("accept canonical rsw", (try? KiwiSolver.validate(rswChallenge)) != nil)
        check("refuse even rsw modulus",
              (try? KiwiSolver.validate(variant(rswChallenge, rswModulus: Base64.encode(even2048())))) == nil)
        check("refuse short rsw t",
              (try? KiwiSolver.validate(variant(rswChallenge, t: 9_999))) == nil)
        do {
            let solution = try KiwiSolver.solve(challenge: rswChallenge)
            check("rsw proof is 512 hex and matches manual loop",
                  solution.rswProof?.count == 512
                      && solution.rswProof == manualRsw(prefix: "kiwi|login|", nonce: challenge.nonce, n: n, t: 10_000))
            // The vector computed independently (node BigInt, the same
            // composite): pins the Montgomery machinery to the wire form.
            check("rsw proof matches the external vector",
                  solution.rswProof == "218193a822ff892a0f822bebecdc79e43abee9974bbf32d1e3aa93ad8b746adca73f30c87f670229c9f93bd2468e04a4462c539bbb560d57da744249f2cc4f0ddfd1c91a0cdcae0272a067bdac1c0b3857bc8d2a85d388b397aacadcae43590ec5a79a4974ca9e658224d325d4e36757c1a6f1552bb7bbc6802f449caa64b72f383a8ed64941cac8d2d1ed88f9f397559bb44cb874d963d0b3fb1825b0673c2db1793e3ce886161cb644b8ec62b0b167e5bb071db35990d6bf51c79e2762f73a0bf0b632d634481a1d18d421d61b222a95d195818b5f3203ac0937ec61b9ea2cb959a9047ebd905aa39f73fee1a9bde0f8a84707b917a463a10f15394723f414")
        } catch {
            failures += 1
            print("FAIL rsw solve threw \(error)")
        }

        // The siteverify body shape.
        let body = String(data: try! KiwiClient.siteverifyBody(secret: "s", response: "t"), encoding: .utf8) ?? ""
        check("siteverify body", body == "{\"response\":\"t\",\"secret\":\"s\"}"
            || body == "{\"secret\":\"s\",\"response\":\"t\"}")

        if failures == 0 {
            print("selftest: all checks passed")
        } else {
            print("selftest: \(failures) failure(s)")
            exit(1)
        }
    }

    static func variant(
        _ c: KiwiChallenge, nonce: String? = nil, algorithm: String? = nil,
        targetBits: UInt64? = nil, t: UInt64? = nil, executionProgram: String? = nil,
        rswModulus: String? = nil
    ) -> KiwiChallenge {
        var copy = c
        if let nonce { copy.nonce = nonce }
        if let algorithm { copy.algorithm = algorithm }
        if let targetBits { copy.targetBits = targetBits }
        if let t { copy.t = t }
        if let executionProgram { copy.executionProgram = executionProgram }
        if let rswModulus { copy.rswModulus = rswModulus }
        return copy
    }

    /// An argon2id challenge at the profile defaults (16 MiB, t=3,
    /// p=1), overridable field by field for the refusal checks.
    static func argonChallenge(
        salt: String = Base64.encode(Array(0..<16).map { UInt8($0) }),
        mKib: UInt64 = 16_384, t: UInt64 = 3, targetBits: UInt64 = 4
    ) -> KiwiChallenge {
        KiwiChallenge(
            nonce: String(repeating: "A", count: 43) + "=",
            salt: salt,
            algorithm: "argon2id",
            mKib: mKib, t: t, p: 1,
            targetBits: targetBits,
            prefix: "kiwi|login|")
    }

    /// (2^1023 + 1) * (2^1023 + 3) * 3: a 2048-bit odd composite (the
    /// factor 3 lifts the product into the top bit, as a canonical
    /// modulus requires).
    static func composite2048() -> [UInt8] {
        let a = UInt256ish().shifted1023().adding(1)
        let b = UInt256ish().shifted1023().adding(3)
        return mulSmall(a.multiply2048(b), 3)
    }

    /// Big-endian byte multiply by a small odd constant.
    static func mulSmall(_ bytes: [UInt8], _ m: UInt8) -> [UInt8] {
        var out = bytes
        var carry = 0
        for i in stride(from: out.count - 1, through: 0, by: -1) {
            let v = Int(out[i]) * Int(m) + carry
            out[i] = UInt8(v & 0xff)
            carry = v >> 8
        }
        return out
    }

    static func even2048() -> [UInt8] {
        var bytes = composite2048()
        bytes[255] &= 0xfe
        return bytes
    }
}

// A minimal 1024-bit helper for building test moduli (product of two
// 1024-bit halves via a schoolbook multiplier).
struct UInt256ish {
    var words: [UInt64] = .init(repeating: 0, count: 16)

    func shifted1023() -> Self { // 2^1023
        var copy = self
        copy.words = .init(repeating: 0, count: 16)
        copy.words[15] = UInt64(1) << 63
        return copy
    }

    func adding(_ x: UInt64) -> Self {
        var copy = self
        var carry = x
        for i in 0..<16 where carry != 0 {
            let (s, o) = copy.words[i].addingReportingOverflow(carry)
            copy.words[i] = s
            carry = o ? 1 : 0
        }
        return copy
    }

    /// Full 1024x1024 -> 2048-bit product using UInt32 limbs.
    func multiply2048(_ other: Self) -> [UInt8] {
        func toU32(_ w: [UInt64]) -> [UInt32] {
            var out: [UInt32] = []
            for word in w {
                out.append(UInt32(word & 0xffff_ffff))
                out.append(UInt32(word >> 32))
            }
            return out
        }
        let a = toU32(words)
        let b = toU32(other.words)
        var acc = [UInt32](repeating: 0, count: a.count + b.count)
        for i in 0..<a.count {
            var carry: UInt32 = 0
            for j in 0..<b.count {
                let prod = UInt64(a[i]) * UInt64(b[j])
                let lo = UInt32(truncatingIfNeeded: prod)
                let hi = UInt32(prod >> 32)
                let (s1, o1) = acc[i + j].addingReportingOverflow(lo)
                let (s2, o2) = s1.addingReportingOverflow(carry)
                acc[i + j] = s2
                carry = hi &+ (o1 ? 1 : 0) &+ (o2 ? 1 : 0)
            }
            var k = i + b.count
            while carry != 0 && k < acc.count {
                let (s, o) = acc[k].addingReportingOverflow(carry)
                acc[k] = s
                carry = o ? 1 : 0
                k += 1
            }
        }
        var bytes = [UInt8](repeating: 0, count: 256)
        for (i, word) in acc.enumerated() where i < 64 {
            for bit in 0..<4 {
                bytes[255 - (i * 4 + bit)] = UInt8((word >> (8 * UInt64(bit))) & 0xff)
            }
        }
        return bytes
    }
}

extension Data {
    init?(base64Padded string: String) { self.init(base64Encoded: string) }
    init?(base64: String) { self.init(base64Encoded: base64) }
}

/// The manual rsw reference for the self-test: T squarings of
/// sha256(prefix || nonce) mod n, computed with the package's own
/// primitives end to end.
func manualRsw(prefix: String, nonce: String, n: [UInt8], t: Int) -> String {
    let modulus = Rsw.Modulus(n)
    let digest = SHA256Hash.digest(Array(prefix.utf8) + Array(nonce.utf8))
    let value = Rsw.Value(digest, modulus: modulus)
    return value.squared(times: t, modulus: modulus).proofHex(modulus: modulus)
}
