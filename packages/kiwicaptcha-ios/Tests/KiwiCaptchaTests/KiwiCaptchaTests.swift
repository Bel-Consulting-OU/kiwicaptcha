import XCTest
@testable import KiwiCaptcha

/// The XCTest suite the Xcode CI runs (`swift test` with a full Xcode;
/// the CLI toolchain on this repository's runners lacks XCTest, so the
/// same vectors ship in the kiwi-selftest executable for local runs).
final class KiwiCaptchaTests: XCTestCase {

    private let nonce = String(repeating: "A", count: 43) + "="

    private func shaChallenge(_ mutate: (inout KiwiChallenge) -> Void = { _ in }) -> KiwiChallenge {
        var c = KiwiChallenge(
            nonce: nonce, salt: "AAECAw==", algorithm: "sha256",
            mKib: 0, t: 1, p: 1, targetBits: 8,
            prefix: "kiwi|login|")
        mutate(&c)
        return c
    }

    func testSha256Vectors() {
        XCTAssertEqual(SHA256Hash.digest(Array("abc".utf8)).map { String(format: "%02x", $0) }.joined(),
                       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        XCTAssertEqual(SHA256Hash.digest([]).map { String(format: "%02x", $0) }.joined(),
                       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    func testBase64RoundTrip() {
        XCTAssertEqual(Base64.encode(Array("foobar".utf8)), "Zm9vYmFy")
        XCTAssertEqual(Base64.encode(Array("foob".utf8)), "Zm9vYg==")
        XCTAssertEqual(Base64.decode("Zm9vYmFy"), Array("foobar".utf8))
        XCTAssertNil(Base64.decode("abc")) // length not a multiple of four
    }

    func testLeadingZeroBits() {
        XCTAssertEqual(KiwiSolver.leadingZeroBits([0, 0, 1]), 23)
        XCTAssertEqual(KiwiSolver.leadingZeroBits([0x80]), 0)
        XCTAssertEqual(KiwiSolver.leadingZeroBits([0x0f]), 4)
    }

    func testSha256SolveFindsKnownCounter() throws {
        let solution = try KiwiSolver.solve(challenge: shaChallenge())
        XCTAssertEqual(solution.counter, 45)
        XCTAssertEqual(solution.hashHex,
                       "00f9718e2a0397b3ca8fe75c44499fccee788e243173dadea546bd4e45af6982")
    }

    func testTokenGrammar() {
        let token = KiwiToken.encode(nonce: nonce, counter: 78, durationMs: 1200, telemetry: "{\"t\":1}")
        let plain = String(data: Data(base64Encoded: token) ?? Data(), encoding: .utf8)
        XCTAssertEqual(plain, "\(nonce).78.1200.{\"t\":1}")
    }

    func testTokenClampsDuration() {
        let token = KiwiToken.encode(nonce: nonce, counter: 1, durationMs: 9_999_999)
        let plain = String(data: Data(base64Encoded: token) ?? Data(), encoding: .utf8)
        XCTAssertTrue(plain?.contains(".1.3600000.") ?? false)
    }

    func testValidationRefusals() {
        XCTAssertThrowsError(try KiwiSolver.validate(shaChallenge { $0.executionProgram = "YQ==" })) {
            XCTAssertEqual($0 as? KiwiSolveError, .executionUnsupported)
        }
        // The profile refusals: m below the reference floor, a time
        // cost beyond the issuance ceiling and p != 1 never validate.
        XCTAssertNil(try? KiwiSolver.validate(shaChallenge {
            $0.algorithm = "argon2id"; $0.mKib = 4; $0.t = 3
        }))
        XCTAssertNil(try? KiwiSolver.validate(shaChallenge {
            $0.algorithm = "argon2id"; $0.mKib = 16_384; $0.t = 7
        }))
        XCTAssertNil(try? KiwiSolver.validate(shaChallenge {
            $0.algorithm = "argon2id"; $0.mKib = 16_384; $0.t = 3; $0.p = 2
        }))
        XCTAssertNil(try? KiwiSolver.validate(shaChallenge { $0.nonce = "short" }))
        XCTAssertNil(try? KiwiSolver.validate(shaChallenge { $0.targetBits = 21 }))
        XCTAssertNil(try? KiwiSolver.validate(shaChallenge { $0.salt = "not b64" }))
    }

    /// RFC 9106 section 5.3: the Argon2id vector with the secret and
    /// the associated data set, against the vendored reference C.
    func testArgon2idRfc9106Vector() throws {
        let tag = try Argon2Bridge.argon2idContext(
            passes: 3, mKib: 32, lanes: 4,
            password: [UInt8](repeating: 0x01, count: 32),
            salt: [UInt8](repeating: 0x02, count: 16),
            secret: [UInt8](repeating: 0x03, count: 8),
            associatedData: [UInt8](repeating: 0x04, count: 12),
            length: 32)
        XCTAssertEqual(tag.map { String(format: "%02x", $0) }.joined(),
                       "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    }

    /// The solver framing cross-checked against PHP's libsodium
    /// (sodium_crypto_pwhash, ARGON2ID13): password "kiwi|login|1",
    /// salt 000102..0f, t=3, m=16384 KiB, p=1, four leading zero bits.
    func testArgon2idSolveMatchesLibsodiumVector() throws {
        var c = shaChallenge()
        c.algorithm = "argon2id"
        c.salt = Base64.encode(Array(0..<16).map { UInt8($0) })
        c.mKib = 16_384
        c.t = 3
        c.targetBits = 4
        let solution = try KiwiSolver.solve(challenge: c)
        XCTAssertEqual(solution.counter, 24)
        XCTAssertEqual(solution.hashHex,
                       "0da72e6764530f4b23995bb62933f0df60d8694c9ad42df09c42ee558c320c57")
    }

    /// The composite (2^1023 + 1)(2^1023 + 3) * 3: canonical shape.
    private func composite2048() -> [UInt8] {
        // 3*2^2046 + 12*2^1023 + 9, big-endian bytes.
        var bytes = [UInt8](repeating: 0, count: 256)
        func setBit(_ bit: Int) {
            let byte = 255 - bit / 8
            bytes[byte] |= UInt8(1 << (bit % 8))
        }
        setBit(2047); setBit(2046) // 3 * 2^2046
        setBit(1026); setBit(1025) // 12 * 2^1023 = 2^1026 + 2^1025
        bytes[255] |= 9 // + 9 (low bits already clear here)
        return bytes
    }

    private func even2048() -> [UInt8] {
        var bytes = composite2048()
        bytes[255] &= 0xfe
        return bytes
    }

    func testRswValidationAndSolve() throws {
        let n = composite2048()
        let challenge = shaChallenge {
            $0.algorithm = "rsw"
            $0.t = 10_000
            $0.targetBits = 1
            $0.rswModulus = Base64.encode(n)
        }
        try KiwiSolver.validate(challenge)
        XCTAssertThrowsError(try KiwiSolver.validate(shaChallenge {
            $0.algorithm = "rsw"
            $0.t = 10_000
            $0.rswModulus = Base64.encode(even2048())
        }))
        XCTAssertThrowsError(try KiwiSolver.validate(shaChallenge {
            $0.algorithm = "rsw"
            $0.t = 9_999
            $0.rswModulus = Base64.encode(n)
        }))

        let solution = try KiwiSolver.solve(challenge: challenge)
        XCTAssertEqual(solution.rswProof?.count, 512)
        XCTAssertEqual(solution.rswProof,
                       "218193a822ff892a0f822bebecdc79e43abee9974bbf32d1e3aa93ad8b746adca73f30c87f670229c9f93bd2468e04a4462c539bbb560d57da744249f2cc4f0ddfd1c91a0cdcae0272a067bdac1c0b3857bc8d2a85d388b397aacadcae43590ec5a79a4974ca9e658224d325d4e36757c1a6f1552bb7bbc6802f449caa64b72f383a8ed64941cac8d2d1ed88f9f397559bb44cb874d963d0b3fb1825b0673c2db1793e3ce886161cb644b8ec62b0b167e5bb071db35990d6bf51c79e2762f73a0bf0b632d634481a1d18d421d61b222a95d195818b5f3203ac0937ec61b9ea2cb959a9047ebd905aa39f73fee1a9bde0f8a84707b917a463a10f15394723f414")
    }

    func testSiteverifyBody() throws {
        let body = String(data: try KiwiClient.siteverifyBody(secret: "s", response: "t"), encoding: .utf8) ?? ""
        XCTAssertTrue(body.contains("\"secret\":\"s\""))
        XCTAssertTrue(body.contains("\"response\":\"t\""))
        let withIp = String(data: try KiwiClient.siteverifyBody(secret: "s", response: "t", remoteip: "203.0.113.9"), encoding: .utf8) ?? ""
        XCTAssertTrue(withIp.contains("\"remoteip\":\"203.0.113.9\""))
    }
}
