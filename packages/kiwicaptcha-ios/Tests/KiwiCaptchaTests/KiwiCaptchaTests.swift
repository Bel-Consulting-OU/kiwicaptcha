import XCTest
import Foundation
@testable import KiwiCaptcha

#if canImport(UIKit)
    import UIKit
#endif

/// A URLProtocol that answers from a closure: the client and widget
/// suites exercise the real URLSession path without a network or a
/// local server.
final class MockURLProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = MockURLProtocol.handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.unknown))
            return
        }
        do {
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}

    /// The outbound request body, whatever form Foundation presents it
    /// in. URLSession hands a URLProtocol the body as an `httpBodyStream`
    /// (the data is converted to a stream on the way down the stack), so
    /// a double that only reads `httpBody` decodes an empty document and
    /// every body assertion degenerates. When `httpBody` is present it
    /// wins; otherwise the stream is drained to the end and the chunks
    /// concatenated. Pure Foundation with no URLSession involvement, so
    /// the drain logic itself is unit-tested directly below.
    static func requestBody(of request: URLRequest) -> Data {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return Data() }
        stream.open()
        defer { stream.close() }
        var body = Data()
        let bufferSize = 4096
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }
        while stream.hasBytesAvailable {
            let read = stream.read(buffer, maxLength: bufferSize)
            guard read > 0 else { break } // 0 = end of stream, < 0 = error
            body.append(buffer, count: read)
        }
        return body
    }
}

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

    override func tearDown() {
        MockURLProtocol.handler = nil
        super.tearDown()
    }

    /// A URLSession whose requests land in MockURLProtocol.
    private func mockSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        return URLSession(configuration: config)
    }

    private func httpResponse(_ request: URLRequest, _ status: Int) -> HTTPURLResponse {
        HTTPURLResponse(
            url: request.url ?? URL(string: "https://invalid.test")!,
            statusCode: status, httpVersion: nil,
            headerFields: ["Content-Type": "application/json"])!
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

    // MARK: - KiwiClient.fetchChallenge

    func testFetchChallengePostsTheDocumentAndDecodesTheAnswer() async throws {
        let challenge = shaChallenge()
        let payload = try JSONEncoder().encode(challenge)
        // Captured from inside the handler; the outbound document is
        // asserted separately below, after the fetch completes.
        var sentBody: Data?
        MockURLProtocol.handler = { request in
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(
                request.url?.absoluteString,
                "https://api.example.test/api/kcaptcha/challenge")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            sentBody = MockURLProtocol.requestBody(of: request)
            return (self.httpResponse(request, 200), payload)
        }
        let client = KiwiClient(
            endpoint: URL(string: "https://api.example.test/api/kcaptcha/challenge")!,
            sitekey: "pk-ios",
            session: mockSession())
        let fetched = try await client.fetchChallenge(
            scope: "login", algorithm: "sha256", requestBinding: "rb-1")
        XCTAssertEqual(fetched, challenge)
        XCTAssertEqual(fetched.prefix, "kiwi|login|")

        // The JSON document KiwiClient actually sent. Decoding must
        // succeed: an empty or truncated body is a failure here, which
        // is exactly what a double that skips httpBodyStream produces.
        let body = try JSONDecoder().decode(
            [String: String].self, from: XCTUnwrap(sentBody, "the POST body was never captured"))
        XCTAssertEqual(body["scope"], "login")
        XCTAssertEqual(body["sitekey"], "pk-ios")
        XCTAssertEqual(body["algorithm"], "sha256")
        XCTAssertEqual(body["request_binding"], "rb-1")
        XCTAssertEqual(body.count, 4)
    }

    func testFetchChallengeRefusesANon200Answer() async {
        MockURLProtocol.handler = { request in
            (self.httpResponse(request, 503), Data("down".utf8))
        }
        let client = KiwiClient(
            endpoint: URL(string: "https://api.example.test/kc")!,
            session: mockSession())
        do {
            _ = try await client.fetchChallenge(scope: "login")
            XCTFail("a 503 must be refused")
        } catch let error as KiwiClient.ClientError {
            XCTAssertEqual(error, .badStatus(503))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testFetchChallengeRefusesAMalformedDocument() async {
        MockURLProtocol.handler = { request in
            (self.httpResponse(request, 200), Data("{\"hello\":1}".utf8))
        }
        let client = KiwiClient(
            endpoint: URL(string: "https://api.example.test/kc")!,
            session: mockSession())
        do {
            _ = try await client.fetchChallenge(scope: "login")
            XCTFail("a non-challenge document must be refused")
        } catch let error as KiwiClient.ClientError {
            guard case .malformed = error else {
                return XCTFail("expected malformed, got \(error)")
            }
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    // MARK: - MockURLProtocol.requestBody

    // These exercise the body-drain logic itself (they run on the
    // GitHub macOS lane, the only place this repository has XCTest).

    func testRequestBodyHelperReadsAnInMemoryBody() throws {
        var request = URLRequest(url: URL(string: "https://api.example.test/kc")!)
        request.httpMethod = "POST"
        request.httpBody = Data("{\"scope\":\"login\"}".utf8)
        XCTAssertEqual(MockURLProtocol.requestBody(of: request), Data("{\"scope\":\"login\"}".utf8))
    }

    func testRequestBodyHelperDrainsABodyStreamAcrossChunks() throws {
        // Larger than the helper's 4096-byte read buffer, so a correct
        // drain must loop and concatenate several chunks.
        let sent = Data((0..<10_000).map { UInt8(truncatingIfNeeded: $0) })
        var request = URLRequest(url: URL(string: "https://api.example.test/kc")!)
        request.httpMethod = "POST"
        request.httpBody = nil
        request.httpBodyStream = InputStream(data: sent)
        XCTAssertEqual(MockURLProtocol.requestBody(of: request), sent)
    }

    func testRequestBodyHelperDrainsAnEmptyBodyStream() throws {
        var request = URLRequest(url: URL(string: "https://api.example.test/kc")!)
        request.httpBodyStream = InputStream(data: Data())
        XCTAssertTrue(MockURLProtocol.requestBody(of: request).isEmpty)
    }

    func testRequestBodyHelperWithoutAnyBodyIsEmpty() {
        let request = URLRequest(url: URL(string: "https://api.example.test/kc")!)
        XCTAssertEqual(MockURLProtocol.requestBody(of: request), Data())
    }

    // MARK: - Solver cancellation (cooperative, typed)

    /// The probe is checked at bounded-latency checkpoints. A probe
    /// that fires immediately stops the SHA-256 search before any
    /// candidate is hashed, and the typed `KiwiSolveError.cancelled`
    /// is the observable result.
    func testSolverSha256StopsAtTheCheckpointWhenCancelled() {
        var probes = 0
        do {
            _ = try KiwiSolver.solve(challenge: shaChallenge(), isCancelled: {
                probes += 1
                return true
            })
            XCTFail("a cancelled sha256 solve must throw")
        } catch let error as KiwiSolveError {
            XCTAssertEqual(error, .cancelled)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        // Checked at counter 0, before the first candidate: no
        // hashing happened after the check fired.
        XCTAssertEqual(probes, 1)
    }

    /// The argon2id search probes between candidate derivations: the
    /// same immediate probe refuses before the first derivation.
    func testSolverArgon2idStopsAtTheCheckpointWhenCancelled() {
        var probes = 0
        var c = shaChallenge()
        c.algorithm = "argon2id"
        c.mKib = 8
        c.t = 3
        do {
            _ = try KiwiSolver.solve(challenge: c, isCancelled: {
                probes += 1
                return true
            })
            XCTFail("a cancelled argon2id solve must throw")
        } catch let error as KiwiSolveError {
            XCTAssertEqual(error, .cancelled)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        XCTAssertEqual(probes, 1)
    }

    /// The rsw time lock probes every 256 squarings. One free
    /// checkpoint, then cancellation: the loop must stop at the very
    /// next checkpoint (256 squarings into a 10_000-squaring run),
    /// which is the bounded-latency contract.
    func testSolverRswStopsWithinOneCheckpointWhenCancelled() {
        var probes = 0
        let challenge = shaChallenge {
            $0.algorithm = "rsw"
            $0.t = 10_000
            $0.targetBits = 1
            $0.rswModulus = Base64.encode(composite2048())
        }
        do {
            _ = try KiwiSolver.solve(challenge: challenge, isCancelled: {
                probes += 1
                return probes > 1
            })
            XCTFail("a cancelled rsw solve must throw")
        } catch let error as KiwiSolveError {
            XCTAssertEqual(error, .cancelled)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        // First probe (before squaring 0) passed, the second (at
        // squaring 256) fired and the loop threw there.
        XCTAssertEqual(probes, 2)
    }

    // MARK: - Lifecycle v1 delivery decision

    /// One scenario of protocol/interactive-client-v1/
    /// lifecycle-vectors.json. The file is the shared, first-writer
    /// contract: the same vectors gate every client.
    private struct LifecycleVector: Decodable {
        struct Expectation: Decodable {
            let deliver: Bool
            let deliverAtMs: Int64
            let reason: String
        }
        let name: String
        let receivedAtMs: Int64
        let ttlSecs: Int64
        let minDurationMs: Int64
        let solveFinishedAtMs: Int64
        let nowMs: Int64
        let cancelled: Bool
        let expect: Expectation
    }

    /// protocol/interactive-client-v1/lifecycle-vectors.json, located
    /// relative to the package root (this file lives in
    /// Tests/KiwiCaptchaTests under it; the two ".." steps then reach
    /// the repository's protocol/ directory).
    private func lifecycleVectorsURL() throws -> URL {
        let testsDir = (#filePath as NSString).deletingLastPathComponent // Tests/KiwiCaptchaTests
        let testsRoot = (testsDir as NSString).deletingLastPathComponent // Tests
        let packageRoot = (testsRoot as NSString).deletingLastPathComponent // the package root
        return URL(fileURLWithPath: packageRoot, isDirectory: true)
            .appendingPathComponent("../../protocol/interactive-client-v1/lifecycle-vectors.json")
    }

    func testDeliveryDecisionMatchesTheSharedLifecycleVectors() throws {
        let data = try Data(contentsOf: try lifecycleVectorsURL())
        let vectors = try JSONDecoder().decode([LifecycleVector].self, from: data)
        XCTAssertGreaterThanOrEqual(vectors.count, 10, "the shared vector set is the contract floor")
        for vector in vectors {
            if vector.cancelled {
                // Cancellation is caller-side: it never reaches the
                // pure helper, and the pinned expectation is that it
                // delivers nothing.
                XCTAssertFalse(vector.expect.deliver, vector.name)
                XCTAssertEqual(vector.expect.deliverAtMs, 0, vector.name)
                XCTAssertEqual(vector.expect.reason, "cancelled", vector.name)
                continue
            }
            let decision = KiwiLifecycle.deliveryDecision(
                receivedAtMs: vector.receivedAtMs,
                ttlSecs: vector.ttlSecs,
                minDurationMs: vector.minDurationMs,
                solveFinishedAtMs: vector.solveFinishedAtMs,
                nowMs: vector.nowMs)
            XCTAssertEqual(decision.deliver, vector.expect.deliver, vector.name)
            XCTAssertEqual(decision.deliverAtMs, vector.expect.deliverAtMs, vector.name)
            XCTAssertEqual(decision.reason, vector.expect.reason, vector.name)
        }
    }

    /// Direct unit cases beside the shared file: the boundaries the
    /// contract calls out verbatim.
    func testDeliveryDecisionUnitCases() {
        let received: Int64 = 1_000_000

        // A fast solve with no gates delivers at once.
        var d = KiwiLifecycle.deliveryDecision(
            receivedAtMs: received, ttlSecs: 120, minDurationMs: 0,
            solveFinishedAtMs: received + 400, nowMs: received + 400)
        XCTAssertTrue(d.deliver && d.deliverAtMs == received + 400 && d.reason == "deliver")

        // Boundary equality delivers: now == deliverAtMs.
        d = KiwiLifecycle.deliveryDecision(
            receivedAtMs: received, ttlSecs: 120, minDurationMs: 5_000,
            solveFinishedAtMs: received + 400, nowMs: received + 5_000)
        XCTAssertTrue(d.deliver && d.deliverAtMs == received + 5_000 && d.reason == "deliver")

        // The min-submit floor defers the finished token to the floor.
        d = KiwiLifecycle.deliveryDecision(
            receivedAtMs: received, ttlSecs: 120, minDurationMs: 5_000,
            solveFinishedAtMs: received + 400, nowMs: received + 400)
        XCTAssertTrue(!d.deliver && d.deliverAtMs == received + 5_000 && d.reason == "defer")

        // The solve finished exactly at expiry: expired (equality is
        // expiry, the token may never arrive at or after the deadline).
        d = KiwiLifecycle.deliveryDecision(
            receivedAtMs: received, ttlSecs: 30, minDurationMs: 0,
            solveFinishedAtMs: received + 29_000, nowMs: received + 29_000)
        XCTAssertTrue(!d.deliver && d.deliverAtMs == 0 && d.reason == "expired")

        // One millisecond before expiry still delivers (the fixed 1 s
        // margin: expiresAt = received + 30_000 - 1_000).
        d = KiwiLifecycle.deliveryDecision(
            receivedAtMs: received, ttlSecs: 30, minDurationMs: 0,
            solveFinishedAtMs: received + 28_999, nowMs: received + 28_999)
        XCTAssertTrue(d.deliver && d.deliverAtMs == received + 28_999 && d.reason == "deliver")

        // A gate that could only land at or after expiry is dead up
        // front: minSubmitAtMs == expiresAtMs → expired.
        d = KiwiLifecycle.deliveryDecision(
            receivedAtMs: received, ttlSecs: 30, minDurationMs: 29_000,
            solveFinishedAtMs: received + 1_000, nowMs: received + 1_000)
        XCTAssertTrue(!d.deliver && d.deliverAtMs == 0 && d.reason == "expired")

        // A late evaluation checkpoint (after a deferral) past the
        // deadline never delivers either.
        d = KiwiLifecycle.deliveryDecision(
            receivedAtMs: received, ttlSecs: 30, minDurationMs: 25_000,
            solveFinishedAtMs: received + 500, nowMs: received + 30_000)
        XCTAssertTrue(!d.deliver && d.deliverAtMs == 0 && d.reason == "expired")

        // No TTL: never expires, the floor still applies.
        d = KiwiLifecycle.deliveryDecision(
            receivedAtMs: received, ttlSecs: 0, minDurationMs: 2_000,
            solveFinishedAtMs: received + 500, nowMs: received + 500)
        XCTAssertTrue(!d.deliver && d.deliverAtMs == received + 2_000 && d.reason == "defer")
        d = KiwiLifecycle.deliveryDecision(
            receivedAtMs: received, ttlSecs: 0, minDurationMs: 0,
            solveFinishedAtMs: received + 500, nowMs: received + 500)
        XCTAssertTrue(d.deliver && d.deliverAtMs == received + 500 && d.reason == "deliver")

        // ttl of one second: the margin consumes it, the deadline is
        // parse time itself and no solve can win.
        d = KiwiLifecycle.deliveryDecision(
            receivedAtMs: received, ttlSecs: 1, minDurationMs: 0,
            solveFinishedAtMs: received, nowMs: received)
        XCTAssertTrue(!d.deliver && d.deliverAtMs == 0 && d.reason == "expired")

        // The clock helpers agree with the decision arithmetic.
        XCTAssertEqual(
            KiwiLifecycle.expiresAt(receivedAtMs: received, ttlSecs: 30),
            received + 29_000)
        XCTAssertEqual(
            KiwiLifecycle.expiresAt(receivedAtMs: received, ttlSecs: 0),
            Int64.max)
        XCTAssertEqual(
            KiwiLifecycle.minSubmitAt(receivedAtMs: received, minDurationMs: 0), 0)
        XCTAssertEqual(
            KiwiLifecycle.minSubmitAt(receivedAtMs: received, minDurationMs: 2_500),
            received + 2_500)
    }

    // MARK: - KiwiClient capability header

    func testFetchChallengeSendsTheExecutionMaxVersionCapabilityHeader() async throws {
        let payload = try JSONEncoder().encode(shaChallenge())
        var capability: String?
        MockURLProtocol.handler = { request in
            capability = request.value(forHTTPHeaderField: "Kiwi-Execution-Max-Version")
            return (self.httpResponse(request, 200), payload)
        }
        let client = KiwiClient(
            endpoint: URL(string: "https://api.example.test/kc")!,
            session: mockSession())
        _ = try await client.fetchChallenge(scope: "login")
        // Version 0: the native path runs no execution interpreter,
        // and the endpoint must not arm execution_program against it.
        XCTAssertEqual(capability, "0")
    }

    // MARK: - Rsw direct entry points

    func testRswMontgomeryRoundTripAndSquaring() {
        // n = 2^2047 + 1: the canonical wire shape (256 bytes, top bit
        // set, odd), which is all Modulus requires.
        var bytes = [UInt8](repeating: 0, count: 256)
        bytes[0] = 0x80
        bytes[255] = 0x01
        let modulus = Rsw.Modulus(bytes)
        XCTAssertEqual(Rsw.limbs, 64)
        let one = Rsw.Value([1], modulus: modulus)
        // Entering Montgomery form then leaving it is the identity.
        XCTAssertEqual(one.proofHex(modulus: modulus),
                       String(repeating: "0", count: 510) + "01")
        // squared(times:) is exactly t sequential Montgomery squarings.
        var manual = one.words
        for _ in 0..<3 {
            manual = Rsw.montMultiply(manual, manual, modulus: modulus)
        }
        XCTAssertEqual(one.squared(times: 3, modulus: modulus).words, manual)
        XCTAssertEqual(Rsw.greaterOrEqual([0, 1], [0, 1]), true)
        XCTAssertEqual(Rsw.greaterOrEqual([0, 1], [0, 2]), false)
    }

    // MARK: - Widget update path (UIKit platforms only)

    #if canImport(UIKit)
        @MainActor
        func testWidgetApplyConfigurationRestartsOnlyOnConnectionChange() {
            let view = KiwiCaptchaUIView(
                client: KiwiClient(
                    endpoint: URL(string: "https://a.example.test/kc")!,
                    sitekey: "pk-a", session: mockSession()),
                scope: "login")
            let same = view.applyConfiguration(
                endpoint: URL(string: "https://a.example.test/kc")!,
                scope: "login", sitekey: "pk-a",
                onVerify: { _ in })
            XCTAssertFalse(same)
            XCTAssertEqual(view.restartCount, 0)
            XCTAssertEqual(view.state, .idle)

            let changed = view.applyConfiguration(
                endpoint: URL(string: "https://b.example.test/kc")!,
                scope: "login", sitekey: "pk-a",
                onVerify: { _ in })
            XCTAssertTrue(changed)
            XCTAssertEqual(view.restartCount, 1)
            XCTAssertEqual(view.endpoint.absoluteString, "https://b.example.test/kc")
            XCTAssertEqual(view.state, .solving)
            XCTAssertTrue(view.token.isEmpty)

            // Scope and sitekey are connection identity too.
            XCTAssertTrue(view.applyConfiguration(
                endpoint: URL(string: "https://b.example.test/kc")!,
                scope: "signup", sitekey: "pk-a",
                onVerify: { _ in }))
            XCTAssertTrue(view.applyConfiguration(
                endpoint: URL(string: "https://b.example.test/kc")!,
                scope: "signup", sitekey: "pk-b",
                onVerify: { _ in }))
            XCTAssertEqual(view.restartCount, 3)
            XCTAssertEqual(view.sitekey, "pk-b")
        }

        @MainActor
        func testWidgetRestartCancelsThePreviousTask() async throws {
            let challenge = shaChallenge()
            let payload = try JSONEncoder().encode(challenge)
            MockURLProtocol.handler = { request in
                // Hold the first fetch open long enough for the update
                // to cancel it, then answer a valid document anyway.
                Thread.sleep(forTimeInterval: 0.2)
                return (self.httpResponse(request, 200), payload)
            }
            let view = KiwiCaptchaUIView(
                client: KiwiClient(
                    endpoint: URL(string: "https://a.example.test/kc")!,
                    session: mockSession()),
                scope: "login")
            view.start()
            let first = view.task
            XCTAssertNotNil(first)
            XCTAssertFalse(first?.isCancelled ?? true)

            view.applyConfiguration(
                endpoint: URL(string: "https://b.example.test/kc")!,
                scope: "login", sitekey: nil,
                onVerify: { _ in })
            XCTAssertTrue(first?.isCancelled ?? false)
            XCTAssertNotNil(view.task)
        }

        @MainActor
        func testWidgetSolvesAndUsesTheLatestCallback() async throws {
            let challenge = shaChallenge()
            let payload = try JSONEncoder().encode(challenge)
            MockURLProtocol.handler = { request in
                (self.httpResponse(request, 200), payload)
            }
            let endpoint = URL(string: "https://api.example.test/kc")!
            let view = KiwiCaptchaUIView(
                client: KiwiClient(endpoint: endpoint, session: mockSession()),
                scope: "login")
            let verified = expectation(description: "verified")
            var token: String?
            // An unchanged connection refreshes the callback without a
            // restart (the solve started by init's caller observes it).
            view.applyConfiguration(
                endpoint: endpoint, scope: "login", sitekey: nil,
                onVerify: { value in
                    token = value
                    verified.fulfill()
                })
            XCTAssertEqual(view.restartCount, 0)
            view.start()
            await fulfillment(of: [verified], timeout: 10)
            XCTAssertEqual(view.state, .verified)
            XCTAssertFalse(view.token.isEmpty)
            XCTAssertEqual(token, view.token)
        }

        @MainActor
        func testSwiftUIWidgetCarriesItsConfiguration() {
            var verified: String?
            let view = KiwiCaptchaView(
                endpoint: URL(string: "https://api.example.test/kc")!,
                scope: "signup",
                sitekey: "pk-swiftui",
                onVerify: { verified = $0 })
            XCTAssertEqual(view.endpoint.absoluteString, "https://api.example.test/kc")
            XCTAssertEqual(view.scope, "signup")
            XCTAssertEqual(view.sitekey, "pk-swiftui")
            view.onVerify("tok")
            XCTAssertEqual(verified, "tok")
        }

        // MARK: Lifecycle v1 on the widget

        /// minDurationMs gates delivery: the token is finished early
        /// but held (cancellably) to the floor before onVerify fires.
        @MainActor
        func testWidgetDefersDeliveryUntilMinSubmit() async throws {
            let challenge = shaChallenge { $0.minDurationMs = 600 }
            let payload = try JSONEncoder().encode(challenge)
            MockURLProtocol.handler = { request in
                (self.httpResponse(request, 200), payload)
            }
            let view = KiwiCaptchaUIView(
                client: KiwiClient(
                    endpoint: URL(string: "https://api.example.test/kc")!,
                    session: mockSession()),
                scope: "login")
            let verified = expectation(description: "verified after the floor")
            let startedAt = Date()
            view.applyConfiguration(
                endpoint: URL(string: "https://api.example.test/kc")!,
                scope: "login", sitekey: nil,
                onVerify: { _ in verified.fulfill() })
            view.start()
            await fulfillment(of: [verified], timeout: 10)
            let elapsedMs = Date().timeIntervalSince(startedAt) * 1000
            // The solve itself takes milliseconds; the wait to the
            // min-submit floor is the reason delivery happened here.
            XCTAssertGreaterThanOrEqual(elapsedMs, 550)
            XCTAssertEqual(view.state, .verified)
            XCTAssertFalse(view.token.isEmpty)
        }

        /// The expiry clock starts at parse time, not after solving.
        /// A 1 s TTL means the deadline lands at parse time itself
        /// (the fixed 1 s margin consumes the TTL): no solve can win,
        /// the widget shows the expired state and onVerify is
        /// suppressed — the pre-contract behavior delivered first and
        /// only then started the countdown.
        @MainActor
        func testWidgetNeverDeliversWhenTheDeadlineBeatsTheSolve() async throws {
            let challenge = shaChallenge { $0.ttlSecs = 1 }
            let payload = try JSONEncoder().encode(challenge)
            MockURLProtocol.handler = { request in
                (self.httpResponse(request, 200), payload)
            }
            let view = KiwiCaptchaUIView(
                client: KiwiClient(
                    endpoint: URL(string: "https://api.example.test/kc")!,
                    session: mockSession()),
                scope: "login")
            let expired = expectation(description: "expired at the parse-anchored deadline")
            var delivered = false
            view.applyConfiguration(
                endpoint: URL(string: "https://api.example.test/kc")!,
                scope: "login", sitekey: nil,
                onVerify: { _ in delivered = true },
                onExpire: { expired.fulfill() })
            view.start()
            await fulfillment(of: [expired], timeout: 10)
            XCTAssertFalse(delivered, "a token past expiresAtMs must never be delivered")
            XCTAssertTrue(view.token.isEmpty)
            XCTAssertEqual(view.state, .expired)
        }

        /// Only the newest generation emits: a run superseded by a
        /// configuration change has its late challenge answer
        /// discarded — it never verifies, never overwrites the token.
        @MainActor
        func testWidgetSupersedesTheStaleGenerationToken() async throws {
            let payload = try JSONEncoder().encode(shaChallenge())
            var servedFirst = false
            MockURLProtocol.handler = { request in
                if !servedFirst {
                    servedFirst = true
                    // Hold the first run's fetch open so the restart
                    // happens well before it answers.
                    Thread.sleep(forTimeInterval: 0.3)
                }
                return (self.httpResponse(request, 200), payload)
            }
            let view = KiwiCaptchaUIView(
                client: KiwiClient(
                    endpoint: URL(string: "https://a.example.test/kc")!,
                    session: mockSession()),
                scope: "login")
            view.start()
            var verifyCount = 0
            let verified = expectation(description: "verified by the newest generation")
            view.applyConfiguration(
                endpoint: URL(string: "https://b.example.test/kc")!,
                scope: "login", sitekey: nil,
                onVerify: { _ in
                    verifyCount += 1
                    verified.fulfill()
                })
            await fulfillment(of: [verified], timeout: 10)
            // Let the superseded run's late answer land and be
            // discarded by its dead generation.
            try await Task.sleep(nanoseconds: 500_000_000)
            XCTAssertEqual(verifyCount, 1, "only the newest generation may emit")
            XCTAssertEqual(view.state, .verified)
            XCTAssertFalse(view.token.isEmpty)
        }

        /// The container is no longer one collapsed accessibility
        /// element: the Retry button stays a real, reachable button,
        /// the status label is the live region, and the progress bar
        /// reports itself.
        @MainActor
        func testWidgetAccessibilityKeepsControlsSeparate() {
            let view = KiwiCaptchaUIView(
                client: KiwiClient(
                    endpoint: URL(string: "https://api.example.test/kc")!,
                    session: mockSession()),
                scope: "login")
            XCTAssertFalse(view.isAccessibilityElement, "the control must not collapse its children")
            XCTAssertTrue(view.retryButton.isAccessibilityElement)
            XCTAssertEqual(view.retryButton.accessibilityLabel, "Retry")
            XCTAssertTrue(view.statusLabel.isAccessibilityElement)
            XCTAssertEqual(view.statusLabel.accessibilityLabel, "Security check status")
            XCTAssertTrue(
                view.statusLabel.accessibilityTraits.contains(.updatesFrequently),
                "the status label is the live region")
            XCTAssertEqual(view.statusLabel.accessibilityValue, "Idle")
            XCTAssertTrue(view.progress.isAccessibilityElement)
            XCTAssertEqual(view.progress.accessibilityLabel, "Security check progress")
        }
    #endif
}
