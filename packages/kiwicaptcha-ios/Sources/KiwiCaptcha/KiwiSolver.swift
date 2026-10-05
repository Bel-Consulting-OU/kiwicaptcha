import Foundation

/// The challenge document, parsed from the challenge endpoint's JSON.
/// The wire keys are the endpoint's own (the same set the Rust solver
/// and the browser driver validate): camelCase `mKib`/`targetBits`/
/// `ttlSecs`/`minDurationMs` beside the snake_case optional keys.
public struct KiwiChallenge: Codable, Equatable {
    public var nonce: String
    public var challenge: String?
    public var salt: String
    public var algorithm: String
    public var mKib: UInt64
    public var t: UInt64
    public var p: UInt64
    public var targetBits: UInt64
    public var ttlSecs: UInt64?
    public var minDurationMs: UInt64?
    public var prefix: String
    public var decoyField: String?
    public var executionProgram: String?
    public var rswModulus: String?

    enum CodingKeys: String, CodingKey {
        case nonce, challenge, salt, algorithm
        case mKib, t, p
        case targetBits, ttlSecs, minDurationMs, prefix
        case decoyField = "decoy_field"
        case executionProgram = "execution_program"
        case rswModulus = "rsw_modulus"
    }

    public init(
        nonce: String, challenge: String? = nil, salt: String,
        algorithm: String, mKib: UInt64, t: UInt64, p: UInt64,
        targetBits: UInt64, ttlSecs: UInt64? = nil, minDurationMs: UInt64? = nil,
        prefix: String, decoyField: String? = nil, executionProgram: String? = nil,
        rswModulus: String? = nil
    ) {
        self.nonce = nonce
        self.challenge = challenge
        self.salt = salt
        self.algorithm = algorithm
        self.mKib = mKib
        self.t = t
        self.p = p
        self.targetBits = targetBits
        self.ttlSecs = ttlSecs
        self.minDurationMs = minDurationMs
        self.prefix = prefix
        self.decoyField = decoyField
        self.executionProgram = executionProgram
        self.rswModulus = rswModulus
    }
}

/// Why a solve refused to run or failed to find a proof. The caps are
/// the shared ones (protocol/limits.json); this solver adds none.
public enum KiwiSolveError: Error, Equatable, CustomStringConvertible {
    case malformed(String)
    case difficultyBeyondCap(algorithm: String, targetBits: UInt64, cap: UInt64)
    /// The issued argon2id parameters are outside the shared profile
    /// (m outside 8..=65536 KiB, p != 1, or t outside 3..=6), so the
    /// reference implementation would derive something no server would
    /// accept.
    case unsupportedArgonParams(String)
    case argonDerivationFailed(String)
    case unsupportedRswParams(String)
    case executionUnsupported
    case exhausted(attempted: UInt64)

    public var description: String {
        switch self {
        case .malformed(let m): return "the challenge document is malformed: \(m)"
        case .difficultyBeyondCap(let a, let t, let c):
            return "target_bits \(t) exceeds the \(a) solver cap \(c)"
        case .unsupportedArgonParams(let m):
            return "the argon2id parameters are outside the shared profile: \(m)"
        case .argonDerivationFailed(let m):
            return "the argon2id derivation failed: \(m)"
        case .unsupportedRswParams(let m): return "the rsw parameters are outside the client contract: \(m)"
        case .executionUnsupported:
            return "an execution-armed challenge needs the browser interpreter; the native solver refuses it"
        case .exhausted(let a): return "no counter met the target within the \(a)-hash cap"
        }
    }
}

/// A completed solve.
public struct KiwiSolution: Equatable {
    public var counter: UInt64
    public var durationMs: UInt64
    public var hashes: UInt64
    /// The winning digest (64 lowercase hex), or the rsw final value's
    /// 512-hex wire form.
    public var hashHex: String
    public var rswProof: String?
    /// The telemetry object folded into the token: the empty object,
    /// because a native client claims no browser signals.
    public var telemetry: String

    public init(counter: UInt64, durationMs: UInt64, hashes: UInt64,
                hashHex: String, rswProof: String? = nil, telemetry: String = "{}") {
        self.counter = counter
        self.durationMs = durationMs
        self.hashes = hashes
        self.hashHex = hashHex
        self.rswProof = rswProof
        self.telemetry = telemetry
    }
}

/// The shared protocol caps (protocol/limits.json).
public enum KiwiLimits {
    public static let maxHashes: UInt64 = 20_000_000
    public static let shaMaxTargetBits: UInt64 = 20
    public static let argon2MaxTargetBits: UInt64 = 10
    public static let argon2MaxMKib: UInt64 = 65_536
    public static let argon2MaxTIssuance: UInt64 = 6
    public static let rswTMin: UInt64 = 10_000
    public static let rswTMax: UInt64 = 300_000
    public static let maxDurationMs: UInt64 = 3_600_000
}

/// The native solver core: the exact proof of work a browser widget
/// performs, inside the shared caps. SHA-256 comes from CryptoKit, the
/// rsw time lock from the package's own bignum, and Argon2id from the
/// vendored reference C implementation (the phc-winner-argon2 sources
/// behind the CArgon2 target, never a home-grown memory-hard function).
public enum KiwiSolver {

    /// Enforce the client contract before any work is spent.
    public static func validate(_ c: KiwiChallenge) throws {
        if c.executionProgram?.isEmpty == false {
            throw KiwiSolveError.executionUnsupported
        }
        guard c.nonce.count == 44, c.nonce.hasSuffix("="),
              c.nonce.dropLast(1).allSatisfy({ $0.isLetter || $0.isNumber || $0 == "+" || $0 == "/" })
        else {
            throw KiwiSolveError.malformed("the nonce is not the standard base64 of 32 bytes")
        }
        guard !c.prefix.isEmpty, c.prefix.utf8.count <= 4096 else {
            throw KiwiSolveError.malformed("the prefix length is outside 1..=4096")
        }
        let salt = Base64.decode(c.salt)
        guard let salt, !salt.isEmpty, c.salt.count <= 512 else {
            throw KiwiSolveError.malformed("the salt is not decodable base64 or is oversized")
        }
        switch c.algorithm {
        case "sha256":
            guard c.targetBits >= 1, c.targetBits <= KiwiLimits.shaMaxTargetBits else {
                throw KiwiSolveError.difficultyBeyondCap(
                    algorithm: c.algorithm, targetBits: c.targetBits,
                    cap: KiwiLimits.shaMaxTargetBits)
            }
        case "argon2id":
            // The shared profile: m within 8..=65536 KiB (the reference
            // implementation's own floor is 8*p), one lane, and the
            // issuance time cost 3..=6. target_bits rides the shared
            // argon cap (every derivation is memory-hard, so the cap
            // stays far below the SHA one).
            guard c.p == 1 else {
                throw KiwiSolveError.unsupportedArgonParams(
                    "the profile is single-lane (p \(c.p))")
            }
            guard c.mKib >= 8, c.mKib <= KiwiLimits.argon2MaxMKib else {
                throw KiwiSolveError.unsupportedArgonParams(
                    "m_kib \(c.mKib) is outside 8..=\(KiwiLimits.argon2MaxMKib)")
            }
            guard c.t >= 3, c.t <= KiwiLimits.argon2MaxTIssuance else {
                throw KiwiSolveError.unsupportedArgonParams(
                    "t \(c.t) is outside 3..=\(KiwiLimits.argon2MaxTIssuance)")
            }
            guard c.targetBits >= 1, c.targetBits <= KiwiLimits.argon2MaxTargetBits else {
                throw KiwiSolveError.difficultyBeyondCap(
                    algorithm: c.algorithm, targetBits: c.targetBits,
                    cap: KiwiLimits.argon2MaxTargetBits)
            }
        case "rsw":
            guard c.t >= KiwiLimits.rswTMin, c.t <= KiwiLimits.rswTMax, c.p == 1, c.mKib == 0 else {
                throw KiwiSolveError.unsupportedRswParams(
                    "the squaring count T is outside the protocol bounds or the memory fields are nonzero")
            }
            guard let modulus = Base64.decode(c.rswModulus ?? ""), modulus.count == 256,
                  modulus.first.flatMap({ $0 & 0x80 }) != 0,
                  modulus.last.flatMap({ $0 & 1 }) == 1
            else {
                throw KiwiSolveError.unsupportedRswParams(
                    "the rsw modulus is not a canonical 2048-bit odd composite")
            }
        default:
            throw KiwiSolveError.malformed("the algorithm is not one of sha256, argon2id, rsw")
        }
    }

    /// Solve a validated challenge at the browser's price.
    public static func solve(challenge: KiwiChallenge, startedAt: Date = Date()) throws -> KiwiSolution {
        try validate(challenge)
        switch challenge.algorithm {
        case "sha256":
            return try solveSha256(challenge, startedAt: startedAt)
        case "argon2id":
            return try solveArgon2id(challenge, startedAt: startedAt)
        case "rsw":
            return try solveRsw(challenge, startedAt: startedAt)
        default:
            throw KiwiSolveError.malformed("the algorithm is not one of sha256, argon2id, rsw")
        }
    }

    /// The Argon2id search: derive `argon2id(prefix + decimal(counter),
    /// salt)` with the issued m/t/p through the vendored reference
    /// implementation, first hit at target_bits wins, bounded by the
    /// shared hash cap. The framing is the one the server verifier
    /// recomputes (password = prefix + counter, salt bytes, 32 bytes
    /// out, Argon2id v1.3), identical with the wasm widget's solver.
    static func solveArgon2id(_ c: KiwiChallenge, startedAt: Date, maxHashes: UInt64 = KiwiLimits.maxHashes) throws -> KiwiSolution {
        let salt = try require(Base64.decode(c.salt), "the salt stopped decoding")
        let prefix = Array(c.prefix.utf8)
        var password = prefix
        let digitStart = password.count
        for counter in 0..<maxHashes {
            password.removeSubrange(digitStart...)
            password.append(contentsOf: Array(String(counter).utf8))
            let digest: [UInt8]
            do {
                digest = try Argon2Bridge.argon2idHash(
                    t: UInt32(c.t), mKib: UInt32(c.mKib), parallelism: UInt32(c.p),
                    password: password, salt: salt)
            } catch let error as Argon2Bridge.ArgonError {
                throw KiwiSolveError.argonDerivationFailed(String(describing: error))
            }
            if leadingZeroBits(digest) >= Int(c.targetBits) {
                return KiwiSolution(
                    counter: counter,
                    durationMs: durationSince(startedAt),
                    hashes: counter + 1,
                    hashHex: hex(digest))
            }
        }
        throw KiwiSolveError.exhausted(attempted: maxHashes)
    }

    /// The SHA-256 search: hash `prefix || decimal(counter) || salt`,
    /// first hit wins, bounded by the shared cap.
    static func solveSha256(_ c: KiwiChallenge, startedAt: Date, maxHashes: UInt64 = KiwiLimits.maxHashes) throws -> KiwiSolution {
        let salt = try require(Base64.decode(c.salt), "the salt stopped decoding")
        let prefix = Array(c.prefix.utf8)
        for counter in 0..<maxHashes {
            var input = prefix
            input.append(contentsOf: Array(String(counter).utf8))
            input.append(contentsOf: salt)
            let digest = SHA256Hash.digest(input)
            if leadingZeroBits(digest) >= Int(c.targetBits) {
                return KiwiSolution(
                    counter: counter,
                    durationMs: durationSince(startedAt),
                    hashes: counter + 1,
                    hashHex: hex(digest))
            }
        }
        throw KiwiSolveError.exhausted(attempted: maxHashes)
    }

    /// The rsw time lock: T sequential modular squarings of the derived
    /// base over the issued composite, rendered as the 512-hex form.
    static func solveRsw(_ c: KiwiChallenge, startedAt: Date) throws -> KiwiSolution {
        let modulusBytes = try require(Base64.decode(c.rswModulus ?? ""), "the rsw modulus is not base64")
        let modulus = Rsw.Modulus(modulusBytes)
        let digest = SHA256Hash.digest(Array(c.prefix.utf8) + Array(c.nonce.utf8))
        let value = Rsw.Value(digest, modulus: modulus)
        let squared = value.squared(times: Int(c.t), modulus: modulus)
        let proof = squared.proofHex(modulus: modulus)
        return KiwiSolution(
            counter: 0,
            durationMs: durationSince(startedAt),
            hashes: UInt64(c.t),
            hashHex: proof,
            rswProof: proof)
    }

    public static func leadingZeroBits(_ bytes: [UInt8]) -> Int {
        var count = 0
        for byte in bytes {
            if byte == 0 { count += 8; continue }
            var b = byte
            while (b & 0x80) == 0 { count += 1; b <<= 1 }
            break
        }
        return count
    }

    static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    static func durationSince(_ start: Date) -> UInt64 {
        UInt64(max(0, Date().timeIntervalSince(start) * 1000))
    }

    static func require<T>(_ value: T?, _ message: String) throws -> T {
        guard let value else { throw KiwiSolveError.malformed(message) }
        return value
    }
}
