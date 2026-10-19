import CryptoKit
import Foundation
import React

/// The iOS KiwiCaptchaSolver native module (docs/NATIVE.md is the
/// authoritative spec). The Obj-C bridge name is exactly what the JS
/// layer looks up: `NativeModules.KiwiCaptchaSolver` /
/// TurboModuleRegistry. The selectors are wired in
/// KiwiCaptchaSolverBridge.m via RCT_EXTERN_MODULE.
///
/// One asynchronous method, JSON in, JSON out, strings across the
/// bridge, solved on this module's own serial background queue — never
/// the JS thread, never the main thread. SHA-256 via CryptoKit.
///
/// SHA-256 only, exactly like the Android module: argon2id and rsw are
/// refused with a typed code and the JS orchestration surfaces
/// `solver-unavailable` (see docs/NATIVE.md for the per-platform
/// Argon2id status: the SwiftPM package packages/kiwicaptcha-ios
/// implements Argon2id over the vendored reference C implementation).
@objc(KiwiCaptchaSolver)
public final class KiwiCaptchaSolver: NSObject {
  /// Shared cap, mirrored from protocol/limits.json (solver_max_hashes).
  private static let maxHashes = 20_000_000
  /// Shared sha256 difficulty cap (protocol/limits.json).
  private static let shaMaxTargetBits = 20
  /// Bounded native progress cadence: at most one report per 1024
  /// attempts AND per 100 ms, plus the winning report — never once per
  /// hash. The JS side re-gates at 100 ms and drops duplicate counts.
  private static let progressAttempts = 1024
  private static let progressMinInterval: TimeInterval = 0.1

  /// Serial queue: proof of work is CPU-bound, so solves serialize and
  /// stay off both the JS thread and the main thread.
  private let queue = DispatchQueue(label: "com.kiwicaptcha.solver", qos: .userInitiated)

  /// A refused challenge or a failed solve, carrying the machine-
  /// readable code the promise rejects with (the JS orchestration maps
  /// every rejection to `KiwiSolveError` with
  /// `refusal: "solver-unavailable"`; the code stays on the JS
  /// `Error.code` for diagnostics).
  private enum KiwiRefusal: Error, CustomStringConvertible {
    case malformed(String)
    case difficultyBeyondCap(Int)
    case unsupportedAlgorithm(String)
    case executionUnsupported
    case exhausted(Int)

    var description: String {
      switch self {
      case .malformed(let detail):
        return "the challenge document is malformed: \(detail)"
      case .difficultyBeyondCap(let bits):
        return "target_bits \(bits) exceeds the sha256 solver cap \(KiwiCaptchaSolver.shaMaxTargetBits)"
      case .unsupportedAlgorithm(let algorithm):
        return "\(algorithm) is not implemented in the KiwiCaptchaSolver native module (SHA-256 only)"
      case .executionUnsupported:
        return "an execution-armed challenge needs the browser interpreter; the native path refuses it"
      case .exhausted(let cap):
        return "no counter met the target within the \(cap)-hash cap"
      }
    }

    var code: String {
      switch self {
      case .malformed: return "MALFORMED"
      case .difficultyBeyondCap: return "DIFFICULTY_BEYOND_CAP"
      case .unsupportedAlgorithm: return "UNSUPPORTED_ALGORITHM"
      case .executionUnsupported: return "EXECUTION_UNSUPPORTED"
      case .exhausted: return "EXHAUSTED"
      }
    }
  }

  @objc(solve:resolver:rejecter:)
  func solve(
    _ challengeJson: String,
    resolver resolve: @escaping RCTPromiseResolveBlock,
    rejecter reject: @escaping RCTPromiseRejectBlock
  ) {
    run(challengeJson, progress: nil, resolve: resolve, reject: reject)
  }

  /// The optional progress channel. The native side owns the cadence
  /// (at most one report per 1024 attempts and 100 ms, plus the winning
  /// report); the JS side re-gates at 100 ms and drops duplicates, so
  /// the bridge can never flood the JS thread either.
  @objc(solveWithProgress:progressResolver:resolver:rejecter:)
  func solveWithProgress(
    _ challengeJson: String,
    progressResolver: @escaping RCTResponseSenderBlock,
    resolver resolve: @escaping RCTPromiseResolveBlock,
    rejecter reject: @escaping RCTPromiseRejectBlock
  ) {
    run(challengeJson, progress: progressResolver, resolve: resolve, reject: reject)
  }

  private func run(
    _ challengeJson: String,
    progress: RCTResponseSenderBlock?,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    queue.async {
      do {
        let answer = try KiwiCaptchaSolver.solveSync(challengeJson) { attempted in
          progress?([["attempted": attempted]])
        }
        resolve(answer)
      } catch let refusal as KiwiRefusal {
        reject(refusal.code, String(describing: refusal), refusal)
      } catch {
        reject("SOLVER_FAILED", String(describing: error), error)
      }
    }
  }

  /// The synchronous solve core: the shared solver contract, byte for
  /// byte (docs/NATIVE.md; verified against
  /// packages/kiwicaptcha-solver and the pure-TS fallback in
  /// src/solve.ts). Preimage `prefix || decimal(counter) || salt`
  /// (UTF-8/ASCII bytes; the salt as its decoded base64 bytes), counter
  /// from 0, winner on leadingZeroBits(digest) >= targetBits, capped at
  /// 20,000,000 hashes with a typed refusal on exhaustion. Answers the
  /// JSON string of the KiwiSolution shape:
  /// `{"counter":n,"durationMs":ms,"hashHex":"..."}`.
  static func solveSync(_ challengeJson: String, onProgress: ((Int) -> Void)? = nil) throws -> String {
    guard let raw = challengeJson.data(using: .utf8) else {
      throw KiwiRefusal.malformed("the document is not UTF-8")
    }
    let document: Any
    do {
      document = try JSONSerialization.jsonObject(with: raw)
    } catch {
      throw KiwiRefusal.malformed("the document is not valid JSON")
    }
    guard let object = document as? [String: Any] else {
      throw KiwiRefusal.malformed("the document is not a JSON object")
    }

    // -- the client contract, re-checked before any work is spent -----
    let executionProgram = object["execution_program"] as? String
    if let executionProgram, !executionProgram.isEmpty {
      throw KiwiRefusal.executionUnsupported
    }
    let nonce = try requireString(object, "nonce")
    if nonce.count != 44 || !nonce.hasSuffix("=") {
      throw KiwiRefusal.malformed("the nonce is not the standard base64 of 32 bytes")
    }
    let nonceHead = nonce.prefix(43)
    if !nonceHead.allSatisfy({ ($0.isASCII && ($0.isLetter || $0.isNumber)) || $0 == "+" || $0 == "/" }) {
      throw KiwiRefusal.malformed("the nonce is not the standard base64 of 32 bytes")
    }
    let prefix = try requireString(object, "prefix")
    if prefix.isEmpty || prefix.utf8.count > 4096 {
      throw KiwiRefusal.malformed("the prefix length is outside 1..=4096")
    }
    let saltText = try requireString(object, "salt")
    if saltText.isEmpty || saltText.count > 512 {
      throw KiwiRefusal.malformed("the salt is oversized or empty")
    }
    guard let salt = Data(base64Encoded: saltText), !salt.isEmpty else {
      throw KiwiRefusal.malformed("the salt is not decodable base64")
    }
    let algorithm = try requireString(object, "algorithm")
    let targetBits = try requireInt(object, "targetBits")
    switch algorithm {
    case "sha256":
      guard targetBits >= 1, targetBits <= shaMaxTargetBits else {
        throw KiwiRefusal.difficultyBeyondCap(targetBits)
      }
    case "argon2id", "rsw":
      throw KiwiRefusal.unsupportedAlgorithm(algorithm)
    default:
      throw KiwiRefusal.malformed("the algorithm is not one of sha256, argon2id, rsw")
    }

    // -- the search ----------------------------------------------------
    let startedAt = Date()
    var lastReportAt: TimeInterval = 0
    for counter in 0..<maxHashes {
      var hasher = SHA256()
      hasher.update(data: Data(prefix.utf8))
      hasher.update(data: Data(String(counter).utf8))
      hasher.update(data: salt)
      let digest = hasher.finalize()
      if leadingZeroBits(digest) >= targetBits {
        onProgress?(counter + 1)
        return answer(counter: counter, startedAt: startedAt, hashHex: hexString(digest))
      }
      if let onProgress, (counter + 1) % progressAttempts == 0 {
        let now = Date().timeIntervalSince1970
        if now - lastReportAt >= progressMinInterval {
          lastReportAt = now
          onProgress(counter + 1)
        }
      }
    }
    throw KiwiRefusal.exhausted(maxHashes)
  }

  // -- helpers ------------------------------------------------------------

  private static func answer(counter: Int, startedAt: Date, hashHex: String) throws -> String {
    let durationMs = Int(Date().timeIntervalSince(startedAt) * 1000)
    let answer: [String: Any] = [
      "counter": counter,
      "durationMs": durationMs,
      "hashHex": hashHex,
    ]
    guard let data = try? JSONSerialization.data(withJSONObject: answer),
      let json = String(data: data, encoding: .utf8)
    else {
      throw KiwiRefusal.malformed("the answer did not serialize")
    }
    return json
  }

  private static func requireString(_ object: [String: Any], _ key: String) throws -> String {
    guard let value = object[key] else {
      throw KiwiRefusal.malformed("the challenge is missing \(key)")
    }
    guard let text = value as? String else {
      throw KiwiRefusal.malformed("the challenge \(key) is not a string")
    }
    return text
  }

  private static func requireInt(_ object: [String: Any], _ key: String) throws -> Int {
    guard let value = object[key] else {
      throw KiwiRefusal.malformed("the challenge is missing \(key)")
    }
    guard let number = value as? Int else {
      throw KiwiRefusal.malformed("the challenge \(key) is not an integer")
    }
    return number
  }

  /// Leading zero bits, big-endian bit order (the shared difficulty
  /// notion).
  private static func leadingZeroBits(_ digest: SHA256Digest) -> Int {
    var count = 0
    for byte in digest {
      if byte == 0 {
        count += 8
        continue
      }
      var m = byte
      while (m & 0x80) == 0 {
        count += 1
        m <<= 1
      }
      break
    }
    return count
  }

  private static func hexString(_ digest: SHA256Digest) -> String {
    digest.map { String(format: "%02x", $0) }.joined()
  }
}
