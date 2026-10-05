import Foundation
import CryptoKit

/// SHA-256 over concatenated byte arrays, via CryptoKit.
public enum SHA256Hash {
    public static func digest(_ parts: [UInt8]) -> [UInt8] {
        var data = Data()
        data.reserveCapacity(parts.count)
        data.append(contentsOf: parts)
        return Array(SHA256.hash(data: data))
    }
}

/// Canonical padded standard-base64, both directions, no dependency.
public enum Base64 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

    public static func encode(_ bytes: [UInt8]) -> String {
        var out = ""
        var i = 0
        while i < bytes.count {
            let b0 = bytes[i]
            let b1 = i + 1 < bytes.count ? bytes[i + 1] : nil
            let b2 = i + 2 < bytes.count ? bytes[i + 2] : nil
            out.append(alphabet[Int(b0 >> 2)])
            out.append(alphabet[Int((b0 & 0x03) << 4 | (b1 ?? 0) >> 4)])
            if let b1 {
                out.append(alphabet[Int((b1 & 0x0f) << 2 | (b2 ?? 0) >> 6)])
            } else {
                out.append("=")
            }
            if let b2 {
                out.append(alphabet[Int(b2 & 0x3f)])
            } else {
                out.append("=")
            }
            i += 3
        }
        return out
    }

    public static func decode(_ value: String) -> [UInt8]? {
        var trimmed = Substring(value)
        guard trimmed.count % 4 == 0 else { return nil }
        while trimmed.hasSuffix("=") { trimmed = trimmed.dropLast() }
        var out: [UInt8] = []
        out.reserveCapacity(trimmed.count * 3 / 4)
        var bits = 0
        var acc = 0
        for ch in trimmed.utf8 {
            let idx: Int
            switch ch {
            case 0x41...0x5a: idx = Int(ch - 0x41)
            case 0x61...0x7a: idx = Int(ch - 0x61) + 26
            case 0x30...0x39: idx = Int(ch - 0x30) + 52
            case 0x2b: idx = 62
            case 0x2f: idx = 63
            default: return nil
            }
            acc = (acc << 6) | idx
            bits += 6
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((acc >> bits) & 0xff))
            }
        }
        return out
    }
}

/// The wire token: base64(nonce.counter.durationMs.telemetry) with the
/// rsw proof riding as the final 512-hex segment. The bytes are the
/// widget's and the Rust solver's by construction (same grammar).
public enum KiwiToken {
    public static func encode(nonce: String, counter: UInt64, durationMs: UInt64,
                              telemetry: String = "{}", rswProof: String? = nil) -> String {
        let duration = min(max(durationMs, 0), KiwiLimits.maxDurationMs)
        var plain = "\(nonce).\(counter).\(duration).\(telemetry)"
        if let rswProof {
            plain += ".\(rswProof)"
        }
        return Base64.encode(Array(plain.utf8))
    }

    public static func encode(challenge: KiwiChallenge, solution: KiwiSolution) -> String {
        encode(
            nonce: challenge.nonce,
            counter: solution.counter,
            durationMs: solution.durationMs,
            telemetry: solution.telemetry,
            rswProof: solution.rswProof)
    }
}
