import Foundation
import CArgon2

/// The bridge to the vendored reference argon2 C implementation
/// (phc-winner-argon2 20190702). No memory-hard math lives in Swift:
/// every derivation goes through the audited reference sources, so the
/// package stays fail-closed by construction (a build without CArgon2
/// cannot compile the solver's argon leg).
public enum Argon2Bridge {

    public enum ArgonError: Error, Equatable {
        /// The reference implementation returned a non-zero error code
        /// (an ARGON2_ERROR_CODES value; the text comes from
        /// argon2_error_message).
        case code(Int32, String)
    }

    /// The solver primitive: Argon2id v1.3 over `password` and `salt`
    /// with the issued parameters, 32 raw bytes out. This is the exact
    /// framing the server verifier recomputes: password = prefix +
    /// decimal counter, salt = the raw record salt, m in KiB, one lane.
    public static func argon2idHash(
        t: UInt32, mKib: UInt32, parallelism: UInt32,
        password: [UInt8], salt: [UInt8], length: Int = 32
    ) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: length)
        let rc = argon2id_hash_raw(
            t, mKib, parallelism,
            password, password.count,
            salt, salt.count,
            &out, out.count)
        guard rc == Int32(ARGON2_OK.rawValue) else { throw ArgonError.code(rc, errorMessage(rc)) }
        return out
    }

    /// The full reference context: the secret and the associated data
    /// ride the derivation, so the RFC 9106 vectors (which carry both)
    /// pin the whole vendored implementation, not just the raw path.
    public static func argon2idContext(
        passes: UInt32, mKib: UInt32, lanes: UInt32,
        password: [UInt8], salt: [UInt8], secret: [UInt8],
        associatedData: [UInt8], length: Int
    ) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: length)
        var pwd = password
        var slt = salt
        var sec = secret
        var ad = associatedData
        var ctx = argon2_context()
        ctx.t_cost = passes
        ctx.m_cost = mKib
        ctx.lanes = lanes
        ctx.threads = lanes
        ctx.version = UInt32(ARGON2_VERSION_13.rawValue)
        ctx.allocate_cbk = nil
        ctx.free_cbk = nil
        ctx.flags = 0
        let rc = out.withUnsafeMutableBufferPointer { outPtr in
            pwd.withUnsafeMutableBufferPointer { pwdPtr in
                slt.withUnsafeMutableBufferPointer { saltPtr in
                    sec.withUnsafeMutableBufferPointer { secPtr in
                        ad.withUnsafeMutableBufferPointer { adPtr in
                            ctx.out = outPtr.baseAddress
                            ctx.outlen = UInt32(length)
                            ctx.pwd = pwdPtr.baseAddress
                            ctx.pwdlen = UInt32(pwdPtr.count)
                            ctx.salt = saltPtr.baseAddress
                            ctx.saltlen = UInt32(saltPtr.count)
                            ctx.secret = secPtr.baseAddress
                            ctx.secretlen = UInt32(secPtr.count)
                            ctx.ad = adPtr.baseAddress
                            ctx.adlen = UInt32(adPtr.count)
                            return argon2id_ctx(&ctx)
                        }
                    }
                }
            }
        }
        guard rc == Int32(ARGON2_OK.rawValue) else { throw ArgonError.code(rc, errorMessage(rc)) }
        return out
    }

    static func errorMessage(_ code: Int32) -> String {
        let cstr = argon2_error_message(code)
        return cstr.map { String(cString: $0) } ?? "unknown argon2 error"
    }
}
