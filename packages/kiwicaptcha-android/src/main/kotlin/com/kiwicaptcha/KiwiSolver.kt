package com.kiwicaptcha

import java.security.MessageDigest
import java.util.Base64

/**
 * The challenge document, parsed from the challenge endpoint's JSON.
 * The wire keys are the endpoint's own (the same set the Rust solver
 * and the browser driver validate): camelCase mKib/targetBits/ttlSecs
 * beside the snake_case optional keys.
 *
 * Parsing is org.json-free and dependency-free: the solver reads the
 * document through [KiwiChallenge.fromJson], a small strict reader for
 * the documented key set, so the module carries zero dependencies.
 */
public data class KiwiChallenge(
    public val nonce: String,
    public val salt: String,
    public val algorithm: String,
    public val mKib: Long,
    public val t: Long,
    public val p: Long,
    public val targetBits: Long,
    public val prefix: String,
    public val ttlSecs: Long = 0,
    public val minDurationMs: Long = 0,
    public val executionProgram: String? = null,
    public val rswModulus: String? = null,
) {
    public companion object {
        /** Parse a challenge from the endpoint's JSON response body. */
        public fun fromJson(raw: String): KiwiChallenge = KiwiJsonReader.challenge(raw)
    }
}

/** A completed solve. */
public data class KiwiSolution(
    public val counter: Long,
    public val durationMs: Long,
    public val hashes: Long,
    /** The winning 64-hex digest, or the rsw 512-hex wire form. */
    public val hashHex: String,
    public val rswProof: String? = null,
    /** The telemetry object folded into the token: the empty object. */
    public val telemetry: String = "{}",
)

/** Why a solve refused to run or failed. */
public sealed class KiwiSolveError(message: String) : Exception(message) {
    public class Malformed(message: String) : KiwiSolveError(message)
    public class DifficultyBeyondCap(val targetBits: Long, val cap: Long) :
        KiwiSolveError("target_bits $targetBits exceeds the sha256 solver cap $cap")

    /** Argon2id is fail-closed: no vetted implementation on the JVM
     * platform ships with Android, and this package refuses a
     * home-grown memory-hard function. Link BouncyCastle or a native
     * library and extend [KiwiSolver] to lift it. */
    public class ArgonUnavailable :
        KiwiSolveError("argon2id is not implemented in this package (fail-closed)")

    public class UnsupportedRswParams(message: String) : KiwiSolveError(message)
    public class ExecutionUnsupported :
        KiwiSolveError("an execution-armed challenge needs the browser interpreter")

    public class Exhausted(val attempted: Long) :
        KiwiSolveError("no counter met the target within the $attempted-hash cap")
}

/** The shared protocol caps (protocol/limits.json). */
public object KiwiLimits {
    public const val MAX_HASHES: Long = 20_000_000L
    public const val SHA_MAX_TARGET_BITS: Long = 20L
    public const val RSW_T_MIN: Long = 10_000L
    public const val RSW_T_MAX: Long = 300_000L
    public const val MAX_DURATION_MS: Long = 3_600_000L
}

/** Canonical base64 (padded, standard alphabet) with no dependency. */
public object KiwiBase64 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    public fun encode(bytes: ByteArray): String {
        val out = StringBuilder()
        var i = 0
        while (i < bytes.size) {
            val b0 = bytes[i].toInt() and 0xff
            val b1 = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xff else 0
            val b2 = if (i + 2 < bytes.size) bytes[i + 2].toInt() and 0xff else 0
            out.append(ALPHABET[b0 shr 2])
            out.append(ALPHABET[((b0 and 0x03) shl 4) or (b1 shr 4)])
            out.append(if (i + 1 < bytes.size) ALPHABET[((b1 and 0x0f) shl 2) or (b2 shr 6)] else '=')
            out.append(if (i + 2 < bytes.size) ALPHABET[b2 and 0x3f] else '=')
            i += 3
        }
        return out.toString()
    }

    public fun decode(value: String): ByteArray? {
        if (value.length % 4 != 0) return null
        var end = value.length
        while (end > 0 && value[end - 1] == '=') end--
        val out = ByteArray(end * 3 / 4)
        var bits = 0
        var acc = 0
        var o = 0
        for (ch in value.substring(0, end)) {
            val idx = when (ch) {
                in 'A'..'Z' -> ch - 'A'
                in 'a'..'z' -> ch - 'a' + 26
                in '0'..'9' -> ch - '0' + 52
                '+' -> 62
                '/' -> 63
                else -> return null
            }
            acc = (acc shl 6) or idx
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out[o++] = ((acc shr bits) and 0xff).toByte()
            }
        }
        return out
    }
}

/**
 * The native Android solver core: the exact proof of work a browser
 * widget performs, inside the shared caps. SHA-256 comes from
 * java.security.MessageDigest, the rsw time lock from java.math
 * .BigInteger, and Argon2id is fail-closed (see
 * [KiwiSolveError.ArgonUnavailable]).
 */
public object KiwiSolver {

    /** Enforce the client contract before any work is spent. */
    public fun validate(c: KiwiChallenge) {
        if (!c.executionProgram.isNullOrEmpty()) {
            throw KiwiSolveError.ExecutionUnsupported()
        }
        if (c.nonce.length != 44 || !c.nonce.endsWith("=") ||
            !c.nonce.substring(0, 43).all { it.isLetterOrDigit() || it == '+' || it == '/' }
        ) {
            throw KiwiSolveError.Malformed("the nonce is not the standard base64 of 32 bytes")
        }
        if (c.prefix.isEmpty() || c.prefix.toByteArray(Charsets.UTF_8).size > 4096) {
            throw KiwiSolveError.Malformed("the prefix length is outside 1..=4096")
        }
        val salt = KiwiBase64.decode(c.salt)
        if (salt == null || salt.isEmpty() || c.salt.length > 512) {
            throw KiwiSolveError.Malformed("the salt is not decodable base64 or is oversized")
        }
        when (c.algorithm) {
            "sha256" -> if (c.targetBits < 1 || c.targetBits > KiwiLimits.SHA_MAX_TARGET_BITS) {
                throw KiwiSolveError.DifficultyBeyondCap(c.targetBits, KiwiLimits.SHA_MAX_TARGET_BITS)
            }
            "argon2id" -> throw KiwiSolveError.ArgonUnavailable()
            "rsw" -> {
                if (c.t < KiwiLimits.RSW_T_MIN || c.t > KiwiLimits.RSW_T_MAX || c.p != 1L || c.mKib != 0L) {
                    throw KiwiSolveError.UnsupportedRswParams(
                        "the squaring count T is outside the protocol bounds or the memory fields are nonzero",
                    )
                }
                val modulus = c.rswModulus?.let { KiwiBase64.decode(it) }
                if (modulus == null || modulus.size != 256 ||
                    (modulus[0].toInt() and 0x80) == 0 || (modulus[255].toInt() and 1) == 0
                ) {
                    throw KiwiSolveError.UnsupportedRswParams(
                        "the rsw modulus is not a canonical 2048-bit odd composite",
                    )
                }
            }
            else -> throw KiwiSolveError.Malformed("the algorithm is not one of sha256, argon2id, rsw")
        }
    }

    /** Solve a validated challenge at the browser's price. */
    public fun solve(challenge: KiwiChallenge, startedAt: Long = System.currentTimeMillis()): KiwiSolution {
        validate(challenge)
        return when (challenge.algorithm) {
            "sha256" -> solveSha256(challenge, startedAt)
            "rsw" -> solveRsw(challenge, startedAt)
            else -> throw KiwiSolveError.ArgonUnavailable()
        }
    }

    /** The SHA-256 search over `prefix || decimal(counter) || salt`. */
    public fun solveSha256(
        c: KiwiChallenge,
        startedAt: Long,
        maxHashes: Long = KiwiLimits.MAX_HASHES,
    ): KiwiSolution {
        val salt = KiwiBase64.decode(c.salt) ?: throw KiwiSolveError.Malformed("the salt stopped decoding")
        val digest = MessageDigest.getInstance("SHA-256")
        val prefix = c.prefix.toByteArray(Charsets.UTF_8)
        for (counter in 0 until maxHashes) {
            digest.reset()
            digest.update(prefix)
            digest.update(counter.toString().toByteArray(Charsets.UTF_8))
            digest.update(salt)
            val hash = digest.digest()
            if (leadingZeroBits(hash) >= c.targetBits) {
                return KiwiSolution(
                    counter = counter,
                    durationMs = durationSince(startedAt),
                    hashes = counter + 1,
                    hashHex = hex(hash),
                )
            }
        }
        throw KiwiSolveError.Exhausted(maxHashes)
    }

    /** The rsw time lock: T sequential modular squarings. */
    public fun solveRsw(c: KiwiChallenge, startedAt: Long): KiwiSolution {
        val modulusBytes = KiwiBase64.decode(c.rswModulus ?: "")
            ?: throw KiwiSolveError.UnsupportedRswParams("the rsw modulus is not base64")
        val n = java.math.BigInteger(1, modulusBytes)
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(c.prefix.toByteArray(Charsets.UTF_8))
        digest.update(c.nonce.toByteArray(Charsets.UTF_8))
        var value = java.math.BigInteger(1, digest.digest()).mod(n)
        val start = System.currentTimeMillis()
        repeat(c.t.toInt()) {
            value = value.modPow(java.math.BigInteger.TWO, n)
        }
        val proof = value.toString(16).padStart(512, '0')
        return KiwiSolution(
            counter = 0,
            durationMs = durationSince(start),
            hashes = c.t,
            hashHex = proof,
            rswProof = proof,
        )
    }

    public fun leadingZeroBits(bytes: ByteArray): Int {
        var count = 0
        for (b in bytes) {
            val byte = b.toInt() and 0xff
            if (byte == 0) {
                count += 8
                continue
            }
            var m = byte
            while (m and 0x80 == 0) {
                count++
                m = m shl 1
            }
            break
        }
        return count
    }

    public fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { String.format("%02x", it) }

    private fun durationSince(startedAt: Long): Long =
        (System.currentTimeMillis() - startedAt).coerceAtLeast(0)
}
