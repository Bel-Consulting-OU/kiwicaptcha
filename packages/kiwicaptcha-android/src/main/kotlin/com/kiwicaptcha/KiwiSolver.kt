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
        KiwiSolveError("target_bits $targetBits exceeds the solver cap $cap")

    /** The argon2id parameters are outside the issued client contract
     * (m_kib 8..=65536 KiB and at least 8*p, t 3..=6, p = 1) — the same
     * refusal the Rust and Flutter solvers raise. */
    public class UnsupportedArgon2Params(val mKib: Long, val t: Long, val p: Long) :
        KiwiSolveError("argon2id parameters are outside the client contract (m_kib $mKib, t $t, p $p)")

    public class UnsupportedRswParams(message: String) : KiwiSolveError(message)
    public class ExecutionUnsupported :
        KiwiSolveError("an execution-armed challenge needs the browser interpreter")

    public class Exhausted(val attempted: Long) :
        KiwiSolveError("no counter met the target within the $attempted-hash cap")

    /** The generation's cancellation probe fired (widget closed, a
     * newer generation started, or the solve lost the expiry race):
     * the solver stopped before spending the next batch of work. */
    public class Cancelled : KiwiSolveError("the solve was cancelled")
}

/** The shared protocol caps (protocol/limits.json). */
public object KiwiLimits {
    public const val MAX_HASHES: Long = 20_000_000L
    public const val SHA_MAX_TARGET_BITS: Long = 20L
    public const val ARGON_MAX_TARGET_BITS: Long = 10L
    public const val ARGON_MAX_M_KIB: Long = 65_536L
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
 * .BigInteger, and Argon2id from the vetted pure-Java [Argon2id]
 * implementation the JVM SDK carries (RFC 9106-pinned; see
 * Argon2idTest). The argon2id preimage is the shared solver contract:
 * Argon2id(password `prefix || decimal(counter)`, salt, m_kib, t, p)
 * with a 32-byte tag, the same derivation the server verifier re-runs.
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
            "argon2id" -> {
                if (c.targetBits < 1 || c.targetBits > KiwiLimits.ARGON_MAX_TARGET_BITS) {
                    throw KiwiSolveError.DifficultyBeyondCap(c.targetBits, KiwiLimits.ARGON_MAX_TARGET_BITS)
                }
                // The issued argon2id contract: the memory/time/parallelism
                // ranges the Rust and Flutter solvers enforce, and the
                // profile split the server verifier accepts (p = 1, t >= 3).
                if (c.mKib < 8 || c.mKib > KiwiLimits.ARGON_MAX_M_KIB || c.mKib < 8 * c.p ||
                    c.t < 3 || c.t > 6 || c.p != 1L
                ) {
                    throw KiwiSolveError.UnsupportedArgon2Params(c.mKib, c.t, c.p)
                }
            }
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

    /**
     * Solve a validated challenge at the browser's price.
     *
     * [isCancelled] is the Interactive-Client Lifecycle v1 cooperative
     * probe: a cheap, non-blocking predicate checked on entry and then
     * at bounded cadence inside each search (see the checkpoint table
     * in protocol/interactive-client-v1/README.md). When it fires the
     * solver raises [KiwiSolveError.Cancelled] and schedules no further
     * CPU work.
     */
    public fun solve(
        challenge: KiwiChallenge,
        startedAt: Long = System.currentTimeMillis(),
        isCancelled: (() -> Boolean)? = null,
    ): KiwiSolution {
        validate(challenge)
        cancelledIf(isCancelled)
        return when (challenge.algorithm) {
            "sha256" -> solveSha256(challenge, startedAt, isCancelled = isCancelled)
            "argon2id" -> solveArgon2id(challenge, startedAt, isCancelled = isCancelled)
            "rsw" -> solveRsw(challenge, startedAt, isCancelled = isCancelled)
            else -> throw KiwiSolveError.Malformed("the algorithm is not one of sha256, argon2id, rsw")
        }
    }

    /** The SHA-256 search over `prefix || decimal(counter) || salt`.
     * The cancellation probe runs every 2048 candidates (protocol
     * Interactive-Client Lifecycle v1 latency table). */
    public fun solveSha256(
        c: KiwiChallenge,
        startedAt: Long,
        maxHashes: Long = KiwiLimits.MAX_HASHES,
        isCancelled: (() -> Boolean)? = null,
    ): KiwiSolution {
        val salt = KiwiBase64.decode(c.salt) ?: throw KiwiSolveError.Malformed("the salt stopped decoding")
        val digest = MessageDigest.getInstance("SHA-256")
        val prefix = c.prefix.toByteArray(Charsets.UTF_8)
        for (counter in 0 until maxHashes) {
            if (counter % CANCEL_CHECK_HASHES == 0L) cancelledIf(isCancelled)
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

    /**
     * The Argon2id search: Argon2id(password `prefix || decimal(counter)`,
     * salt, m_kib, t, p = 1) for each counter from zero, first hit wins,
     * exactly the loop the Rust solver and the wasm chunk solver run.
     * Each derivation allocates the m_kib-block working memory (up to
     * 64 MiB at the protocol ceiling), so the search is memory-hard at
     * the challenge's own price.
     */
    public fun solveArgon2id(
        c: KiwiChallenge,
        startedAt: Long,
        maxHashes: Long = KiwiLimits.MAX_HASHES,
        isCancelled: (() -> Boolean)? = null,
    ): KiwiSolution {
        val salt = KiwiBase64.decode(c.salt) ?: throw KiwiSolveError.Malformed("the salt stopped decoding")
        val prefix = c.prefix.toByteArray(Charsets.UTF_8)
        for (counter in 0 until maxHashes) {
            // The probe runs between candidate derivations: at most one
            // derivation of stale work after a firing probe.
            cancelledIf(isCancelled)
            val password = prefix + counter.toString().toByteArray(Charsets.UTF_8)
            val hash = Argon2id.derive(
                password,
                salt,
                c.t.toInt(),
                c.mKib.toInt(),
                c.p.toInt(),
                32,
                ByteArray(0),
                ByteArray(0),
            )
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

    /** The rsw time lock: T sequential modular squarings. The
     * cancellation probe runs every 256 squarings (protocol
     * Interactive-Client Lifecycle v1 latency table). */
    public fun solveRsw(
        c: KiwiChallenge,
        startedAt: Long,
        isCancelled: (() -> Boolean)? = null,
    ): KiwiSolution {
        val modulusBytes = KiwiBase64.decode(c.rswModulus ?: "")
            ?: throw KiwiSolveError.UnsupportedRswParams("the rsw modulus is not base64")
        val n = java.math.BigInteger(1, modulusBytes)
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(c.prefix.toByteArray(Charsets.UTF_8))
        digest.update(c.nonce.toByteArray(Charsets.UTF_8))
        var value = java.math.BigInteger(1, digest.digest()).mod(n)
        val two = java.math.BigInteger.TWO
        val start = System.currentTimeMillis()
        var squarings = 0L
        while (squarings < c.t) {
            if (squarings % CANCEL_CHECK_SQUARINGS == 0L) cancelledIf(isCancelled)
            value = value.modPow(two, n)
            squarings++
        }
        val proof = value.toString(16).padStart(512, '0')
        return KiwiSolution(
            counter = 0,
            durationMs = durationSince(start),
            hashes = squarings,
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

    /** Cancellation checkpoint cadences: the bounded latency the
     * Interactive-Client Lifecycle v1 contract pins (the most work a
     * cancelled generation can still schedule after its probe fired). */
    public const val CANCEL_CHECK_HASHES: Long = 2_048L
    public const val CANCEL_CHECK_SQUARINGS: Long = 256L

    private fun cancelledIf(isCancelled: (() -> Boolean)?) {
        if (isCancelled != null && isCancelled()) throw KiwiSolveError.Cancelled()
    }

    private fun durationSince(startedAt: Long): Long =
        (System.currentTimeMillis() - startedAt).coerceAtLeast(0)
}
