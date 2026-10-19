package com.kiwicaptcha.reactnative

import org.json.JSONObject
import java.security.MessageDigest

/**
 * The SHA-256 solve core the [KiwiCaptchaSolverModule] runs on its
 * background thread. This is the shared solver contract, byte for byte
 * (docs/NATIVE.md; verified against packages/kiwicaptcha-solver and the
 * pure-TS fallback in src/solve.ts):
 *
 * - preimage: `prefix || decimal(counter) || salt` — the prefix and the
 *   ASCII decimal counter as UTF-8/ASCII bytes, the salt as its decoded
 *   base64 bytes, counter starting at 0;
 * - winner: the first counter whose SHA-256 digest shows at least
 *   `targetBits` leading zero bits (big-endian bit order);
 * - bounds: 1 <= targetBits <= 20, at most 20,000,000 hashes
 *   (protocol/limits.json solver_max_hashes), then a typed
 *   [KiwiRefusalException] with the `EXHAUSTED` refusal.
 *
 * The module ships SHA-256 only: argon2id and rsw are refused with the
 * `UNSUPPORTED_ALGORITHM` code (see docs/NATIVE.md for the per-platform
 * Argon2id status). JSON in, JSON out, strings across the bridge.
 */
internal object KiwiSolverCore {

    /** The shared cap, mirrored from protocol/limits.json. */
    internal const val MAX_HASHES: Int = 20_000_000

    /** The shared sha256 difficulty cap (protocol/limits.json). */
    internal const val SHA_MAX_TARGET_BITS: Int = 20

    /**
     * Bounded native progress cadence: at most one report per 1024
     * attempts AND per 100 ms, plus the winning report — never once per
     * hash. The JS side re-gates at 100 ms and drops duplicate counts.
     */
    private const val PROGRESS_ATTEMPTS: Int = 1024
    private const val PROGRESS_MIN_MS: Long = 100L

    /**
     * Solve one validated challenge document. Answers the JSON string of
     * the KiwiSolution shape the JS side parses:
     * `{"counter":n,"durationMs":ms,"hashHex":"..."}`.
     */
    internal fun solve(challengeJson: String, onProgress: ((Int) -> Unit)? = null): String {
        val challenge = parse(challengeJson)
        validate(challenge)
        val salt = decodeBase64(challenge.salt)
            ?: throw KiwiRefusalException(
                KiwiRefusalException.MALFORMED,
                "the salt is not decodable base64",
            )

        val digest = messageDigest()
        val prefix = challenge.prefix.toByteArray(Charsets.UTF_8)
        val startedAt = System.currentTimeMillis()
        var lastReportAt = 0L

        for (counter in 0 until MAX_HASHES) {
            digest.reset()
            digest.update(prefix)
            digest.update(counter.toString().toByteArray(Charsets.UTF_8))
            digest.update(salt)
            val hash = digest.digest()
            if (leadingZeroBits(hash) >= challenge.targetBits) {
                onProgress?.invoke(counter + 1)
                return solutionJson(counter, System.currentTimeMillis() - startedAt, hex(hash))
            }
            if (onProgress != null && (counter + 1) % PROGRESS_ATTEMPTS == 0) {
                val now = System.currentTimeMillis()
                if (now - lastReportAt >= PROGRESS_MIN_MS) {
                    lastReportAt = now
                    onProgress(counter + 1)
                }
            }
        }
        throw KiwiRefusalException(
            KiwiRefusalException.EXHAUSTED,
            "no counter met the target within the $MAX_HASHES-hash cap",
        )
    }

    // -- parsing ----------------------------------------------------------

    /** The fields the SHA-256 leg relies on, read strictly. */
    private class Sha256Challenge(
        val nonce: String,
        val salt: String,
        val algorithm: String,
        val targetBits: Long,
        val prefix: String,
        val executionProgram: String?,
    )

    private fun parse(challengeJson: String): Sha256Challenge {
        val document = try {
            JSONObject(challengeJson)
        } catch (_: Throwable) {
            throw KiwiRefusalException(
                KiwiRefusalException.MALFORMED,
                "the challenge document is not valid JSON",
            )
        }
        return Sha256Challenge(
            nonce = requireString(document, "nonce"),
            salt = requireString(document, "salt"),
            algorithm = requireString(document, "algorithm"),
            targetBits = requireLong(document, "targetBits"),
            prefix = requireString(document, "prefix"),
            executionProgram = optionalString(document, "execution_program"),
        )
    }

    private fun requireString(document: JSONObject, key: String): String {
        if (!document.has(key) || document.isNull(key)) {
            throw KiwiRefusalException(
                KiwiRefusalException.MALFORMED,
                if (document.has(key)) "the challenge $key is not a string" else "the challenge is missing $key",
            )
        }
        // org.json coerces scalars to strings; the JS orchestration has
        // already validated the wire shape, and every semantic bound
        // below (lengths, alphabet, decodability) is re-checked here.
        return document.optString(key)
    }

    private fun optionalString(document: JSONObject, key: String): String? {
        if (!document.has(key) || document.isNull(key)) return null
        return document.optString(key)
    }

    private fun requireLong(document: JSONObject, key: String): Long {
        if (!document.has(key) || document.isNull(key)) {
            throw KiwiRefusalException(KiwiRefusalException.MALFORMED, "the challenge is missing $key")
        }
        return try {
            document.getLong(key)
        } catch (_: Throwable) {
            throw KiwiRefusalException(
                KiwiRefusalException.MALFORMED,
                "the challenge $key is not an integer",
            )
        }
    }

    // -- the client contract, re-checked before any work is spent ---------

    private fun validate(c: Sha256Challenge) {
        if (!c.executionProgram.isNullOrEmpty()) {
            throw KiwiRefusalException(
                KiwiRefusalException.EXECUTION_UNSUPPORTED,
                "an execution-armed challenge needs the browser interpreter; the native path refuses it",
            )
        }
        if (
            c.nonce.length != 44 ||
            !c.nonce.endsWith("=") ||
            !c.nonce.substring(0, 43).all { it.isLetterOrDigit() || it == '+' || it == '/' }
        ) {
            throw KiwiRefusalException(
                KiwiRefusalException.MALFORMED,
                "the nonce is not the standard base64 of 32 bytes",
            )
        }
        if (c.prefix.isEmpty() || c.prefix.toByteArray(Charsets.UTF_8).size > 4096) {
            throw KiwiRefusalException(
                KiwiRefusalException.MALFORMED,
                "the prefix length is outside 1..=4096",
            )
        }
        if (c.salt.isEmpty() || c.salt.length > 512) {
            throw KiwiRefusalException(
                KiwiRefusalException.MALFORMED,
                "the salt is oversized or empty",
            )
        }
        when (c.algorithm) {
            "sha256" -> {
                if (c.targetBits < 1 || c.targetBits > SHA_MAX_TARGET_BITS) {
                    throw KiwiRefusalException(
                        KiwiRefusalException.DIFFICULTY_BEYOND_CAP,
                        "target_bits ${c.targetBits} exceeds the sha256 solver cap $SHA_MAX_TARGET_BITS",
                    )
                }
            }
            // SHA-256 only in this module. Argon2id and rsw stay
            // fail-closed here; the JS orchestration surfaces
            // `solver-unavailable`. See docs/NATIVE.md for the
            // per-platform Argon2id status (the SwiftPM iOS package
            // implements Argon2id over the vendored C reference).
            "argon2id" -> throw KiwiRefusalException(
                KiwiRefusalException.UNSUPPORTED_ALGORITHM,
                "argon2id is not implemented in the KiwiCaptchaSolver native module (SHA-256 only)",
            )
            "rsw" -> throw KiwiRefusalException(
                KiwiRefusalException.UNSUPPORTED_ALGORITHM,
                "rsw is not implemented in the KiwiCaptchaSolver native module (SHA-256 only)",
            )
            else -> throw KiwiRefusalException(
                KiwiRefusalException.MALFORMED,
                "the algorithm is not one of sha256, argon2id, rsw",
            )
        }
    }

    // -- primitives (kept dependency-free, like the sibling JVM package) --

    private fun messageDigest(): MessageDigest = try {
        MessageDigest.getInstance("SHA-256")
    } catch (_: Throwable) {
        throw IllegalStateException("the platform JCE does not provide SHA-256")
    }

    /** Leading zero bits, big-endian bit order (the shared difficulty notion). */
    internal fun leadingZeroBits(bytes: ByteArray): Int {
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

    /** Canonical base64 (standard alphabet, padding stripped) with no dependency. */
    private fun decodeBase64(value: String): ByteArray? {
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

    internal fun hex(bytes: ByteArray): String {
        val digits = "0123456789abcdef"
        val out = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xff
            out.append(digits[v ushr 4])
            out.append(digits[v and 0x0f])
        }
        return out.toString()
    }

    private fun solutionJson(counter: Long, durationMs: Long, hashHex: String): String = JSONObject()
        .put("counter", counter)
        .put("durationMs", durationMs)
        .put("hashHex", hashHex)
        .toString()
}
