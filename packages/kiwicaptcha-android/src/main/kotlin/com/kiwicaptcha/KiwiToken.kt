package com.kiwicaptcha

/**
 * A small strict JSON reader for the challenge document and the token
 * wire format, dependency-free so the module carries none. It parses
 * exactly the documented key set and rejects anything else as
 * malformed, mirroring the split the widget makes between fetch and
 * validation.
 */
internal object KiwiJsonReader {

    fun challenge(raw: String): KiwiChallenge {
        val obj = parseObject(raw) ?: throw KiwiSolveError.Malformed("the challenge response is not a JSON object")
        fun str(key: String): String =
            obj[key] as? String ?: throw KiwiSolveError.Malformed("the key $key is missing or not a string")
        fun num(key: String): Long =
            (obj[key] as? Double)?.toLong() ?: throw KiwiSolveError.Malformed("the key $key is missing or not a number")
        return KiwiChallenge(
            nonce = str("nonce"),
            salt = str("salt"),
            algorithm = str("algorithm"),
            mKib = num("mKib"),
            t = num("t"),
            p = num("p"),
            targetBits = num("targetBits"),
            prefix = str("prefix"),
            ttlSecs = (obj["ttlSecs"] as? Double)?.toLong() ?: 0,
            minDurationMs = (obj["minDurationMs"] as? Double)?.toLong() ?: 0,
            executionProgram = obj["execution_program"] as? String,
            rswModulus = obj["rsw_modulus"] as? String,
        )
    }

    /** Parse a flat JSON object of strings and numbers (no nesting). */
    fun parseObject(raw: String): Map<String, Any?>? {
        var i = 0
        fun skipWs() {
            while (i < raw.length && raw[i].isWhitespace()) i++
        }
        fun parseString(): String? {
            if (i >= raw.length || raw[i] != '"') return null
            i++
            val out = StringBuilder()
            while (i < raw.length) {
                val c = raw[i]
                if (c == '"') {
                    i++
                    return out.toString()
                }
                if (c == '\\' && i + 1 < raw.length) {
                    i++
                    when (val esc = raw[i]) {
                        'n' -> out.append('\n')
                        't' -> out.append('\t')
                        'r' -> out.append('\r')
                        'u' -> {
                            if (i + 4 >= raw.length) return null
                            val hex = raw.substring(i + 1, i + 5)
                            // A JSON \\u escape is exactly four hex digits:
                            // anything else is malformed input, not an
                            // exception. The reader answers null and the
                            // caller raises the typed Malformed error.
                            if (!hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
                            out.append(hex.toInt(16).toChar())
                            i += 4
                        }
                        else -> out.append(esc)
                    }
                    i++
                } else {
                    out.append(c)
                    i++
                }
            }
            return null
        }
        skipWs()
        if (i >= raw.length || raw[i] != '{') return null
        i++
        val out = mutableMapOf<String, Any?>()
        skipWs()
        if (i < raw.length && raw[i] == '}') return out
        while (true) {
            skipWs()
            val key = parseString() ?: return null
            skipWs()
            if (i >= raw.length || raw[i] != ':') return null
            i++
            skipWs()
            when {
                i < raw.length && raw[i] == '"' -> out[key] = parseString() ?: return null
                i < raw.length && (raw[i].isDigit() || raw[i] == '-') -> {
                    val start = i
                    if (raw[i] == '-') i++
                    while (i < raw.length && (raw[i].isDigit() || raw[i] == '.' || raw[i] == 'e' || raw[i] == 'E')) i++
                    out[key] = raw.substring(start, i).toDoubleOrNull() ?: return null
                }
                raw.startsWith("true", i) -> {
                    out[key] = true; i += 4
                }
                raw.startsWith("false", i) -> {
                    out[key] = false; i += 5
                }
                raw.startsWith("null", i) -> {
                    out[key] = null; i += 4
                }
                else -> return null
            }
            skipWs()
            if (i < raw.length && raw[i] == ',') {
                i++
                continue
            }
            if (i < raw.length && raw[i] == '}') {
                i++
                return out
            }
            return null
        }
    }
}

/**
 * The wire token: base64(nonce.counter.durationMs.telemetry) with the
 * rsw proof riding as the final 512-hex segment. The bytes are the
 * widget's and the Rust solver's by construction (same grammar).
 */
public object KiwiToken {
    public fun encode(
        nonce: String,
        counter: Long,
        durationMs: Long,
        telemetry: String = "{}",
        rswProof: String? = null,
    ): String {
        val duration = durationMs.coerceIn(0, KiwiLimits.MAX_DURATION_MS)
        var plain = "$nonce.$counter.$duration.$telemetry"
        if (rswProof != null) {
            require(Regex("^[0-9a-f]{512}$").matches(rswProof)) {
                "the rsw proof must be 512 lowercase hex characters"
            }
            plain += ".$rswProof"
        }
        return KiwiBase64.encode(plain.toByteArray(Charsets.UTF_8))
    }

    public fun encode(challenge: KiwiChallenge, solution: KiwiSolution): String =
        encode(
            nonce = challenge.nonce,
            counter = solution.counter,
            durationMs = solution.durationMs,
            telemetry = solution.telemetry,
            rswProof = solution.rswProof,
        )
}
