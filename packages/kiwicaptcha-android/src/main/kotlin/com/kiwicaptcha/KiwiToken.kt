package com.kiwicaptcha

/**
 * A small strict JSON reader for the challenge document, dependency-free
 * so the module carries none. It accepts one root object and refuses
 * malformed input with the typed Malformed error. The grammar is the
 * strict JSON grammar: no trailing bytes, no duplicate keys at any
 * depth, only the legal escapes, no raw control characters, and integer
 * fields parsed from an integer literal instead of a float.
 */
internal object KiwiJsonReader {

    /** The shared nesting ceiling, matching the telemetry register value. */
    private const val MAX_DEPTH = 32

    private class InvalidDocument : Exception() {
        override fun fillInStackTrace(): Throwable = this
    }

    fun challenge(raw: String): KiwiChallenge {
        val obj = parseObject(raw) ?: throw KiwiSolveError.Malformed("the challenge response is not a JSON object")
        fun str(key: String): String =
            obj[key] as? String ?: throw KiwiSolveError.Malformed("the key $key is missing or not a string")
        fun num(key: String): Long =
            obj[key] as? Long ?: throw KiwiSolveError.Malformed("the key $key is missing or not an integer")
        fun optNum(key: String): Long =
            when (val value = obj[key]) {
                null -> 0L
                is Long -> value
                else -> throw KiwiSolveError.Malformed("the key $key is not an integer")
            }
        fun optStr(key: String): String? =
            when (val value = obj[key]) {
                null -> null
                is String -> value
                else -> throw KiwiSolveError.Malformed("the key $key is not a string")
            }
        return KiwiChallenge(
            nonce = str("nonce"),
            salt = str("salt"),
            algorithm = str("algorithm"),
            mKib = num("mKib"),
            t = num("t"),
            p = num("p"),
            targetBits = num("targetBits"),
            prefix = str("prefix"),
            ttlSecs = optNum("ttlSecs"),
            minDurationMs = optNum("minDurationMs"),
            executionProgram = optStr("execution_program"),
            rswModulus = optStr("rsw_modulus"),
        )
    }

    /**
     * Parse one JSON object with the strict grammar. Returns null for any
     * malformed document. That includes trailing non-whitespace, a
     * duplicate key at any depth, an unknown escape, an unescaped control
     * character or an integer field written with a fraction or exponent.
     */
    fun parseObject(raw: String): Map<String, Any?>? =
        try {
            val parser = Parser(raw)
            parser.parseDocument()
        } catch (_: InvalidDocument) {
            null
        }

    private class Parser(private val raw: String) {
        private var i = 0

        fun parseDocument(): Map<String, Any?>? {
            skipWs()
            if (i >= raw.length || raw[i] != '{') return null
            val value = parseObjectBody(0)
            skipWs()
            return if (i == raw.length) value else null
        }

        private fun skipWs() {
            while (i < raw.length) {
                val c = raw[i]
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++ else break
            }
        }

        private fun fail(): Nothing = throw InvalidDocument()

        private fun peek(): Char {
            if (i >= raw.length) fail()
            return raw[i]
        }

        private fun expect(c: Char) {
            if (i >= raw.length || raw[i] != c) fail()
            i++
        }

        private fun parseValue(depth: Int): Any? =
            when (peek()) {
                '{' -> parseObjectBody(depth)
                '[' -> parseArray(depth)
                '"' -> parseString()
                't' -> {
                    expectWord("true")
                    true
                }
                'f' -> {
                    expectWord("false")
                    false
                }
                'n' -> {
                    expectWord("null")
                    null
                }
                else -> parseNumber()
            }

        private fun parseObjectBody(depth: Int): MutableMap<String, Any?> {
            if (depth >= MAX_DEPTH) fail()
            expect('{')
            val out = LinkedHashMap<String, Any?>()
            skipWs()
            if (i < raw.length && raw[i] == '}') {
                i++
                return out
            }
            while (true) {
                skipWs()
                val key = parseString()
                if (out.containsKey(key)) fail()
                skipWs()
                expect(':')
                skipWs()
                out[key] = parseValue(depth + 1)
                skipWs()
                when (peek()) {
                    ',' -> i++
                    '}' -> {
                        i++
                        return out
                    }
                    else -> fail()
                }
            }
        }

        private fun parseArray(depth: Int): MutableList<Any?> {
            if (depth >= MAX_DEPTH) fail()
            expect('[')
            val out = ArrayList<Any?>()
            skipWs()
            if (i < raw.length && raw[i] == ']') {
                i++
                return out
            }
            while (true) {
                skipWs()
                out.add(parseValue(depth + 1))
                skipWs()
                when (peek()) {
                    ',' -> i++
                    ']' -> {
                        i++
                        return out
                    }
                    else -> fail()
                }
            }
        }

        private fun parseString(): String {
            expect('"')
            val out = StringBuilder()
            while (true) {
                val c = peek()
                when {
                    c == '"' -> {
                        i++
                        return out.toString()
                    }
                    c == '\\' -> {
                        i++
                        when (peek()) {
                            '"' -> {
                                out.append('"')
                                i++
                            }
                            '\\' -> {
                                out.append('\\')
                                i++
                            }
                            '/' -> {
                                out.append('/')
                                i++
                            }
                            'b' -> {
                                out.append('\b')
                                i++
                            }
                            'f' -> {
                                out.append('\u000C')
                                i++
                            }
                            'n' -> {
                                out.append('\n')
                                i++
                            }
                            'r' -> {
                                out.append('\r')
                                i++
                            }
                            't' -> {
                                out.append('\t')
                                i++
                            }
                            'u' -> {
                                i++
                                val unit = parseHex4()
                                when {
                                    unit in 0xD800..0xDBFF -> {
                                        if (i + 1 >= raw.length || raw[i] != '\\' || raw[i + 1] != 'u') fail()
                                        i += 2
                                        val low = parseHex4()
                                        if (low !in 0xDC00..0xDFFF) fail()
                                        out.append(unit.toChar()).append(low.toChar())
                                    }
                                    unit in 0xDC00..0xDFFF -> fail()
                                    else -> out.append(unit.toChar())
                                }
                            }
                            else -> fail()
                        }
                    }
                    c.code < 0x20 -> fail()
                    Character.isHighSurrogate(c) -> {
                        if (i + 1 >= raw.length || !Character.isLowSurrogate(raw[i + 1])) fail()
                        out.append(c).append(raw[i + 1])
                        i += 2
                    }
                    Character.isLowSurrogate(c) -> fail()
                    else -> {
                        out.append(c)
                        i++
                    }
                }
            }
        }

        private fun parseHex4(): Int {
            if (i + 4 > raw.length) fail()
            var value = 0
            repeat(4) {
                val c = raw[i]
                val digit = when (c) {
                    in '0'..'9' -> c - '0'
                    in 'a'..'f' -> c - 'a' + 10
                    in 'A'..'F' -> c - 'A' + 10
                    else -> fail()
                }
                value = value * 16 + digit
                i++
            }
            return value
        }

        private fun parseNumber(): Any {
            val start = i
            if (peek() == '-') i++
            if (i >= raw.length || raw[i] !in '0'..'9') fail()
            if (raw[i] == '0') {
                i++
                if (i < raw.length && raw[i] in '0'..'9') fail()
            } else {
                while (i < raw.length && raw[i] in '0'..'9') i++
            }
            var integer = true
            if (i < raw.length && raw[i] == '.') {
                integer = false
                i++
                if (i >= raw.length || raw[i] !in '0'..'9') fail()
                while (i < raw.length && raw[i] in '0'..'9') i++
            }
            if (i < raw.length && (raw[i] == 'e' || raw[i] == 'E')) {
                integer = false
                i++
                if (i < raw.length && (raw[i] == '+' || raw[i] == '-')) i++
                if (i >= raw.length || raw[i] !in '0'..'9') fail()
                while (i < raw.length && raw[i] in '0'..'9') i++
            }
            val text = raw.substring(start, i)
            return if (integer) {
                text.toLongOrNull() ?: fail()
            } else {
                val value = text.toDoubleOrNull() ?: fail()
                if (!value.isFinite()) fail()
                value
            }
        }

        private fun expectWord(word: String) {
            if (i + word.length > raw.length || !raw.startsWith(word, i)) fail()
            i += word.length
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
