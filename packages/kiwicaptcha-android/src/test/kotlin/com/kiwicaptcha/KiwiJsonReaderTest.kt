package com.kiwicaptcha

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test

/**
 * The hostile corpus for the challenge JSON reader. Each row names one
 * malformed class and must draw the typed Malformed refusal; the valid
 * document is the control.
 */
class KiwiJsonReaderTest {

    private val nonce = "A".repeat(43) + "="

    private fun document(extra: String = ""): String {
        val body = "\"nonce\":\"$nonce\",\"salt\":\"AAECAw==\",\"algorithm\":\"sha256\"," +
            "\"mKib\":0,\"t\":1,\"p\":1,\"targetBits\":8,\"prefix\":\"kiwi|login|\"," +
            "\"ttlSecs\":120,\"minDurationMs\":50"
        return if (extra.isEmpty()) "{$body}" else "{$body,$extra}"
    }

    private fun replacing(field: String, replacement: String): String =
        document().replace(field, replacement)

    /** Interpolates a prefix spelling without interpreting Kotlin escapes. */
    private fun withPrefixRaw(prefixJson: String): String =
        """{"nonce":"$nonce","salt":"AAECAw==","algorithm":"sha256","mKib":0,"t":1,"p":1,"targetBits":8,"prefix":"$prefixJson","ttlSecs":120,"minDurationMs":50}"""

    private data class HostileCase(val name: String, val raw: String)

    private fun hostileCorpus(): List<HostileCase> = listOf(
        HostileCase("trailing garbage", document() + "x"),
        HostileCase("trailing NUL", document() + "\u0000"),
        HostileCase("trailing non-json whitespace", document() + "\u00a0"),
        HostileCase("duplicate top-level key", document("\"t\":2")),
        HostileCase("duplicate null top-level key", document("\"t\":null")),
        HostileCase("duplicate nested key", document("\"meta\":{\"a\":1,\"a\":2}")),
        HostileCase("duplicate nested array object key", document("\"meta\":[{\"a\":1,\"a\":2}]")),
        HostileCase("duplicate escaped key", document("\"meta\":{\"a\":1,\"\\u0061\":2}")),
        HostileCase("unknown escape", withPrefixRaw("""a\qb""")),
        HostileCase("lone high surrogate escape", withPrefixRaw("""\ud800""")),
        HostileCase("lone low surrogate escape", withPrefixRaw("""\udc00""")),
        HostileCase("high surrogate escape before a plain character", withPrefixRaw("""\ud83dX""")),
        HostileCase("lone raw surrogate", withPrefixRaw("a\uD800b")),
        HostileCase("raw control character", withPrefixRaw("a\u0001b")),
        HostileCase("raw newline in a string", withPrefixRaw("a\nb")),
        HostileCase("integer field written as a float", replacing("\"mKib\":0", "\"mKib\":8.9")),
        HostileCase("integer field written as a fraction", replacing("\"t\":1", "\"t\":1.0")),
        HostileCase("integer field written as an exponent", replacing("\"p\":1", "\"p\":1e0")),
        HostileCase(
            "oversized integer",
            replacing("\"mKib\":0", "\"mKib\":999999999999999999999999"),
        ),
        HostileCase("oversized exponent", replacing("\"mKib\":0", "\"mKib\":1e400")),
        HostileCase("wrong type for a required string", replacing("\"targetBits\":8", "\"targetBits\":\"8\"")),
        HostileCase("wrong type for a required number", replacing("\"prefix\":\"kiwi|login|\"", "\"prefix\":7")),
        HostileCase("wrong type for an optional number", replacing("\"ttlSecs\":120", "\"ttlSecs\":\"fast\"")),
        HostileCase("wrong type for an optional string", document("\"rsw_modulus\":7")),
        HostileCase(
            "nesting beyond the depth ceiling",
            document("\"meta\":" + "{\"a\":".repeat(33) + "1" + "}".repeat(33)),
        ),
        HostileCase("empty document", ""),
        HostileCase("whitespace-only document", "  \n\t\r "),
        HostileCase("truncated object", document().dropLast(1)),
        HostileCase("truncated mid-key", document().substring(0, 20)),
        HostileCase("root array", "[]"),
        HostileCase("root string", "\"x\""),
        HostileCase("trailing comma", """{"nonce":"$nonce",}"""),
        HostileCase("missing colon", """{"nonce" "$nonce"}"""),
        HostileCase("leading zero number", replacing("\"mKib\":0", "\"mKib\":01")),
        HostileCase("bare fraction", replacing("\"mKib\":0", "\"mKib\":1.")),
        HostileCase("plus sign number", replacing("\"mKib\":0", "\"mKib\":+1")),
        HostileCase("bare minus", replacing("\"mKib\":0", "\"mKib\":-")),
    )

    @Test
    fun everyHostileRowIsRefusedAsMalformed() {
        for (case in hostileCorpus()) {
            val thrown = try {
                KiwiChallenge.fromJson(case.raw)
                null
            } catch (e: Exception) {
                e
            }
            when (thrown) {
                null -> fail("${case.name}: the reader accepted a malformed document")
                is KiwiSolveError.Malformed -> Unit
                else -> fail(
                    "${case.name}: expected KiwiSolveError.Malformed, got " +
                        "${thrown.javaClass.name}: ${thrown.message}",
                )
            }
        }
    }

    @Test
    fun theValidDocumentIsTheControl() {
        val challenge = KiwiChallenge.fromJson(document())
        assertEquals(nonce, challenge.nonce)
        assertEquals(0L, challenge.mKib)
        assertEquals(1L, challenge.t)
        assertEquals(1L, challenge.p)
        assertEquals(8L, challenge.targetBits)
        assertEquals("kiwi|login|", challenge.prefix)
        assertEquals(120L, challenge.ttlSecs)
        assertEquals(50L, challenge.minDurationMs)
        assertNull(challenge.executionProgram)
        assertNull(challenge.rswModulus)
    }

    @Test
    fun trailingJsonWhitespaceIsAccepted() {
        assertEquals(nonce, KiwiChallenge.fromJson(document() + " \t\r\n").nonce)
    }

    @Test
    fun legalEscapesAndSurrogatePairsDecode() {
        val raw = withPrefixRaw(
            """quote\" slash\/ back\\ bs\b ff\f nl\n cr\r tab\t uni\u0041 ctl\u0001 pair\ud83d\ude00""",
        )
        assertEquals(
            "quote\" slash/ back\\ bs\b ff\u000C nl\n cr\r tab\t uniA ctl\u0001 pair\uD83D\uDE00",
            KiwiChallenge.fromJson(raw).prefix,
        )
    }

    @Test
    fun aRawSupplementaryCharacterIsAccepted() {
        assertEquals("\uD83D\uDE00", KiwiChallenge.fromJson(withPrefixRaw("\uD83D\uDE00")).prefix)
    }

    @Test
    fun integerFieldsKeepTheirExactLongValue() {
        val raw = replacing("\"mKib\":0", "\"mKib\":9007199254740993")
        assertEquals(9007199254740993L, KiwiChallenge.fromJson(raw).mKib)
    }
}
