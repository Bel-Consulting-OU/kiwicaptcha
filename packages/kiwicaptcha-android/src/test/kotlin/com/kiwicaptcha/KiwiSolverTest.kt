package com.kiwicaptcha

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * JVM unit tests for the solver core (run by `gradle testDebugUnitTest`;
 * the Android widget layer needs the instrumented environment, the
 * solver core is pure Kotlin on the JVM).
 */
class KiwiSolverTest {

    private val nonce = "A".repeat(43) + "="

    private fun shaChallenge(mutate: (KiwiChallenge) -> KiwiChallenge = { it }) = mutate(
        KiwiChallenge(
            nonce = nonce,
            salt = "AAECAw==",
            algorithm = "sha256",
            mKib = 0,
            t = 1,
            p = 1,
            targetBits = 8,
            prefix = "kiwi|login|",
        ),
    )

    /** The smallest issued-profile argon challenge: m_kib 8, t 3, p 1. */
    private fun argonChallenge(mutate: (KiwiChallenge) -> KiwiChallenge = { it }) = mutate(
        KiwiChallenge(
            nonce = nonce,
            salt = "AAECAw==",
            algorithm = "argon2id",
            mKib = 8,
            t = 3,
            p = 1,
            targetBits = 4,
            prefix = "kiwi|login|",
        ),
    )

    @Test
    fun sha256SolverFindsTheKnownCounter() {
        val solution = KiwiSolver.solve(shaChallenge())
        assertEquals(45L, solution.counter)
        assertEquals(
            "00f9718e2a0397b3ca8fe75c44499fccee788e243173dadea546bd4e45af6982",
            solution.hashHex,
        )
    }

    @Test
    fun solveSha256DirectEntryPointAndExhaustedBranch() {
        val challenge = shaChallenge()
        val startedAt = System.currentTimeMillis()
        val solution = KiwiSolver.solveSha256(challenge, startedAt, maxHashes = 1_000)
        assertEquals(45L, solution.counter)
        assertEquals(46L, solution.hashes)
        assertEquals(
            "00f9718e2a0397b3ca8fe75c44499fccee788e243173dadea546bd4e45af6982",
            solution.hashHex,
        )

        // The first hit is counter 45; a 10-hash window exhausts before
        // it, and the typed error names the attempted count.
        try {
            KiwiSolver.solveSha256(challenge, startedAt, maxHashes = 10)
            fail("expected the exhausted branch")
        } catch (e: KiwiSolveError.Exhausted) {
            assertEquals(10L, e.attempted)
        }
    }

    @Test
    fun solveRswDirectEntryPointProducesTheWireProof() {
        val challenge = shaChallenge {
            it.copy(
                algorithm = "rsw",
                t = 128,
                targetBits = 1,
                rswModulus = KiwiBase64.encode(composite2048()),
            )
        }
        val solution = KiwiSolver.solveRsw(challenge, System.currentTimeMillis())
        assertEquals(0L, solution.counter)
        assertEquals(128L, solution.hashes)
        assertEquals(512, solution.rswProof?.length)
        assertEquals(solution.rswProof, solution.hashHex)
        assertTrue(solution.rswProof != "0".repeat(512))
        // The direct entry point is deterministic: the same challenge
        // yields the same proof.
        assertEquals(
            solution.rswProof,
            KiwiSolver.solveRsw(challenge, System.currentTimeMillis()).rswProof,
        )
    }

    @Test
    fun argon2idSolverFindsTheKnownCounter() {
        val solution = KiwiSolver.solve(argonChallenge())
        assertEquals(11L, solution.counter)
        assertEquals(12L, solution.hashes)
        assertEquals(
            "0364a814c9f69263470001ffee3058bc9a74436924229444560bb91adcd6fc3d",
            solution.hashHex,
        )
        assertNull(solution.rswProof)
    }

    @Test
    fun argon2idTokenPacksTheCounterIntoTheWireGrammar() {
        val challenge = argonChallenge()
        val solution = KiwiSolver.solve(challenge)
        val token = KiwiToken.encode(challenge, solution)
        val plain = String(java.util.Base64.getDecoder().decode(token), Charsets.UTF_8)
        assertTrue(plain.startsWith("$nonce.11."))
        assertTrue(plain.endsWith(".{}"))
    }

    @Test
    fun solveArgon2idDirectEntryPointAndExhaustedBranch() {
        val challenge = argonChallenge()
        // Counter 11 is the first hit: a 12-hash window covers it, an
        // 11-hash window exhausts one short, and the typed error names
        // the attempted count.
        val solution = KiwiSolver.solveArgon2id(challenge, System.currentTimeMillis(), maxHashes = 12)
        assertEquals(11L, solution.counter)
        assertEquals(12L, solution.hashes)
        try {
            KiwiSolver.solveArgon2id(challenge, System.currentTimeMillis(), maxHashes = 11)
            fail("expected the exhausted branch")
        } catch (e: KiwiSolveError.Exhausted) {
            assertEquals(11L, e.attempted)
        }
    }

    @Test
    fun argon2idValidationEnforcesTheSharedCaps() {
        refusal(argonChallenge { it.copy(targetBits = 11) }) {
            assertTrue(it is KiwiSolveError.DifficultyBeyondCap)
            assertEquals(10L, (it as KiwiSolveError.DifficultyBeyondCap).cap)
        }
        refusal(argonChallenge { it.copy(targetBits = 0) }) {
            assertTrue(it is KiwiSolveError.DifficultyBeyondCap)
        }
        refusal(argonChallenge { it.copy(mKib = 0) }) {
            assertTrue(it is KiwiSolveError.UnsupportedArgon2Params)
        }
        refusal(argonChallenge { it.copy(mKib = 65_537) }) {
            assertTrue(it is KiwiSolveError.UnsupportedArgon2Params)
        }
        refusal(argonChallenge { it.copy(t = 2) }) {
            assertTrue(it is KiwiSolveError.UnsupportedArgon2Params)
        }
        refusal(argonChallenge { it.copy(t = 7) }) {
            assertTrue(it is KiwiSolveError.UnsupportedArgon2Params)
        }
        refusal(argonChallenge { it.copy(p = 2) }) {
            assertTrue(it is KiwiSolveError.UnsupportedArgon2Params)
        }
    }

    @Test
    fun argon2idSolvesAtTheMemoryCeiling() {
        // The top of the issued profile space (a 64 MiB working memory)
        // must derive and search, not refuse: this pins the allocator
        // envelope the official client has to absorb.
        val solution = KiwiSolver.solve(argonChallenge { it.copy(mKib = 65_536, targetBits = 1) })
        assertEquals(0L, solution.counter)
        assertEquals(1L, solution.hashes)
        assertEquals(
            "7cb9eaedf7c47fdb5bd934cd92235547e17e340afc09cc048ce9b0ab72ac17ac",
            solution.hashHex,
        )
    }

    @Test
    fun sha256MatchesTheStandardVectors() {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
            .digest("abc".toByteArray(Charsets.UTF_8))
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            KiwiSolver.hex(digest),
        )
    }

    @Test
    fun leadingZeroBitsFollowsTheSharedNotion() {
        assertEquals(23, KiwiSolver.leadingZeroBits(byteArrayOf(0, 0, 1)))
        assertEquals(0, KiwiSolver.leadingZeroBits(byteArrayOf(0x80.toByte())))
        assertEquals(4, KiwiSolver.leadingZeroBits(byteArrayOf(0x0f)))
    }

    @Test
    fun tokenGrammarIsPinnedByteForByte() {
        val token = KiwiToken.encode(nonce = nonce, counter = 78, durationMs = 1200, telemetry = "{\"t\":1}")
        val plain = String(java.util.Base64.getDecoder().decode(token), Charsets.UTF_8)
        assertEquals("$nonce.78.1200.{\"t\":1}", plain)
    }

    @Test
    fun tokenClampsDurationToTheWireCeiling() {
        val token = KiwiToken.encode(nonce = nonce, counter = 1, durationMs = 9_999_999)
        val plain = String(java.util.Base64.getDecoder().decode(token), Charsets.UTF_8)
        assertTrue(plain.contains(".1.3600000."))
    }

    @Test
    fun rswProofMatchesTheExternalVector() {
        val n = composite2048()
        val challenge = shaChallenge {
            it.copy(
                algorithm = "rsw",
                t = 10_000,
                targetBits = 1,
                rswModulus = KiwiBase64.encode(n),
            )
        }
        val solution = KiwiSolver.solve(challenge)
        assertEquals(512, solution.rswProof?.length)
        assertEquals(
            "218193a822ff892a0f822bebecdc79e43abee9974bbf32d1e3aa93ad8b746adca73f30c87f670229c9f93bd2468e04a4462c539bbb560d57da744249f2cc4f0ddfd1c91a0cdcae0272a067bdac1c0b3857bc8d2a85d388b397aacadcae43590ec5a79a4974ca9e658224d325d4e36757c1a6f1552bb7bbc6802f449caa64b72f383a8ed64941cac8d2d1ed88f9f397559bb44cb874d963d0b3fb1825b0673c2db1793e3ce886161cb644b8ec62b0b167e5bb071db35990d6bf51c79e2762f73a0bf0b632d634481a1d18d421d61b222a95d195818b5f3203ac0937ec61b9ea2cb959a9047ebd905aa39f73fee1a9bde0f8a84707b917a463a10f15394723f414",
            solution.rswProof,
        )
    }

    @Test
    fun validationRefusesOutOfContractChallenges() {
        refusal(shaChallenge { it.copy(executionProgram = "YQ==") }) {
            assertTrue(it is KiwiSolveError.ExecutionUnsupported)
        }
        refusal(shaChallenge { it.copy(algorithm = "argon2id") }) {
            assertTrue(it is KiwiSolveError.UnsupportedArgon2Params)
        }
        refusal(shaChallenge { it.copy(nonce = "short") }) {
            assertTrue(it is KiwiSolveError.Malformed)
        }
        refusal(shaChallenge { it.copy(targetBits = 21) }) {
            assertTrue(it is KiwiSolveError.DifficultyBeyondCap)
        }
        refusal(shaChallenge { it.copy(salt = "not b64") }) {
            assertTrue(it is KiwiSolveError.Malformed)
        }
        refusal(
            shaChallenge {
                it.copy(algorithm = "rsw", t = 10_000, rswModulus = KiwiBase64.encode(even2048()))
            },
        ) {
            assertTrue(it is KiwiSolveError.UnsupportedRswParams)
        }
    }

    @Test
    fun challengeJsonParsesTheDocumentedKeySet() {
        val raw = """
            {"nonce":"$nonce","salt":"AAECAw==","algorithm":"sha256","mKib":0,
             "t":1,"p":1,"targetBits":8,"prefix":"kiwi|login|","ttlSecs":120,
             "minDurationMs":50,"rsw_modulus":null}
        """.trimIndent()
        val challenge = KiwiChallenge.fromJson(raw)
        assertEquals("kiwi|login|", challenge.prefix)
        assertEquals(120L, challenge.ttlSecs)
        assertNull(challenge.rswModulus)
    }

    @Test
    fun challengeJsonRejectsBrokenUnicodeEscapesAsMalformed() {
        // A non-hex \u escape is malformed input and must raise the typed
        // Malformed error, never escape as a raw parse exception.
        val broken = """
            {"nonce":"$nonce","salt":"AAECAw==","algorithm":"sha256","mKib":0,
             "t":1,"p":1,"targetBits":8,"prefix":"kiwi|login|\uZZZZ","ttlSecs":120,
             "minDurationMs":50}
        """.trimIndent()
        try {
            KiwiChallenge.fromJson(broken)
            fail("expected a malformed refusal")
        } catch (e: KiwiSolveError.Malformed) {
            // expected: typed refusal
        }
        // A valid four-hex-digit escape still parses.
        val ok = """
            {"nonce":"$nonce","salt":"AAECAw==","algorithm":"sha256","mKib":0,
             "t":1,"p":1,"targetBits":8,"prefix":"a\u0042c","ttlSecs":120,
             "minDurationMs":50}
        """.trimIndent()
        assertEquals("aBc", KiwiChallenge.fromJson(ok).prefix)
    }

    @Test
    fun siteverifyBodyCarriesSecretResponseAndOptionalRemoteip() {
        assertEquals(
            "{\"secret\":\"s\",\"response\":\"tok\",\"remoteip\":\"203.0.113.9\"}",
            KiwiClient.siteverifyBody("s", "tok", "203.0.113.9"),
        )
        assertEquals(
            "{\"secret\":\"s\",\"response\":\"tok\"}",
            KiwiClient.siteverifyBody("s", "tok"),
        )
    }

    @Test
    fun base64RoundTripsAndRejectsBrokenInput() {
        assertEquals("Zm9vYmFy", KiwiBase64.encode("foobar".toByteArray()))
        assertTrue(KiwiBase64.decode("Zm9vYmFy").contentEquals("foobar".toByteArray()))
        assertNull(KiwiBase64.decode("abc"))
    }

    private fun refusal(challenge: KiwiChallenge, check: (KiwiSolveError) -> Unit) {
        try {
            KiwiSolver.validate(challenge)
            fail("expected a refusal")
        } catch (e: KiwiSolveError) {
            check(e)
        }
    }

    private fun refusalSafe(): Unit = Unit

    /** (2^1023 + 1)(2^1023 + 3) * 3: a canonical 2048-bit odd composite. */
    private fun composite2048(): ByteArray {
        val bytes = ByteArray(256)
        fun setBit(bit: Int) {
            bytes[255 - bit / 8] = (bytes[255 - bit / 8].toInt() or (1 shl (bit % 8))).toByte()
        }
        setBit(2047); setBit(2046)
        setBit(1026); setBit(1025)
        bytes[255] = (bytes[255].toInt() or 9).toByte()
        return bytes
    }

    private fun even2048(): ByteArray = composite2048().also { it[255] = (it[255].toInt() and 0xfe).toByte() }
}
