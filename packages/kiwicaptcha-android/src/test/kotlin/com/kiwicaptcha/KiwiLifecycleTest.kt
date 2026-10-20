package com.kiwicaptcha

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

/**
 * The Interactive-Client Lifecycle v1 delivery gate, tested against
 * EVERY scenario in the shared vector file
 * protocol/interactive-client-v1/lifecycle-vectors.json (read from the
 * repo via a path resolved upward from the module, so the JVM test
 * stays a pure unit test).
 */
class KiwiLifecycleTest {

    /** Walk upward from the working directory (the module dir under
     * Gradle) until the repo-rooted protocol file appears. */
    private fun vectorsPath(): Path {
        var dir: Path? = Paths.get("").toAbsolutePath()
        while (dir != null) {
            val candidate = dir.resolve("protocol").resolve("interactive-client-v1").resolve("lifecycle-vectors.json")
            if (Files.exists(candidate)) return candidate
            dir = dir.parent
        }
        error("lifecycle-vectors.json not found above ${Paths.get("").toAbsolutePath()}")
    }

    /** The module's strict dependency-free reader parses one root
     * object, so the shared array rides as a value. */
    @Suppress("UNCHECKED_CAST")
    private fun readVectors(): List<Pair<String, Map<String, Any?>>> {
        val raw = String(Files.readAllBytes(vectorsPath()), Charsets.UTF_8)
        val doc = KiwiJsonReader.parseObject("""{"vectors":$raw}""")
            ?: error("lifecycle-vectors.json is not valid JSON")
        val vectors = doc["vectors"] as? List<*>
        assertTrue("the vector file must hold an array", vectors != null)
        return vectors!!
            .filterIsInstance<Map<String, Any?>>()
            .map { it["name"] as String to it }
    }

    @Test
    fun deadlineFormulasMatchTheContract() {
        // parse time + ttl*1000 - the fixed 1 s safety margin
        assertEquals(1_119_000L, KiwiLifecycle.expiresAtMs(1_000_000L, 120L))
        assertEquals(1_029_000L, KiwiLifecycle.expiresAtMs(1_000_000L, 30L))
        // ttl 0 is no expiry at all
        assertEquals(Long.MAX_VALUE, KiwiLifecycle.expiresAtMs(1_000_000L, 0L))
        // parse time + min duration
        assertEquals(1_005_000L, KiwiLifecycle.minSubmitAtMs(1_000_000L, 5_000L))
        assertEquals(1_000_000L, KiwiLifecycle.minSubmitAtMs(1_000_000L, 0L))
    }

    @Test
    fun decisionMatchesEverySharedVector() {
        val vectors = readVectors()
        assertTrue(
            "expected at least 10 shared vectors, found ${vectors.size}",
            vectors.size >= 10,
        )
        for ((name, v) in vectors) {
            val decision = KiwiLifecycle.deliveryDecision(
                receivedAtMs = v["receivedAtMs"] as Long,
                ttlSecs = v["ttlSecs"] as Long,
                minDurationMs = v["minDurationMs"] as Long,
                solveFinishedAtMs = v["solveFinishedAtMs"] as Long,
                nowMs = v["nowMs"] as Long,
                cancelled = v["cancelled"] as Boolean,
            )
            val expect = v["expect"] as Map<String, Any?>
            assertEquals("vector '$name' deliver", expect["deliver"] as Boolean, decision.deliver)
            assertEquals("vector '$name' deliverAtMs", expect["deliverAtMs"] as Long, decision.deliverAtMs)
            assertEquals("vector '$name' reason", expect["reason"] as String, decision.reason)
        }
    }

    @Test
    fun contractSignatureWithoutCancelledInputMatchesNonCancelledVectors() {
        for ((name, v) in readVectors()) {
            if (v["cancelled"] as Boolean) continue
            val decision = KiwiLifecycle.deliveryDecision(
                receivedAtMs = v["receivedAtMs"] as Long,
                ttlSecs = v["ttlSecs"] as Long,
                minDurationMs = v["minDurationMs"] as Long,
                solveFinishedAtMs = v["solveFinishedAtMs"] as Long,
                nowMs = v["nowMs"] as Long,
            )
            val expect = v["expect"] as Map<String, Any?>
            assertEquals("vector '$name' deliver", expect["deliver"] as Boolean, decision.deliver)
            assertEquals("vector '$name' deliverAtMs", expect["deliverAtMs"] as Long, decision.deliverAtMs)
            assertEquals("vector '$name' reason", expect["reason"] as String, decision.reason)
        }
    }
}
