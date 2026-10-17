package com.kiwicaptcha

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets

/**
 * JVM unit tests for the challenge client, against a real local HTTP
 * server: the request shape, the success path, the non-2xx refusal, the
 * closed malformed error and the siteverify body.
 *
 * The server is a tiny HTTP/1.1 responder over a loopback
 * [ServerSocket] — the Android unit-test compilation does not expose
 * com.sun.net.httpserver, and a test dependency (MockWebServer) would be
 * heavier than the protocol surface these tests need.
 */
class KiwiClientTest {

    private val nonce = "A".repeat(43) + "="
    private lateinit var server: TestHttpServer
    private var status = 200
    private var body = ""

    @Volatile private var lastMethod: String? = null
    @Volatile private var lastPath: String? = null
    @Volatile private var lastAccept: String? = null
    @Volatile private var lastContentType: String? = null
    @Volatile private var lastBody: String? = null

    private fun challengeJson() = """
        {"nonce":"$nonce","salt":"AAECAw==","algorithm":"sha256","mKib":0,
         "t":1,"p":1,"targetBits":8,"prefix":"kiwi|login|","ttlSecs":120,
         "minDurationMs":50}
    """.trimIndent()

    @Before
    fun startServer() {
        body = challengeJson()
        server = TestHttpServer { request ->
            lastMethod = request.method
            lastPath = request.path
            lastAccept = request.headers["accept"]
            lastContentType = request.headers["content-type"]
            lastBody = request.body
            TestHttpServer.Response(status, body)
        }
    }

    @After
    fun stopServer() {
        server.close()
    }

    private fun client() = KiwiClient(
        endpoint = server.url("/challenge"),
        sitekey = "pk-android",
        connectTimeoutMs = 5_000,
        readTimeoutMs = 5_000,
    )

    @Test
    fun fetchChallengePostsTheDocumentAndParsesTheAnswer() {
        val challenge = client().fetchChallenge(
            scope = "login",
            algorithm = "sha256",
            requestBinding = "rb-1",
        )
        assertEquals("kiwi|login|", challenge.prefix)
        assertEquals(nonce, challenge.nonce)
        assertEquals(120L, challenge.ttlSecs)
        assertEquals(50L, challenge.minDurationMs)

        assertEquals("POST", lastMethod)
        assertEquals("/challenge", lastPath)
        assertEquals("application/json", lastAccept)
        assertEquals("application/json", lastContentType)
        val sent = KiwiJsonReader.parseObject(lastBody ?: "")!!
        assertEquals("login", sent["scope"])
        assertEquals("sha256", sent["algorithm"])
        assertEquals("pk-android", sent["sitekey"])
        assertEquals("rb-1", sent["request_binding"])
    }

    @Test
    fun fetchChallengeRefusesANon200Answer() {
        status = 503
        try {
            client().fetchChallenge("login")
            fail("a 503 must be refused")
        } catch (e: KiwiClient.BadStatus) {
            assertEquals(503, e.status)
        }
    }

    @Test
    fun fetchChallengeRefusesAMalformedDocumentClosed() {
        body = """{"hello":1}"""
        try {
            client().fetchChallenge("login")
            fail("a non-challenge document must be refused")
        } catch (e: KiwiSolveError.Malformed) {
            assertTrue(e.message?.contains("nonce") == true)
        }
        // A truncated JSON document is the same closed refusal, never a
        // raw parser exception leaking out of the client.
        body = """{"nonce":"""
        try {
            client().fetchChallenge("login")
            fail("truncated JSON must be refused")
        } catch (e: KiwiSolveError.Malformed) {
            assertTrue(e.message?.isNotEmpty() == true)
        }
    }

    @Test
    fun siteverifyBodyIsTheProviderShape() {
        assertEquals(
            """{"secret":"s","response":"tok","remoteip":"203.0.113.9"}""",
            KiwiClient.siteverifyBody("s", "tok", "203.0.113.9"),
        )
        assertEquals(
            """{"secret":"s","response":"tok"}""",
            KiwiClient.siteverifyBody("s", "tok"),
        )
    }
}

/**
 * One-request-at-a-time HTTP/1.1 responder on a loopback port. It
 * answers with `Connection: close`, so HttpURLConnection never reuses a
 * socket and the parser stays trivial.
 */
private class TestHttpServer(
    private val handler: (Request) -> Response,
) : AutoCloseable {

    data class Request(
        val method: String,
        val path: String,
        val headers: Map<String, String>,
        val body: String,
    )

    data class Response(val status: Int, val body: String)

    private val socket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
    private val thread = Thread { acceptLoop() }.apply {
        isDaemon = true
        name = "kiwi-test-http"
        start()
    }

    fun url(path: String): String = "http://127.0.0.1:${socket.localPort}$path"

    private fun acceptLoop() {
        while (!socket.isClosed) {
            try {
                socket.accept().use { connection ->
                    connection.soTimeout = 5_000
                    val input = connection.getInputStream().buffered()
                    val requestLine = readLine(input) ?: return@use
                    val parts = requestLine.split(" ")
                    val headers = LinkedHashMap<String, String>()
                    while (true) {
                        val line = readLine(input) ?: break
                        if (line.isEmpty()) break
                        val colon = line.indexOf(':')
                        if (colon > 0) {
                            headers[line.substring(0, colon).trim().lowercase()] =
                                line.substring(colon + 1).trim()
                        }
                    }
                    val length = headers["content-length"]?.toIntOrNull() ?: 0
                    val bytes = ByteArray(length)
                    var read = 0
                    while (read < length) {
                        val n = input.read(bytes, read, length - read)
                        if (n < 0) break
                        read += n
                    }
                    val request = Request(
                        method = parts.getOrNull(0) ?: "",
                        path = parts.getOrNull(1) ?: "",
                        headers = headers,
                        body = String(bytes, 0, read, StandardCharsets.UTF_8),
                    )
                    val response = try {
                        handler(request)
                    } catch (t: Throwable) {
                        Response(500, "handler failure")
                    }
                    val payload = response.body.toByteArray(StandardCharsets.UTF_8)
                    val out = connection.getOutputStream()
                    out.write(
                        (
                            "HTTP/1.1 ${response.status} ${reason(response.status)}\r\n" +
                                "Content-Type: application/json\r\n" +
                                "Content-Length: ${payload.size}\r\n" +
                                "Connection: close\r\n\r\n"
                            ).toByteArray(StandardCharsets.US_ASCII),
                    )
                    out.write(payload)
                    out.flush()
                }
            } catch (_: IOException) {
                // The socket was closed by close(); the loop exits.
            }
        }
    }

    private fun readLine(input: InputStream): String? {
        val line = StringBuilder()
        while (true) {
            val b = input.read()
            if (b < 0) return if (line.isEmpty()) null else line.toString()
            if (b == '\n'.code) break
            if (b != '\r'.code) line.append(b.toChar())
        }
        return line.toString()
    }

    private fun reason(status: Int): String = when (status) {
        200 -> "OK"
        503 -> "Service Unavailable"
        else -> "Error"
    }

    override fun close() {
        socket.close()
        thread.interrupt()
    }
}
