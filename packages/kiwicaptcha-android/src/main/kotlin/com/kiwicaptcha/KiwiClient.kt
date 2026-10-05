package com.kiwicaptcha

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/**
 * The challenge client: a POST to the challenge endpoint and the
 * provider-shaped siteverify body builder. Verification itself is a
 * server-to-server call; the app submits the token with its own
 * authenticated request and the backend runs siteverify.
 */
public class KiwiClient(
    public val endpoint: String,
    public val sitekey: String? = null,
    public val connectTimeoutMs: Int = 10_000,
    public val readTimeoutMs: Int = 15_000,
) {
    public class BadStatus(val status: Int) : IOException("the challenge endpoint answered $status")

    /**
     * POST the challenge request on a background thread and parse the
     * document. Call from a worker dispatcher; the method blocks.
     */
    public fun fetchChallenge(scope: String, algorithm: String? = null, requestBinding: String? = null): KiwiChallenge {
        val body = buildString {
            append("{\"scope\":").append(KiwiJson.quote(scope))
            if (algorithm != null) append(",\"algorithm\":").append(KiwiJson.quote(algorithm))
            if (sitekey != null) append(",\"sitekey\":").append(KiwiJson.quote(sitekey))
            if (requestBinding != null) append(",\"request_binding\":").append(KiwiJson.quote(requestBinding))
            append("}")
        }
        val connection = URL(endpoint).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.connectTimeout = connectTimeoutMs
            connection.readTimeout = readTimeoutMs
            connection.doOutput = true
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Content-Type", "application/json")
            connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            val status = connection.responseCode
            if (status != 200) throw BadStatus(status)
            val raw = connection.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
            return KiwiChallenge.fromJson(raw)
        } finally {
            connection.disconnect()
        }
    }

    public companion object {
        /** The provider-shaped siteverify request body. */
        public fun siteverifyBody(secret: String, response: String, remoteip: String? = null): String {
            val out = StringBuilder()
            out.append("{\"secret\":").append(KiwiJson.quote(secret))
            out.append(",\"response\":").append(KiwiJson.quote(response))
            if (remoteip != null) out.append(",\"remoteip\":").append(KiwiJson.quote(remoteip))
            out.append("}")
            return out.toString()
        }
    }
}

internal object KiwiJson {
    public fun quote(value: String): String {
        val out = StringBuilder("\"")
        for (c in value) {
            when (c) {
                '"' -> out.append("\\\"")
                '\\' -> out.append("\\\\")
                '\n' -> out.append("\\n")
                '\r' -> out.append("\\r")
                '\t' -> out.append("\\t")
                else -> if (c < ' ') out.append("\\u%04x".format(c.code)) else out.append(c)
            }
        }
        out.append("\"")
        return out.toString()
    }
}
