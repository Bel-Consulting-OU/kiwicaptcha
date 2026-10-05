package com.kiwicaptcha;

import java.util.List;

/**
 * The narrow command surface the Redis store adapter binds to, so
 * tests and deployments can substitute any client with the same five
 * verbs. The shipped RESP2 client implements it over the JDK socket
 * streams.
 */
public interface RedisClient {
    /**
     * Returns the string value as a one-element array, or null when
     * the key is absent.
     */
    String[] get(String key);

    /** Writes the value with a millisecond lifetime. */
    void setWithTtl(String key, String value, long ttlMillis);

    /** Returns the remaining lifetime in milliseconds. */
    long pttl(String key);

    /** Removes one key and reports whether it existed. */
    boolean del(String key);

    /** Runs one script. */
    Object eval(String script, List<String> keys, List<String> args);

    /** Runs a cached script. */
    Object evalSha(String sha, List<String> keys, List<String> args);

    /** Caches one script and returns its hex digest. */
    String scriptLoad(String script);

    /** Sends one raw command and decodes the reply. */
    Object command(String... args);

    /** Probes the server. */
    void ping();

    /** Releases the connection. */
    void close();
}
