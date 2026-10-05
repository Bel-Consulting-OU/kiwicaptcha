package com.kiwicaptcha;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * A minimal Redis client over the Redis wire protocol, implemented on
 * the JDK socket streams only. The client speaks RESP2, the protocol
 * the php and Python adapters run over, and implements the narrow
 * command surface the store adapter needs: get, set with a lifetime,
 * pttl, del, and script execution through eval, evalsha and script
 * load. One connection, serialized with a monitor; the adapter issues
 * one request at a time.
 */
public final class RespClient implements RedisClient {
    private Socket socket;
    private BufferedInputStream reader;

    /** A negative server reply. */
    public static final class RedisException extends RuntimeException {
        public final String message;

        RedisException(String message) {
            super("kiwicaptcha: redis error: " + message);
            this.message = message;
        }

        /** Reports the noscript miss that triggers an eval reload. */
        public boolean isNoScript() {
            return message.toLowerCase().contains("noscript");
        }
    }

    /** Builds the shipped client from a redis:// or rediss:// url. */
    public static RespClient dial(String raw) {
        URI parsed;
        try {
            parsed = new URI(raw);
        } catch (URISyntaxException e) {
            throw new RuntimeException("kiwicaptcha: bad redis url: " + e.getMessage(), e);
        }
        if ("rediss".equalsIgnoreCase(parsed.getScheme())) {
            throw new RuntimeException(
                    "kiwicaptcha: rediss:// needs a tls transport this jdk client does not carry; "
                            + "terminate tls at the redis proxy fronting the store");
        }
        String host = parsed.getHost() == null ? "127.0.0.1" : parsed.getHost();
        int port = parsed.getPort() > 0 ? parsed.getPort() : 6379;
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(host, port), 5_000);
            socket.setTcpNoDelay(true);
        } catch (IOException e) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // The dial already failed.
            }
            throw new RuntimeException("kiwicaptcha: redis dial failed: " + e.getMessage(), e);
        }
        RespClient client = new RespClient(socket);
        if (parsed.getUserInfo() != null) {
            int colon = parsed.getUserInfo().indexOf(':');
            String password = colon >= 0 ? parsed.getUserInfo().substring(colon + 1) : parsed.getUserInfo();
            try {
                client.command("AUTH", password);
            } catch (RuntimeException e) {
                client.close();
                throw new RuntimeException("kiwicaptcha: redis auth failed: " + e.getMessage(), e);
            }
        }
        return client;
    }

    private RespClient(Socket socket) {
        this.socket = socket;
        try {
            this.reader = new BufferedInputStream(socket.getInputStream());
        } catch (IOException e) {
            throw new RuntimeException("kiwicaptcha: redis stream failed: " + e.getMessage(), e);
        }
    }

    /** Sends one command and decodes the reply. */
    @Override
    public synchronized Object command(String... args) {
        if (socket == null) {
            throw new RuntimeException("kiwicaptcha: redis client is closed");
        }
        StringBuilder sb = new StringBuilder();
        sb.append('*').append(args.length).append("\r\n");
        for (String arg : args) {
            byte[] bytes = arg.getBytes(StandardCharsets.UTF_8);
            sb.append('$').append(bytes.length).append("\r\n");
            sb.append(arg).append("\r\n");
        }
        try {
            socket.getOutputStream().write(sb.toString().getBytes(StandardCharsets.UTF_8));
            socket.getOutputStream().flush();
            return readReply();
        } catch (IOException e) {
            throw new RuntimeException("kiwicaptcha: redis write failed: " + e.getMessage(), e);
        }
    }

    private Object readReply() {
        String line = readLine();
        if (line.isEmpty()) {
            throw new RuntimeException("kiwicaptcha: redis sent an empty reply line");
        }
        char type = line.charAt(0);
        String body = line.substring(1);
        return switch (type) {
            case '+' -> body;
            case '-' -> throw new RedisException(body);
            case ':' -> parseLong(body);
            case '$' -> {
                long length = parseLong(body);
                if (length < 0) {
                    yield null;
                }
                byte[] payload = readFull((int) length + 2);
                yield new String(payload, 0, (int) length, StandardCharsets.UTF_8);
            }
            case '*' -> {
                long count = parseLong(body);
                if (count < 0) {
                    yield null;
                }
                List<Object> out = new ArrayList<>((int) count);
                for (int i = 0; i < count; i++) {
                    out.add(readReply());
                }
                yield out;
            }
            default -> throw new RuntimeException("kiwicaptcha: unknown redis reply type " + type);
        };
    }

    private static long parseLong(String body) {
        try {
            return Long.parseLong(body);
        } catch (NumberFormatException e) {
            throw new RuntimeException("kiwicaptcha: bad redis integer reply: " + body);
        }
    }

    private String readLine() {
        ByteArrayOutputStream sb = new ByteArrayOutputStream();
        try {
            int previous = -1;
            while (true) {
                int b = reader.read();
                if (b < 0) {
                    throw new IOException("connection closed");
                }
                if (previous == '\r' && b == '\n') {
                    byte[] bytes = sb.toByteArray();
                    return new String(bytes, 0, bytes.length - 1, StandardCharsets.UTF_8);
                }
                sb.write(b);
                previous = b;
            }
        } catch (IOException e) {
            throw new RuntimeException("kiwicaptcha: redis read failed: " + e.getMessage(), e);
        }
    }

    private byte[] readFull(int n) {
        byte[] buf = new byte[n];
        int total = 0;
        try {
            while (total < n) {
                int read = reader.read(buf, total, n - total);
                if (read < 0) {
                    throw new IOException("connection closed");
                }
                total += read;
            }
        } catch (IOException e) {
            throw new RuntimeException("kiwicaptcha: redis bulk read failed: " + e.getMessage(), e);
        }
        return buf;
    }

    /** Returns the string value and its presence. */
    @Override
    public String[] get(String key) {
        Object reply = command("GET", key);
        if (reply == null) {
            return null;
        }
        if (!(reply instanceof String value)) {
            throw new RuntimeException("kiwicaptcha: redis get returned a non string reply");
        }
        return new String[]{value};
    }

    /** Writes the value with a millisecond lifetime. */
    @Override
    public void setWithTtl(String key, String value, long ttlMillis) {
        command("SET", key, value, "PX", Long.toString(ttlMillis));
    }

    /** Returns the remaining lifetime in milliseconds. */
    @Override
    public long pttl(String key) {
        Object reply = command("PTTL", key);
        if (!(reply instanceof Long value)) {
            throw new RuntimeException("kiwicaptcha: redis pttl returned a non integer reply");
        }
        return value;
    }

    /** Removes one key. */
    @Override
    public boolean del(String key) {
        Object reply = command("DEL", key);
        if (!(reply instanceof Long value)) {
            throw new RuntimeException("kiwicaptcha: redis del returned a non integer reply");
        }
        return value > 0;
    }

    @Override
    public Object eval(String script, List<String> keys, List<String> args) {
        List<String> parts = new ArrayList<>(3 + keys.size() + args.size());
        parts.add("EVAL");
        parts.add(script);
        parts.add(Integer.toString(keys.size()));
        parts.addAll(keys);
        parts.addAll(args);
        return command(parts.toArray(new String[0]));
    }

    @Override
    public Object evalSha(String sha, List<String> keys, List<String> args) {
        List<String> parts = new ArrayList<>(3 + keys.size() + args.size());
        parts.add("EVALSHA");
        parts.add(sha);
        parts.add(Integer.toString(keys.size()));
        parts.addAll(keys);
        parts.addAll(args);
        return command(parts.toArray(new String[0]));
    }

    @Override
    public String scriptLoad(String script) {
        Object reply = command("SCRIPT", "LOAD", script);
        if (!(reply instanceof String value)) {
            throw new RuntimeException("kiwicaptcha: script load returned a non string reply");
        }
        return value;
    }

    /** Probes the server. */
    @Override
    public void ping() {
        command("PING");
    }

    /** Releases the connection. */
    @Override
    public synchronized void close() {
        if (socket == null) {
            return;
        }
        try {
            socket.close();
        } catch (IOException ignored) {
            // Closing is best-effort.
        }
        socket = null;
        reader = null;
    }
}
