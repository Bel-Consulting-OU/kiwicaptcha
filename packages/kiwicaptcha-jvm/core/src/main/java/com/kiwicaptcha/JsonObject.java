package com.kiwicaptcha;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A decoded json object that preserves the wire key order. Duplicate
 * keys keep the first position and the last value, the same resolution
 * the php json decoder applies. The encoder renders the compact
 * separators and the ascii escaping of the reference encoders, so a
 * decoded token encodes back to its exact wire bytes. Values are
 * null, Boolean, JsonNumber, String, JsonObject or List of those.
 */
public final class JsonObject {
    private final List<String> keys = new ArrayList<>();
    private final Map<String, Object> values = new LinkedHashMap<>();

    /** Builds an empty object. */
    public JsonObject() {}

    /** Builds an object from ordered pairs. */
    public static JsonObject of(Object... keyValues) {
        if (keyValues.length % 2 != 0) {
            throw new IllegalArgumentException("ordered pairs required");
        }
        JsonObject obj = new JsonObject();
        for (int i = 0; i < keyValues.length; i += 2) {
            obj.set((String) keyValues[i], keyValues[i + 1]);
        }
        return obj;
    }

    /** Inserts or updates a member, preserving first position on update. */
    public void set(String key, Object value) {
        if (!values.containsKey(key)) {
            keys.add(key);
        }
        values.put(key, value);
    }

    /** Returns the value stored under the key, or null. */
    public Object get(String key) {
        return values.get(key);
    }

    /** Returns the value and reports presence. */
    public boolean tryGet(String key, Object[] out) {
        if (!values.containsKey(key)) {
            return false;
        }
        out[0] = values.get(key);
        return true;
    }

    /** Returns the named boolean member, or the fallback. */
    public Boolean boolOrNull(String key) {
        Object v = values.get(key);
        return v instanceof Boolean b ? b : null;
    }

    /** The number of members. */
    public int size() {
        return keys.size();
    }

    /** The members in wire order. */
    public List<String> keys() {
        return new ArrayList<>(keys);
    }

    /** The "et" event list when it is an array of non negative integers. */
    public List<Long> telemetryEvents() {
        Object v = values.get("et");
        if (!(v instanceof List<?> items)) {
            return null;
        }
        List<Long> events = new ArrayList<>();
        for (Object item : items) {
            if (item instanceof JsonNumber n) {
                try {
                    long parsed = n.longValue();
                    if (parsed >= 0) {
                        events.add(parsed);
                    }
                } catch (NumberFormatException ignored) {
                    // A non integer event literal is skipped, the
                    // reference behavior for a malformed sample.
                }
            }
        }
        return events;
    }

    /** Renders the object with the compact reference encoding. */
    public String encode() {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        for (int i = 0; i < keys.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            writeJsonString(sb, keys.get(i));
            sb.append(':');
            writeJsonValue(sb, values.get(keys.get(i)));
        }
        sb.append('}');
        return sb.toString();
    }

    /** Encodes one string with the reference json string escaping. */
    public static String encodeStatic(String value) {
        StringBuilder sb = new StringBuilder();
        writeJsonString(sb, value);
        return sb.toString();
    }

    static void writeJsonValue(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof Boolean b) {
            sb.append(b ? "true" : "false");
        } else if (value instanceof JsonNumber n) {
            sb.append(n.raw);
        } else if (value instanceof String s) {
            writeJsonString(sb, s);
        } else if (value instanceof JsonObject o) {
            sb.append(o.encode());
        } else if (value instanceof List<?> list) {
            sb.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                writeJsonValue(sb, list.get(i));
            }
            sb.append(']');
        } else {
            sb.append("null");
        }
    }

    /** Writes one json string with the ascii escaping of the reference encoders. */
    static void writeJsonString(StringBuilder sb, String value) {
        sb.append('"');
        int offset = 0;
        while (offset < value.length()) {
            int cp = value.codePointAt(offset);
            switch (cp) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (cp < 0x20 || cp > 0x7e) {
                        writeEscapedCodePoint(sb, cp);
                    } else {
                        sb.appendCodePoint(cp);
                    }
                }
            }
            offset += Character.charCount(cp);
        }
        sb.append('"');
    }

    private static void writeEscapedCodePoint(StringBuilder sb, int cp) {
        if (cp > 0xffff) {
            char[] pair = Character.toChars(cp);
            writeUnicodeEscape(sb, pair[0]);
            writeUnicodeEscape(sb, pair[1]);
            return;
        }
        writeUnicodeEscape(sb, cp);
    }

    private static void writeUnicodeEscape(StringBuilder sb, int unit) {
        sb.append(String.format("\\u%04x", unit));
    }

    /**
     * Parses one json document that must be an object, preserving key
     * order and the raw spelling of every number. Duplicate keys at
     * any nesting level are rejected, mirroring the strict envelope
     * gate the stored documents go through.
     */
    public static JsonObject parseObject(String text) {
        Parser p = new Parser(text);
        p.skipSpace();
        if (p.peek() != '{') {
            throw new IllegalArgumentException("telemetry must be a json object");
        }
        JsonObject obj = p.parseObjectBody(0);
        p.skipSpace();
        if (p.pos <= p.last) {
            throw new IllegalArgumentException("trailing bytes after the telemetry object");
        }
        return obj;
    }

    private static final class Parser {
        private final String text;
        private final int last;
        private int pos;

        Parser(String text) {
            if (!isUtf8Clean(text)) {
                throw new IllegalArgumentException("telemetry is not valid utf-8");
            }
            this.text = text;
            this.last = text.length() - 1;
        }

        char peek() {
            if (pos > last) {
                throw new IllegalArgumentException("unexpected end of json");
            }
            return text.charAt(pos);
        }

        void skipSpace() {
            while (pos <= last) {
                char c = text.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        JsonObject parseObjectBody(int depth) {
            if (depth > 32) {
                throw new IllegalArgumentException("json nesting too deep");
            }
            expect('{');
            JsonObject obj = new JsonObject();
            skipSpace();
            if (peek() == '}') {
                pos++;
                return obj;
            }
            while (true) {
                skipSpace();
                String key = parseString();
                skipSpace();
                expect(':');
                skipSpace();
                Object value = parseValue(depth + 1);
                if (!obj.values.containsKey(key)) {
                    obj.keys.add(key);
                }
                obj.values.put(key, value);
                skipSpace();
                char c = peek();
                if (c == ',') {
                    pos++;
                } else if (c == '}') {
                    pos++;
                    return obj;
                } else {
                    throw new IllegalArgumentException("bad json object separator");
                }
            }
        }

        List<Object> parseArray(int depth) {
            if (depth > 32) {
                throw new IllegalArgumentException("json nesting too deep");
            }
            expect('[');
            List<Object> out = new ArrayList<>();
            skipSpace();
            if (peek() == ']') {
                pos++;
                return out;
            }
            while (true) {
                skipSpace();
                out.add(parseValue(depth + 1));
                skipSpace();
                char c = peek();
                if (c == ',') {
                    pos++;
                } else if (c == ']') {
                    pos++;
                    return out;
                } else {
                    throw new IllegalArgumentException("bad json array separator");
                }
            }
        }

        Object parseValue(int depth) {
            char c = peek();
            return switch (c) {
                case '{' -> parseObjectBody(depth);
                case '[' -> parseArray(depth);
                case '"' -> parseString();
                case 't' -> {
                    expectWord("true");
                    yield Boolean.TRUE;
                }
                case 'f' -> {
                    expectWord("false");
                    yield Boolean.FALSE;
                }
                case 'n' -> {
                    expectWord("null");
                    yield null;
                }
                default -> parseNumber();
            };
        }

        JsonNumber parseNumber() {
            int start = pos;
            if (peek() == '-') {
                pos++;
            }
            boolean digits = false;
            while (pos <= last) {
                char c = text.charAt(pos);
                if (c >= '0' && c <= '9') {
                    digits = true;
                    pos++;
                } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                    pos++;
                } else {
                    break;
                }
            }
            if (!digits) {
                throw new IllegalArgumentException("bad json number");
            }
            return new JsonNumber(text.substring(start, pos));
        }

        String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (pos > last) {
                    throw new IllegalArgumentException("unterminated json string");
                }
                char c = text.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    char esc = text.charAt(pos++);
                    switch (esc) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            int unit = Integer.parseInt(text.substring(pos, pos + 4), 16);
                            pos += 4;
                            if (Character.isHighSurrogate((char) unit) && pos + 1 <= last
                                    && text.charAt(pos) == '\\' && text.charAt(pos + 1) == 'u') {
                                int low = Integer.parseInt(text.substring(pos + 2, pos + 6), 16);
                                if (Character.isLowSurrogate((char) low)) {
                                    pos += 6;
                                    sb.appendCodePoint(Character.toCodePoint((char) unit, (char) low));
                                    continue;
                                }
                            }
                            sb.append((char) unit);
                        }
                        default -> throw new IllegalArgumentException("bad json escape");
                    }
                } else {
                    sb.append(c);
                }
            }
        }

        private void expect(char c) {
            if (peek() != c) {
                throw new IllegalArgumentException("unexpected json byte " + c);
            }
            pos++;
        }

        private void expectWord(String word) {
            if (pos + word.length() > last + 1 || !text.startsWith(word, pos)) {
                throw new IllegalArgumentException("bad json literal");
            }
            pos += word.length();
        }
    }

    private static boolean isUtf8Clean(String text) {
        // A java String is already decoded utf-16; lone surrogates are
        // the one shape that cannot come from a valid utf-8 document.
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isSurrogate(c)
                    && (i + 1 >= text.length() || !Character.isSurrogatePair(c, text.charAt(i + 1)))) {
                return false;
            }
            if (Character.isLowSurrogate(c) && i > 0 && Character.isHighSurrogate(text.charAt(i - 1))) {
                return false;
            }
        }
        return true;
    }
}
