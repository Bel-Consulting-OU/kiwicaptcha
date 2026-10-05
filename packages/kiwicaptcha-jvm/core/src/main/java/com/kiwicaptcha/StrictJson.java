package com.kiwicaptcha;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Strict json decoding shared by the record parser and the stored
 * envelope decoder. Both surfaces follow the serde deny unknown fields
 * rule and reject semantic duplicate keys: a document whose members
 * decode to the same name at any nesting level is ambiguous corruption
 * and is never trusted. Numbers are kept as JsonNumber with their raw
 * spelling, so a stored issued_at_ns never passes through a float.
 */
public final class StrictJson {
    private StrictJson() {}

    /** Decodes one document with trailing-byte and duplicate-key rejection. */
    public static Object decode(byte[] data) {
        if (data.length > Kiwi.ENVELOPE_MAX_BYTES) {
            throw new IllegalArgumentException(
                    "document exceeds the " + Kiwi.ENVELOPE_MAX_BYTES + " byte envelope ceiling");
        }
        String text = new String(data, StandardCharsets.UTF_8);
        Parser p = new Parser(text);
        p.skipSpace();
        Object value = p.parseValue(0);
        p.skipSpace();
        if (p.pos <= p.last) {
            throw new IllegalArgumentException("trailing bytes after the json value");
        }
        return value;
    }

    private static final class Parser {
        private final String text;
        private final int last;
        private int pos;

        Parser(String text) {
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

        Object parseValue(int depth) {
            char c = peek();
            return switch (c) {
                case '{' -> parseObject(depth);
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

        private Map<String, Object> parseObject(int depth) {
            if (depth > 32) {
                throw new IllegalArgumentException("json nesting too deep");
            }
            expect('{');
            Map<String, Object> out = new LinkedHashMap<>();
            skipSpace();
            if (peek() == '}') {
                pos++;
                return out;
            }
            while (true) {
                skipSpace();
                String key = parseString();
                if (out.containsKey(key)) {
                    throw new IllegalArgumentException("duplicate json key: " + key);
                }
                skipSpace();
                expect(':');
                skipSpace();
                out.put(key, parseValue(depth + 1));
                skipSpace();
                char c = peek();
                if (c == ',') {
                    pos++;
                } else if (c == '}') {
                    pos++;
                    return out;
                } else {
                    throw new IllegalArgumentException("bad json object separator");
                }
            }
        }

        private List<Object> parseArray(int depth) {
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

        private JsonNumber parseNumber() {
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

        private String parseString() {
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
                            if (Character.isHighSurrogate((char) unit) && pos + 5 <= last
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
}
