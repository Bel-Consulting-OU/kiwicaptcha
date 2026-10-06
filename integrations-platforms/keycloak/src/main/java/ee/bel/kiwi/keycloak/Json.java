package ee.bel.kiwi.keycloak;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal strict JSON parser (RFC 8259 grammar), dependency-free so
 * the decision surface still compiles and tests with the JDK alone.
 * The whole document must parse: trailing garbage, truncated
 * documents, single quotes, unquoted keys, comments, NaN/Infinity and
 * control characters inside strings are all refused. Objects decode
 * to {@link Map} (insertion-ordered), arrays to {@link List}, and the
 * four literals to {@link Boolean}/{@link Double}/{@link Long}/null.
 */
final class Json {

    private Json() {
    }

    /**
     * Parses one complete JSON document.
     *
     * @throws IllegalArgumentException on any syntax outside RFC 8259
     */
    static Object parse(String text) {
        Parser parser = new Parser(text);
        Object value = parser.parseValue();
        parser.skipWhitespace();
        if (!parser.atEnd()) {
            throw new IllegalArgumentException("trailing content after the JSON document");
        }
        return value;
    }

    private static final class Parser {
        private final String text;
        private int pos;

        Parser(String text) {
            this.text = text == null ? "" : text;
        }

        boolean atEnd() {
            return pos >= text.length();
        }

        void skipWhitespace() {
            while (pos < text.length()) {
                char c = text.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        Object parseValue() {
            skipWhitespace();
            if (atEnd()) {
                throw new IllegalArgumentException("unexpected end of JSON document");
            }
            char c = text.charAt(pos);
            return switch (c) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> parseString();
                case 't' -> parseLiteral("true", Boolean.TRUE);
                case 'f' -> parseLiteral("false", Boolean.FALSE);
                case 'n' -> parseLiteral("null", null);
                default -> {
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        yield parseNumber();
                    }
                    throw new IllegalArgumentException("unexpected character '" + c + "' in JSON document");
                }
            };
        }

        Map<String, Object> parseObject() {
            expect('{');
            Map<String, Object> object = new LinkedHashMap<>();
            skipWhitespace();
            if (peek() == '}') {
                pos++;
                return object;
            }
            while (true) {
                skipWhitespace();
                if (peek() != '"') {
                    throw new IllegalArgumentException("JSON object keys must be strings");
                }
                String key = parseString();
                if (object.containsKey(key)) {
                    // RFC 8259 leaves duplicate names to the parser;
                    // refusing them is the fail-closed reading (two
                    // "success" members must never resolve to one of
                    // them by accident of ordering).
                    throw new IllegalArgumentException("duplicate JSON object key " + key);
                }
                skipWhitespace();
                expect(':');
                object.put(key, parseValue());
                skipWhitespace();
                char c = peek();
                if (c == ',') {
                    pos++;
                    continue;
                }
                if (c == '}') {
                    pos++;
                    return object;
                }
                throw new IllegalArgumentException("expected ',' or '}' in JSON object");
            }
        }

        List<Object> parseArray() {
            expect('[');
            List<Object> array = new ArrayList<>();
            skipWhitespace();
            if (peek() == ']') {
                pos++;
                return array;
            }
            while (true) {
                array.add(parseValue());
                skipWhitespace();
                char c = peek();
                if (c == ',') {
                    pos++;
                    continue;
                }
                if (c == ']') {
                    pos++;
                    return array;
                }
                throw new IllegalArgumentException("expected ',' or ']' in JSON array");
            }
        }

        String parseString() {
            expect('"');
            StringBuilder out = new StringBuilder();
            while (true) {
                if (atEnd()) {
                    throw new IllegalArgumentException("unterminated JSON string");
                }
                char c = text.charAt(pos++);
                if (c == '"') {
                    return out.toString();
                }
                if (c == '\\') {
                    if (atEnd()) {
                        throw new IllegalArgumentException("unterminated JSON escape");
                    }
                    char e = text.charAt(pos++);
                    switch (e) {
                        case '"' -> out.append('"');
                        case '\\' -> out.append('\\');
                        case '/' -> out.append('/');
                        case 'b' -> out.append('\b');
                        case 'f' -> out.append('\f');
                        case 'n' -> out.append('\n');
                        case 'r' -> out.append('\r');
                        case 't' -> out.append('\t');
                        case 'u' -> out.append(parseUnicodeEscape());
                        default -> throw new IllegalArgumentException("invalid JSON escape '\\" + e + "'");
                    }
                    continue;
                }
                if (c < 0x20) {
                    throw new IllegalArgumentException("unescaped control character in JSON string");
                }
                out.append(c);
            }
        }

        char parseUnicodeEscape() {
            if (pos + 4 > text.length()) {
                throw new IllegalArgumentException("truncated JSON unicode escape");
            }
            int code = 0;
            for (int i = 0; i < 4; i++) {
                char c = text.charAt(pos++);
                int digit = Character.digit(c, 16);
                if (digit < 0) {
                    throw new IllegalArgumentException("invalid JSON unicode escape");
                }
                code = (code << 4) | digit;
            }
            return (char) code;
        }

        Object parseNumber() {
            int start = pos;
            if (peek() == '-') {
                pos++;
            }
            if (atEnd()) {
                throw new IllegalArgumentException("truncated JSON number");
            }
            if (peek() == '0') {
                pos++;
            } else if (peek() >= '1' && peek() <= '9') {
                consumeDigits();
            } else {
                throw new IllegalArgumentException("invalid JSON number");
            }
            boolean integral = true;
            if (!atEnd() && peek() == '.') {
                integral = false;
                pos++;
                if (atEnd() || peek() < '0' || peek() > '9') {
                    throw new IllegalArgumentException("invalid JSON number fraction");
                }
                consumeDigits();
            }
            if (!atEnd() && (peek() == 'e' || peek() == 'E')) {
                integral = false;
                pos++;
                if (!atEnd() && (peek() == '+' || peek() == '-')) {
                    pos++;
                }
                if (atEnd() || peek() < '0' || peek() > '9') {
                    throw new IllegalArgumentException("invalid JSON number exponent");
                }
                consumeDigits();
            }
            String literal = text.substring(start, pos);
            try {
                return integral ? (Object) Long.parseLong(literal) : (Object) Double.parseDouble(literal);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("invalid JSON number " + literal);
            }
        }

        Object parseLiteral(String literal, Object value) {
            if (!text.startsWith(literal, pos)) {
                throw new IllegalArgumentException("invalid JSON literal");
            }
            pos += literal.length();
            return value;
        }

        void consumeDigits() {
            while (!atEnd() && peek() >= '0' && peek() <= '9') {
                pos++;
            }
        }

        char peek() {
            if (atEnd()) {
                throw new IllegalArgumentException("unexpected end of JSON document");
            }
            return text.charAt(pos);
        }

        void expect(char expected) {
            if (atEnd() || text.charAt(pos) != expected) {
                throw new IllegalArgumentException("expected '" + expected + "' in JSON document");
            }
            pos++;
        }
    }
}
