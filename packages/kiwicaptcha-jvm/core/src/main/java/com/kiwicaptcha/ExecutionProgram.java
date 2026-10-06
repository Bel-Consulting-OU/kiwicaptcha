package com.kiwicaptcha;

/**
 * Execution challenge program shape parsing. The wire blob is base64
 * of a compact program: format byte, scope, action, op version, op
 * count, then the op records. This class implements the exact program
 * language accepted by the php ExecutionChallengeGenerator decode, so
 * the record parser and the verifier can validate a stored program's
 * shape and reject foreign blobs fail closed.
 *
 * Out of scope, deliberately: the trace simulator and the trace replay
 * walker that verify a presented execution digest. A program that
 * parses is shape validated, and its signed commitment can still be
 * checked against the stored bytes.
 */
public final class ExecutionProgram {
    private ExecutionProgram() {}

    /** Program language bounds. */
    public static final int EXECUTION_FORMAT_VERSION = 1;
    public static final int EXECUTION_MIN_OPS = 8;
    public static final int EXECUTION_MAX_OPS = 24;
    public static final int MAX_PROGRAM_BASE64 = 4096;
    private static final int EXECUTION_OPCODE_COUNT = 50;

    // Execution opcodes, in vocabulary order.
    private static final int OP_ADD = 0;
    private static final int OP_SUB = 1;
    private static final int OP_MUL = 2;
    private static final int OP_XOR = 3;
    private static final int OP_AND = 4;
    private static final int OP_OR = 5;
    private static final int OP_SHL = 6;
    private static final int OP_SHR = 7;
    private static final int OP_U8_CREATE = 8;
    private static final int OP_U8_WRITE = 9;
    private static final int OP_U8_READ = 10;
    private static final int OP_U8_ROTATE = 11;
    private static final int OP_STR_LEN = 12;
    private static final int OP_STR_CHARCODE = 13;
    private static final int OP_STR_CODEPOINT = 14;
    private static final int OP_STR_SLICE = 15;
    private static final int OP_DOM_CREATE = 16;
    private static final int OP_DOM_SET_ATTR = 17;
    private static final int OP_DOM_APPEND = 18;
    private static final int OP_DOM_QUERY = 19;
    private static final int OP_DOM_GET_ATTR = 20;
    private static final int OP_DOM_DATASET_SET = 21;
    private static final int OP_DOM_DATASET_GET = 22;
    private static final int OP_DOM_CLASS_ADD = 23;
    private static final int OP_DOM_CLASS_CONTAINS = 24;
    private static final int OP_DOM_PARENT = 25;
    private static final int OP_DOM_DISPATCH = 26;
    private static final int OP_DOM_SERIALIZE = 27;
    private static final int OP_DOM_QUERY_REAL = 28;
    private static final int OP_DOM_GEOMETRY = 29;
    private static final int OP_DOM_POINT = 30;
    private static final int OP_DOM_EVENT_REAL = 31;
    private static final int OP_DOM_SERIALIZE_REAL = 32;
    private static final int OP_DOM_OBSERVE = 33;
    private static final int OP_DOM_SIBLING_INDEX = 34;
    private static final int OP_DOM_CHILD = 35;
    private static final int OP_DOM_DEPTH = 36;
    private static final int OP_DOM_FRAGMENT_APPEND = 37;
    private static final int OP_DOM_CLONE = 38;
    private static final int OP_DOM_REPARENT = 39;
    private static final int OP_DOM_ATTR_REFLECT = 40;
    private static final int OP_DOM_EVENT_PHASE = 41;
    private static final int OP_DOM_URL_CANON = 42;
    private static final int OP_DOM_TEXT_MUTATE = 43;
    private static final int OP_DOM_SELECT_DEP = 44;
    private static final int OP_CSS_GEOM = 45;
    private static final int OP_MUT_ORDER = 46;
    private static final int OP_EV_PHASE_FULL = 47;
    private static final int OP_RANGE_ORDER = 48;
    private static final int OP_INT_OBS = 49;

    /** Per-version opcode ceilings of the execution grammar. */
    private static int maxOpcodeByVersion(int version) {
        return switch (version) {
            case 1 -> 33;
            case 2 -> 34;
            case 3 -> 35;
            case 4 -> 37;
            case 5 -> 45;
            case 6 -> EXECUTION_OPCODE_COUNT;
            default -> -1;
        };
    }

    /** The signed commitment of a program: the hex sha256 of the wire string. */
    public static String commitment(String programB64) {
        return Canonical.hex(Canonical.sha256(programB64.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }

    /**
     * Parses a program blob and reports whether it sits inside the
     * protocol program language. A valid prefix with trailing bytes is
     * rejected, every version bounds its own opcode space, and the
     * identifiers follow the narrow deployment alphabet.
     */
    public static boolean decodeExecutionProgram(String programB64) {
        if (programB64.isEmpty() || programB64.length() > MAX_PROGRAM_BASE64) {
            return false;
        }
        byte[] decoded = Canonical.b64CanonicalDecode(programB64);
        if (decoded == null) {
            return false;
        }
        Cursor cur = new Cursor(decoded);
        int header = cur.readByte();
        if (header < 0 || header != EXECUTION_FORMAT_VERSION) {
            return false;
        }
        int scopeLen = cur.readByte();
        if (scopeLen < 0) {
            return false;
        }
        byte[] scopeRaw = cur.read(scopeLen);
        if (scopeRaw == null || scopeRaw.length == 0 || scopeRaw.length > 128) {
            return false;
        }
        if (!ChallengeRecord.isValidIdentifier(new String(scopeRaw, java.nio.charset.StandardCharsets.UTF_8), 128)) {
            return false;
        }
        int actionLen = cur.readByte();
        if (actionLen < 0) {
            return false;
        }
        byte[] actionRaw = cur.read(actionLen);
        if (actionRaw == null || actionRaw.length == 0 || actionRaw.length > 32) {
            return false;
        }
        if (!ChallengeRecord.isValidIdentifier(new String(actionRaw, java.nio.charset.StandardCharsets.UTF_8), 32)) {
            return false;
        }
        int opVersion = cur.readByte();
        if (opVersion < 1 || opVersion > Kiwi.MAX_EXECUTION_VERSION) {
            return false;
        }
        int opCount = cur.readByte();
        if (opCount < EXECUTION_MIN_OPS || opCount > EXECUTION_MAX_OPS) {
            return false;
        }
        int maxOpcode = maxOpcodeByVersion(opVersion);
        if (maxOpcode < 0) {
            return false;
        }
        for (int i = 0; i < opCount; i++) {
            int opcode = cur.readByte();
            if (opcode < 0 || opcode >= maxOpcode) {
                return false;
            }
            if (!cur.readOperands(opcode)) {
                return false;
            }
        }
        return cur.pos == decoded.length;
    }

    /** Whether the blob is inside the protocol program language. */
    public static boolean isValidExecutionProgram(String programB64) {
        return decodeExecutionProgram(programB64);
    }

    private static final class Cursor {
        final byte[] data;
        int pos;

        Cursor(byte[] data) {
            this.data = data;
        }

        int readByte() {
            if (pos + 1 > data.length) {
                return -1;
            }
            return data[pos++] & 0xff;
        }

        byte[] read(int n) {
            if (n < 0 || pos + n > data.length) {
                return null;
            }
            byte[] out = new byte[n];
            System.arraycopy(data, pos, out, 0, n);
            pos += n;
            return out;
        }

        boolean readBoundedString(int minLen, int maxLen) {
            int length = readByte();
            if (length < minLen || length > maxLen) {
                return false;
            }
            return read(length) != null;
        }

        boolean readId() {
            return readBoundedString(4, 16);
        }

        boolean readString() {
            return readBoundedString(1, 16);
        }

        boolean readValue() {
            return readBoundedString(1, 32);
        }

        boolean readClass() {
            return readBoundedString(1, 12);
        }

        boolean skipByte() {
            return readByte() >= 0;
        }

        boolean readOperands(int opcode) {
            switch (opcode) {
                case OP_ADD, OP_SUB, OP_MUL, OP_XOR, OP_AND, OP_OR, OP_SHL, OP_SHR:
                    return read(8) != null;
                case OP_U8_CREATE:
                    return readByte() >= 0;
                case OP_U8_WRITE:
                    return read(2) != null;
                case OP_U8_READ, OP_U8_ROTATE:
                    return readByte() >= 0;
                case OP_STR_LEN, OP_DOM_DATASET_GET:
                    return readString();
                case OP_STR_CHARCODE, OP_STR_CODEPOINT:
                    return readString() && skipByte();
                case OP_STR_SLICE:
                    return readString() && read(2) != null;
                case OP_DOM_CREATE, OP_DOM_CHILD:
                    // Both read one tag byte and one identifier, in that order.
                    return skipByte() && readId();
                case OP_DOM_SET_ATTR:
                    // The php reader pairs the name byte with a value
                    // operand (1..32), not a string operand (1..16).
                    return skipByte() && readValue();
                case OP_DOM_QUERY:
                    return readId();
                case OP_DOM_GET_ATTR, OP_DOM_ATTR_REFLECT:
                    return readByte() >= 0;
                case OP_DOM_DATASET_SET: {
                    int keyByte = readByte();
                    if (keyByte < 1 || keyByte > 16) {
                        return false;
                    }
                    if (read(keyByte) == null) {
                        return false;
                    }
                    return readValue();
                }
                case OP_DOM_CLASS_ADD, OP_DOM_CLASS_CONTAINS:
                    return readClass();
                case OP_DOM_APPEND, OP_DOM_PARENT, OP_DOM_DISPATCH, OP_DOM_SERIALIZE,
                     OP_DOM_SERIALIZE_REAL, OP_DOM_URL_CANON:
                    return true;
                case OP_DOM_QUERY_REAL, OP_DOM_GEOMETRY, OP_DOM_EVENT_REAL, OP_DOM_SIBLING_INDEX, OP_DOM_DEPTH:
                    return readId();
                case OP_DOM_POINT:
                    return read(2) != null;
                case OP_DOM_OBSERVE:
                    return readId() && skipByte();
                case OP_DOM_CLONE, OP_DOM_REPARENT:
                    return readId() && skipByte();
                case OP_DOM_FRAGMENT_APPEND:
                    return read(2) != null;
                case OP_DOM_EVENT_PHASE:
                    return readByte() >= 0;
                case OP_DOM_TEXT_MUTATE:
                    return readValue() && skipByte();
                case OP_DOM_SELECT_DEP:
                    return read(3) != null;
                case OP_CSS_GEOM, OP_INT_OBS:
                    // Version-6 real-platform probes: the probed id
                    // plus one raw seed byte and one raw dst cell.
                    return readId() && read(2) != null;
                case OP_MUT_ORDER, OP_RANGE_ORDER:
                    return readId() && read(3) != null;
                case OP_EV_PHASE_FULL:
                    return readId() && skipByte();
                default:
                    return false;
            }
        }
    }
}
