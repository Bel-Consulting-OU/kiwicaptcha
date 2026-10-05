using System.Text;

namespace KiwiCaptcha;

/// <summary>
/// Execution challenge program shape parsing. The wire blob is
/// base64 of a compact program: format byte, scope, action, op
/// version, op count, then the op records. This class implements the
/// exact program language accepted by the php
/// ExecutionChallengeGenerator decode, so the record parser and the
/// verifier can validate a stored program's shape and reject foreign
/// blobs fail closed.
///
/// Out of scope, deliberately: the trace simulator and the trace
/// replay walker that verify a presented execution digest. A program
/// that parses is shape validated, and its signed commitment can
/// still be checked against the stored bytes.
/// </summary>
public static class ExecutionProgram
{
    public const int ExecutionFormatVersion = 1;
    public const int ExecutionMinOps = 8;
    public const int ExecutionMaxOps = 24;
    public const int MaxProgramBase64 = 4096;
    private const int ExecutionOpcodeCount = 45;

    // Execution opcodes, in vocabulary order.
    private const int OpAdd = 0;
    private const int OpSub = 1;
    private const int OpMul = 2;
    private const int OpXor = 3;
    private const int OpAnd = 4;
    private const int OpOr = 5;
    private const int OpShl = 6;
    private const int OpShr = 7;
    private const int OpU8Create = 8;
    private const int OpU8Write = 9;
    private const int OpU8Read = 10;
    private const int OpU8Rotate = 11;
    private const int OpStrLen = 12;
    private const int OpStrCharcode = 13;
    private const int OpStrCodepoint = 14;
    private const int OpStrSlice = 15;
    private const int OpDomCreate = 16;
    private const int OpDomSetAttr = 17;
    private const int OpDomAppend = 18;
    private const int OpDomQuery = 19;
    private const int OpDomGetAttr = 20;
    private const int OpDomDatasetSet = 21;
    private const int OpDomDatasetGet = 22;
    private const int OpDomClassAdd = 23;
    private const int OpDomClassContains = 24;
    private const int OpDomParent = 25;
    private const int OpDomDispatch = 26;
    private const int OpDomSerialize = 27;
    private const int OpDomQueryReal = 28;
    private const int OpDomGeometry = 29;
    private const int OpDomPoint = 30;
    private const int OpDomEventReal = 31;
    private const int OpDomSerializeReal = 32;
    private const int OpDomObserve = 33;
    private const int OpDomSiblingIndex = 34;
    private const int OpDomChild = 35;
    private const int OpDomDepth = 36;
    private const int OpDomFragmentAppend = 37;
    private const int OpDomClone = 38;
    private const int OpDomReparent = 39;
    private const int OpDomAttrReflect = 40;
    private const int OpDomEventPhase = 41;
    private const int OpDomUrlCanon = 42;
    private const int OpDomTextMutate = 43;
    private const int OpDomSelectDep = 44;

    /// <summary>Per-version opcode ceilings of the execution grammar.</summary>
    private static int MaxOpcodeByVersion(int version) => version switch
    {
        1 => 33,
        2 => 34,
        3 => 35,
        4 => 37,
        5 => ExecutionOpcodeCount,
        _ => -1,
    };

    /// <summary>The signed commitment of a program: the hex sha256 of the wire string.</summary>
    public static string Commitment(string programB64) =>
        Canonical.Hex(Canonical.Sha256(Encoding.UTF8.GetBytes(programB64)));

    /// <summary>
    /// Parses a program blob and reports whether it sits inside the
    /// protocol program language. A valid prefix with trailing bytes
    /// is rejected, every version bounds its own opcode space, and the
    /// identifiers follow the narrow deployment alphabet.
    /// </summary>
    public static bool DecodeExecutionProgram(string programB64)
    {
        if (programB64.Length == 0 || programB64.Length > MaxProgramBase64)
        {
            return false;
        }
        var decoded = Canonical.B64CanonicalDecode(programB64);
        if (decoded == null)
        {
            return false;
        }
        var cursor = new Cursor(decoded);
        var header = cursor.ReadByte();
        if (header < 0 || header != ExecutionFormatVersion)
        {
            return false;
        }
        var scopeLen = cursor.ReadByte();
        if (scopeLen < 0)
        {
            return false;
        }
        var scopeRaw = cursor.Read(scopeLen);
        if (scopeRaw == null || scopeRaw.Length == 0 || scopeRaw.Length > 128)
        {
            return false;
        }
        if (!ChallengeRecord.IsValidIdentifier(Encoding.UTF8.GetString(scopeRaw), 128))
        {
            return false;
        }
        var actionLen = cursor.ReadByte();
        if (actionLen < 0)
        {
            return false;
        }
        var actionRaw = cursor.Read(actionLen);
        if (actionRaw == null || actionRaw.Length == 0 || actionRaw.Length > 32)
        {
            return false;
        }
        if (!ChallengeRecord.IsValidIdentifier(Encoding.UTF8.GetString(actionRaw), 32))
        {
            return false;
        }
        var opVersion = cursor.ReadByte();
        if (opVersion < 1 || opVersion > Kiwi.MaxExecutionVersion)
        {
            return false;
        }
        var opCount = cursor.ReadByte();
        if (opCount < ExecutionMinOps || opCount > ExecutionMaxOps)
        {
            return false;
        }
        var maxOpcode = MaxOpcodeByVersion(opVersion);
        if (maxOpcode < 0)
        {
            return false;
        }
        for (var i = 0; i < opCount; i++)
        {
            var opcode = cursor.ReadByte();
            if (opcode < 0 || opcode >= maxOpcode)
            {
                return false;
            }
            if (!cursor.ReadOperands(opcode))
            {
                return false;
            }
        }
        return cursor.Pos == decoded.Length;
    }

    /// <summary>Whether the blob is inside the protocol program language.</summary>
    public static bool IsValidExecutionProgram(string programB64) => DecodeExecutionProgram(programB64);

    private sealed class Cursor
    {
        private readonly byte[] _data;
        internal int Pos;

        internal Cursor(byte[] data) => _data = data;

        internal int ReadByte()
        {
            if (Pos + 1 > _data.Length)
            {
                return -1;
            }
            return _data[Pos++];
        }

        internal byte[]? Read(int n)
        {
            if (n < 0 || Pos + n > _data.Length)
            {
                return null;
            }
            var outBytes = new byte[n];
            Array.Copy(_data, Pos, outBytes, 0, n);
            Pos += n;
            return outBytes;
        }

        private bool ReadBoundedString(int minLen, int maxLen)
        {
            var length = ReadByte();
            if (length < minLen || length > maxLen)
            {
                return false;
            }
            return Read(length) != null;
        }

        private bool ReadId() => ReadBoundedString(4, 16);

        private bool ReadString() => ReadBoundedString(1, 16);

        private bool ReadValue() => ReadBoundedString(1, 32);

        private bool ReadClass() => ReadBoundedString(1, 12);

        private bool SkipByte() => ReadByte() >= 0;

        internal bool ReadOperands(int opcode)
        {
            switch (opcode)
            {
                case OpAdd:
                case OpSub:
                case OpMul:
                case OpXor:
                case OpAnd:
                case OpOr:
                case OpShl:
                case OpShr:
                    return Read(8) != null;
                case OpU8Create:
                    return ReadByte() >= 0;
                case OpU8Write:
                    return Read(2) != null;
                case OpU8Read:
                case OpU8Rotate:
                    return ReadByte() >= 0;
                case OpStrLen:
                case OpDomDatasetGet:
                    return ReadString();
                case OpStrCharcode:
                case OpStrCodepoint:
                    return ReadString() && SkipByte();
                case OpStrSlice:
                    return ReadString() && Read(2) != null;
                case OpDomCreate:
                case OpDomChild:
                    // Both read one tag byte and one identifier, in that order.
                    return SkipByte() && ReadId();
                case OpDomSetAttr:
                    // The php reader pairs the name byte with a value
                    // operand (1..32), not a string operand (1..16).
                    return SkipByte() && ReadValue();
                case OpDomQuery:
                    return ReadId();
                case OpDomGetAttr:
                case OpDomAttrReflect:
                    return ReadByte() >= 0;
                case OpDomDatasetSet:
                {
                    var keyByte = ReadByte();
                    if (keyByte < 1 || keyByte > 16)
                    {
                        return false;
                    }
                    if (Read(keyByte) == null)
                    {
                        return false;
                    }
                    return ReadValue();
                }
                case OpDomClassAdd:
                case OpDomClassContains:
                    return ReadClass();
                case OpDomAppend:
                case OpDomParent:
                case OpDomDispatch:
                case OpDomSerialize:
                case OpDomSerializeReal:
                case OpDomUrlCanon:
                    return true;
                case OpDomQueryReal:
                case OpDomGeometry:
                case OpDomEventReal:
                case OpDomSiblingIndex:
                case OpDomDepth:
                    return ReadId();
                case OpDomPoint:
                    return Read(2) != null;
                case OpDomObserve:
                    return ReadId() && SkipByte();
                case OpDomClone:
                case OpDomReparent:
                    return ReadId() && SkipByte();
                case OpDomFragmentAppend:
                    return Read(2) != null;
                case OpDomEventPhase:
                    return ReadByte() >= 0;
                case OpDomTextMutate:
                    return ReadValue() && SkipByte();
                case OpDomSelectDep:
                    return Read(3) != null;
                default:
                    return false;
            }
        }
    }
}

/// <summary>
/// Bot detection telemetry scoring, mirroring the Rust
/// score_telemetry. The check is deliberately conservative: only
/// discrete event timings count, and a slow solve with zero
/// interaction is never a signal, because the widget auto-solves with
/// widget-local listeners.
/// </summary>
public static class Telemetry
{
    private const long TelemetryDurationCeilingMs = 300_000;
    private const double TelemetryMeanFloorMs = 8.0;
    private const double TelemetryCvCeiling = 0.02;
    private const int TelemetryMinDiffs = 23;

    /// <summary>
    /// Reports whether the telemetry looks bot generated. Three hard
    /// signals: the webdriver flag, a solve beyond 300 seconds, and a
    /// run of at least 23 discrete event intervals whose mean is at
    /// least 8 ms with a coefficient of variation below 0.02.
    /// </summary>
    public static bool ScoreTelemetry(JsonObject? telemetry, long durationMs)
    {
        if (telemetry != null && telemetry.Get("wd") is true)
        {
            return true;
        }
        var duration = Math.Max(durationMs, 0);
        if (duration > TelemetryDurationCeilingMs)
        {
            return true;
        }
        if (telemetry == null)
        {
            return false;
        }
        if (telemetry.Get("et") is not IReadOnlyList<object?> rawEvents)
        {
            return false;
        }
        var diffs = new long[Math.Max(0, rawEvents.Count - 1)];
        var count = 0;
        for (var i = 1; i < rawEvents.Count; i++)
        {
            var current = ParseNonNegative(rawEvents[i]);
            var prior = ParseNonNegative(rawEvents[i - 1]);
            if (current == null || prior == null || current < prior)
            {
                continue;
            }
            diffs[count++] = current.Value - prior.Value;
        }
        if (count < TelemetryMinDiffs)
        {
            return false;
        }
        double sum = 0;
        for (var i = 0; i < count; i++)
        {
            sum += diffs[i];
        }
        var mean = sum / count;
        if (mean < TelemetryMeanFloorMs)
        {
            return false;
        }
        double variance = 0;
        for (var i = 0; i < count; i++)
        {
            var delta = diffs[i] - mean;
            variance += delta * delta;
        }
        variance /= count;
        return Math.Sqrt(variance) / mean < TelemetryCvCeiling;
    }

    private static long? ParseNonNegative(object? raw)
    {
        if (raw is not JsonNumber number)
        {
            return null;
        }
        var text = number.Raw;
        long value = 0;
        foreach (var c in text)
        {
            if (c is < '0' or > '9')
            {
                return null;
            }
            value = value * 10 + (c - '0');
            if (value > 1L << 31)
            {
                return null;
            }
        }
        return value;
    }
}
