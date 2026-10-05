using System.Text;

namespace KiwiCaptcha;

/// <summary>
/// The wire constants of the shared server SDK contract. The values
/// are pinned by the protocol corpora every implementation accepts, so
/// the record language stays identical across the languages.
/// </summary>
public static class Kiwi
{
    public const int MinSecretBytes = 32;
    public const int MinExecutionKeyBytes = 32;
    public const int MaxShaTargetBits = 20;
    public const int MaxArgon2TargetBits = 10;
    public const int MinDifficulty = 1;
    public const int MaxDifficulty = 20;
    public const int MaxTtlSecs = 300;
    public const int MinRswT = 10_000;
    public const int MaxRswT = 300_000;
    public const int RswTargetBitsPin = 1;
    public const int MaxStringBytes = 4096;

    public const int BaseProtocolVersion = 2;
    public const int DecoyProtocolVersion = 3;
    public const int ExecutionProtocolVersion = 4;
    public const int RswIdentityProtocolVersion = 5;
    public const int MaxProtocolVersion = 5;

    public const int MaxExecutionVersion = 5;
    public const int MaxClockSkew = 60;
    public const long SkewToleranceUs = 5_000_000;

    public const int MinArgonMemoryKib = 8;
    public const int MaxArgonMemoryKib = 65_536;
    public const int MinArgonTime = 3;
    public const int MaxArgonTime = 16;
    public const int MinParallelism = 1;
    public const int MaxParallelism = 4;

    public const int MaxSolverCounter = 20_000_000;
    public const int MaxDurationMs = 3_600_000;
    public const int NonceB64Bytes = 32;
    public const int SaltB64Bytes = 16;
    public const int MaxTokenBytes = 32_768;
    public const int MaxTraceB64Length = 10_924;
    public const int EnvelopeMaxBytes = 131_072;
    public const string EnvelopeDefaultPrefix = "kiwicaptcha:";
    public const int RedisStorageTtl = 60;

    // Key derivation labels, byte-identical across every SDK.
    public const string HkdfDeploySalt = "kiwicaptcha/deploy-salt/v1";
    public const string InfoChallengeSign = "kiwi/v2/challenge-sign";
    public const string InfoIpBind = "kiwi/v2/ip-bind";
    public const string InfoResultToken = "kiwi/v2/result-token";
    public const string InfoServerState = "kiwi/v2/server-state";
    public const string InfoTenantRootPrefix = "kiwi/v2/tenant/";
    public const string RecordMetaDomain = "kiwi/record-meta/v1";
    public const string ConsumedResultDomain = "kiwi/consumed-result/v1";
    public const string IpBindDomain = "kiwicaptcha/ip-bind/v2";
}

/// <summary>
/// A decoded json number carried as its raw literal text, so an
/// encode of a decoded token re-emits the exact wire spelling instead
/// of a reformatted float.
/// </summary>
public sealed record JsonNumber(string Raw)
{
    public long LongValue()
    {
        if (!long.TryParse(Raw, out var value))
        {
            throw new FormatException("bad json integer: " + Raw);
        }
        return value;
    }

    public int IntValue() => checked((int)LongValue());

    public override string ToString() => Raw;
}

/// <summary>
/// A decoded json object that preserves the wire key order. Duplicate
/// keys keep the first position and the last value, the same
/// resolution the php json decoder applies. The encoder renders the
/// compact separators and the ascii escaping of the reference
/// encoders, so a decoded token encodes back to its exact wire bytes.
/// </summary>
public sealed class JsonObject
{
    private readonly List<string> _keys = new();
    private readonly Dictionary<string, object?> _values = new();

    public void Set(string key, object? value)
    {
        if (!_values.ContainsKey(key))
        {
            _keys.Add(key);
        }
        _values[key] = value;
    }

    public object? Get(string key) => _values.TryGetValue(key, out var value) ? value : null;

    public bool TryGet(string key, out object? value) => _values.TryGetValue(key, out value);

    public bool? BoolOrNull(string key) => _values.TryGetValue(key, out var value) && value is bool b ? b : null;

    public int Size => _keys.Count;

    public IReadOnlyList<string> Keys => _keys;

    public static JsonObject Of(params (string Key, object? Value)[] pairs)
    {
        var obj = new JsonObject();
        foreach (var (key, value) in pairs)
        {
            obj.Set(key, value);
        }
        return obj;
    }

    /// <summary>
    /// Parses one json document that must be an object, preserving
    /// key order and the raw spelling of every number. Duplicate keys
    /// keep the first position and the last value, the reference
    /// telemetry resolution.
    /// </summary>
    public static JsonObject ParseObject(string text)
    {
        if (!IsUtf8Clean(text))
        {
            throw new ArgumentException("telemetry is not valid utf-8");
        }
        var parser = new Parser(text);
        parser.SkipSpace();
        if (parser.Peek() != '{')
        {
            throw new ArgumentException("telemetry must be a json object");
        }
        var obj = parser.ParseObjectBody(0);
        parser.SkipSpace();
        if (parser.Pos <= parser.Last)
        {
            throw new ArgumentException("trailing bytes after the telemetry object");
        }
        return obj;
    }

    /// <summary>Renders the object with the compact reference encoding.</summary>
    public string Encode()
    {
        var sb = new StringBuilder();
        sb.Append('{');
        for (var i = 0; i < _keys.Count; i++)
        {
            if (i > 0)
            {
                sb.Append(',');
            }
            WriteJsonString(sb, _keys[i]);
            sb.Append(':');
            WriteJsonValue(sb, _values[_keys[i]]);
        }
        sb.Append('}');
        return sb.ToString();
    }

    internal static void WriteJsonValue(StringBuilder sb, object? value)
    {
        switch (value)
        {
            case null:
                sb.Append("null");
                break;
            case bool b:
                sb.Append(b ? "true" : "false");
                break;
            case JsonNumber n:
                sb.Append(n.Raw);
                break;
            case string s:
                WriteJsonString(sb, s);
                break;
            case JsonObject o:
                sb.Append(o.Encode());
                break;
            case IReadOnlyList<object> list:
                sb.Append('[');
                for (var i = 0; i < list.Count; i++)
                {
                    if (i > 0)
                    {
                        sb.Append(',');
                    }
                    WriteJsonValue(sb, list[i]);
                }
                sb.Append(']');
                break;
            case IEnumerable<object> enumerable:
                sb.Append('[');
                var first = true;
                foreach (var item in enumerable)
                {
                    if (!first)
                    {
                        sb.Append(',');
                    }
                    first = false;
                    WriteJsonValue(sb, item);
                }
                sb.Append(']');
                break;
            default:
                sb.Append("null");
                break;
        }
    }

    /// <summary>Writes one json string with the reference ascii escaping.</summary>
    public static void WriteJsonString(StringBuilder sb, string value)
    {
        sb.Append('"');
        foreach (var rune in value.EnumerateRunes())
        {
            switch (rune.Value)
            {
                case '"':
                    sb.Append("\\\"");
                    break;
                case '\\':
                    sb.Append("\\\\");
                    break;
                case '\n':
                    sb.Append("\\n");
                    break;
                case '\r':
                    sb.Append("\\r");
                    break;
                case '\t':
                    sb.Append("\\t");
                    break;
                case '\b':
                    sb.Append("\\b");
                    break;
                case '\f':
                    sb.Append("\\f");
                    break;
                default:
                    if (rune.Value < 0x20 || rune.Value > 0x7e)
                    {
                        WriteEscapedRune(sb, rune);
                    }
                    else
                    {
                        sb.Append(rune);
                    }
                    break;
            }
        }
        sb.Append('"');
    }

    private static void WriteEscapedRune(StringBuilder sb, Rune rune)
    {
        if (rune.Value > 0xffff)
        {
            // The utf-16 surrogate pair of the astral code point.
            var high = 0xd800 + ((rune.Value - 0x10000) >> 10);
            var low = 0xdc00 + ((rune.Value - 0x10000) & 0x3ff);
            WriteUnicodeEscape(sb, high);
            WriteUnicodeEscape(sb, low);
            return;
        }
        WriteUnicodeEscape(sb, rune.Value);
    }

    private static void WriteUnicodeEscape(StringBuilder sb, int unit)
    {
        sb.Append("\\u");
        sb.Append(unit.ToString("x4"));
    }

    private static bool IsUtf8Clean(string text)
    {
        // A .NET string is already decoded utf-16; lone surrogates are
        // the one shape that cannot come from a valid utf-8 document.
        for (var i = 0; i < text.Length; i++)
        {
            if (char.IsSurrogate(text[i])
                && (i + 1 >= text.Length || !char.IsSurrogatePair(text[i], text[i + 1])))
            {
                return false;
            }
        }
        return true;
    }

    private sealed class Parser
    {
        internal readonly int Last;
        internal int Pos;
        private readonly string _text;

        internal Parser(string text)
        {
            _text = text;
            Last = text.Length - 1;
        }

        internal char Peek()
        {
            if (Pos > Last)
            {
                throw new ArgumentException("unexpected end of json");
            }
            return _text[Pos];
        }

        internal void SkipSpace()
        {
            while (Pos <= Last)
            {
                var c = _text[Pos];
                if (c is ' ' or '\t' or '\r' or '\n')
                {
                    Pos++;
                }
                else
                {
                    break;
                }
            }
        }

        internal JsonObject ParseObjectBody(int depth)
        {
            if (depth > 32)
            {
                throw new ArgumentException("json nesting too deep");
            }
            Expect('{');
            var obj = new JsonObject();
            SkipSpace();
            if (Peek() == '}')
            {
                Pos++;
                return obj;
            }
            while (true)
            {
                SkipSpace();
                var key = ParseString();
                SkipSpace();
                Expect(':');
                SkipSpace();
                var value = ParseValue(depth + 1);
                if (!obj._values.ContainsKey(key))
                {
                    obj._keys.Add(key);
                }
                obj._values[key] = value;
                SkipSpace();
                var c = Peek();
                if (c == ',')
                {
                    Pos++;
                }
                else if (c == '}')
                {
                    Pos++;
                    return obj;
                }
                else
                {
                    throw new ArgumentException("bad json object separator");
                }
            }
        }

        private object? ParseValue(int depth)
        {
            var c = Peek();
            switch (c)
            {
                case '{':
                    return ParseObjectBody(depth);
                case '[':
                    return ParseArray(depth);
                case '"':
                    return ParseString();
                case 't':
                    ExpectWord("true");
                    return true;
                case 'f':
                    ExpectWord("false");
                    return false;
                case 'n':
                    ExpectWord("null");
                    return null;
                default:
                    return ParseNumber();
            }
        }

        private List<object?> ParseArray(int depth)
        {
            if (depth > 32)
            {
                throw new ArgumentException("json nesting too deep");
            }
            Expect('[');
            var outList = new List<object?>();
            SkipSpace();
            if (Peek() == ']')
            {
                Pos++;
                return outList;
            }
            while (true)
            {
                SkipSpace();
                outList.Add(ParseValue(depth + 1));
                SkipSpace();
                var c = Peek();
                if (c == ',')
                {
                    Pos++;
                }
                else if (c == ']')
                {
                    Pos++;
                    return outList;
                }
                else
                {
                    throw new ArgumentException("bad json array separator");
                }
            }
        }

        private JsonNumber ParseNumber()
        {
            var start = Pos;
            if (Peek() == '-')
            {
                Pos++;
            }
            var digits = false;
            while (Pos <= Last)
            {
                var c = _text[Pos];
                if (c is >= '0' and <= '9')
                {
                    digits = true;
                    Pos++;
                }
                else if (c is '.' or 'e' or 'E' or '+' or '-')
                {
                    Pos++;
                }
                else
                {
                    break;
                }
            }
            if (!digits)
            {
                throw new ArgumentException("bad json number");
            }
            return new JsonNumber(_text[start..Pos]);
        }

        private string ParseString()
        {
            Expect('"');
            var sb = new StringBuilder();
            while (true)
            {
                if (Pos > Last)
                {
                    throw new ArgumentException("unterminated json string");
                }
                var c = _text[Pos++];
                if (c == '"')
                {
                    return sb.ToString();
                }
                if (c != '\\')
                {
                    sb.Append(c);
                    continue;
                }
                var esc = _text[Pos++];
                switch (esc)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        var unit = Convert.ToInt32(_text.Substring(Pos, 4), 16);
                        Pos += 4;
                        if (char.IsHighSurrogate((char)unit) && Pos + 5 <= Last
                            && _text[Pos] == '\\' && _text[Pos + 1] == 'u')
                        {
                            var low = Convert.ToInt32(_text.Substring(Pos + 2, 4), 16);
                            if (char.IsLowSurrogate((char)low))
                            {
                                Pos += 6;
                                sb.Append(char.ConvertFromUtf32(char.ConvertToUtf32((char)unit, (char)low)));
                                continue;
                            }
                        }
                        sb.Append((char)unit);
                        break;
                    default:
                        throw new ArgumentException("bad json escape");
                }
            }
        }

        private void Expect(char c)
        {
            if (Peek() != c)
            {
                throw new ArgumentException("unexpected json byte " + c);
            }
            Pos++;
        }

        private void ExpectWord(string word)
        {
            if (Pos + word.Length > Last + 1 || !_text.AsSpan(Pos).StartsWith(word, StringComparison.Ordinal))
            {
                throw new ArgumentException("bad json literal at " + Pos);
            }
            Pos += word.Length;
        }
    }
}

/// <summary>
/// Strict json decoding shared by the record parser and the stored
/// envelope decoder. Both surfaces follow the serde deny unknown
/// fields rule and reject semantic duplicate keys: a document whose
/// members decode to the same name at any nesting level is ambiguous
/// corruption and is never trusted. Numbers are kept as JsonNumber
/// with their raw spelling, so a stored issued_at_ns never passes
/// through a float.
/// </summary>
public static class StrictJson
{
    public static object? Decode(byte[] data)
    {
        if (data.Length > Kiwi.EnvelopeMaxBytes)
        {
            throw new ArgumentException(
                $"document exceeds the {Kiwi.EnvelopeMaxBytes} byte envelope ceiling");
        }
        var text = System.Text.Encoding.UTF8.GetString(data);
        var parser = new StrictParser(text);
        parser.SkipSpace();
        var value = parser.ParseValue(0);
        parser.SkipSpace();
        if (parser.Pos <= parser.Last)
        {
            throw new ArgumentException("trailing bytes after the json value");
        }
        return value;
    }

    private sealed class StrictParser
    {
        internal readonly int Last;
        internal int Pos;
        private readonly string _text;

        internal StrictParser(string text)
        {
            _text = text;
            Last = text.Length - 1;
        }

        internal char Peek()
        {
            if (Pos > Last)
            {
                throw new ArgumentException("unexpected end of json");
            }
            return _text[Pos];
        }

        internal void SkipSpace()
        {
            while (Pos <= Last)
            {
                var c = _text[Pos];
                if (c is ' ' or '\t' or '\r' or '\n')
                {
                    Pos++;
                }
                else
                {
                    break;
                }
            }
        }

        internal object? ParseValue(int depth)
        {
            var c = Peek();
            switch (c)
            {
                case '{': return ParseObject(depth);
                case '[': return ParseArray(depth);
                case '"': return ParseString();
                case 't':
                    ExpectWord("true");
                    return true;
                case 'f':
                    ExpectWord("false");
                    return false;
                case 'n':
                    ExpectWord("null");
                    return null;
                default: return ParseNumber();
            }
        }

        private Dictionary<string, object?> ParseObject(int depth)
        {
            if (depth > 32)
            {
                throw new ArgumentException("json nesting too deep");
            }
            Expect('{');
            var outMap = new Dictionary<string, object?>();
            SkipSpace();
            if (Peek() == '}')
            {
                Pos++;
                return outMap;
            }
            while (true)
            {
                SkipSpace();
                var key = ParseString();
                if (outMap.ContainsKey(key))
                {
                    throw new ArgumentException("duplicate json key: " + key);
                }
                SkipSpace();
                Expect(':');
                SkipSpace();
                outMap[key] = ParseValue(depth + 1);
                SkipSpace();
                var c = Peek();
                if (c == ',')
                {
                    Pos++;
                }
                else if (c == '}')
                {
                    Pos++;
                    return outMap;
                }
                else
                {
                    throw new ArgumentException("bad json object separator");
                }
            }
        }

        private List<object?> ParseArray(int depth)
        {
            if (depth > 32)
            {
                throw new ArgumentException("json nesting too deep");
            }
            Expect('[');
            var outList = new List<object?>();
            SkipSpace();
            if (Peek() == ']')
            {
                Pos++;
                return outList;
            }
            while (true)
            {
                SkipSpace();
                outList.Add(ParseValue(depth + 1));
                SkipSpace();
                var c = Peek();
                if (c == ',')
                {
                    Pos++;
                }
                else if (c == ']')
                {
                    Pos++;
                    return outList;
                }
                else
                {
                    throw new ArgumentException("bad json array separator");
                }
            }
        }

        private JsonNumber ParseNumber()
        {
            var start = Pos;
            if (Peek() == '-')
            {
                Pos++;
            }
            var digits = false;
            while (Pos <= Last)
            {
                var c = _text[Pos];
                if (c is >= '0' and <= '9')
                {
                    digits = true;
                    Pos++;
                }
                else if (c is '.' or 'e' or 'E' or '+' or '-')
                {
                    Pos++;
                }
                else
                {
                    break;
                }
            }
            if (!digits)
            {
                throw new ArgumentException("bad json number");
            }
            return new JsonNumber(_text[start..Pos]);
        }

        private string ParseString()
        {
            Expect('"');
            var sb = new StringBuilder();
            while (true)
            {
                if (Pos > Last)
                {
                    throw new ArgumentException("unterminated json string");
                }
                var c = _text[Pos++];
                if (c == '"')
                {
                    return sb.ToString();
                }
                if (c != '\\')
                {
                    sb.Append(c);
                    continue;
                }
                var esc = _text[Pos++];
                switch (esc)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        var unit = Convert.ToInt32(_text.Substring(Pos, 4), 16);
                        Pos += 4;
                        if (char.IsHighSurrogate((char)unit) && Pos + 5 <= Last
                            && _text[Pos] == '\\' && _text[Pos + 1] == 'u')
                        {
                            var low = Convert.ToInt32(_text.Substring(Pos + 2, 4), 16);
                            if (char.IsLowSurrogate((char)low))
                            {
                                Pos += 6;
                                sb.Append(char.ConvertFromUtf32(char.ConvertToUtf32((char)unit, (char)low)));
                                continue;
                            }
                        }
                        sb.Append((char)unit);
                        break;
                    default:
                        throw new ArgumentException("bad json escape");
                }
            }
        }

        private void Expect(char c)
        {
            if (Peek() != c)
            {
                throw new ArgumentException("unexpected json byte " + c);
            }
            Pos++;
        }

        private void ExpectWord(string word)
        {
            if (Pos + word.Length > Last + 1 || !_text.AsSpan(Pos).StartsWith(word, StringComparison.Ordinal))
            {
                throw new ArgumentException("bad json literal at " + Pos);
            }
            Pos += word.Length;
        }
    }
}
