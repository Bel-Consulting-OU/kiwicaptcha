using System.Text;

namespace KiwiCaptcha;

/// <summary>
/// The server side challenge state persisted by the storage backend.
/// The JSON keys mirror the Rust serde schema one to one, so a .NET
/// service and a php or Rust service share the same records.
/// Optional string fields use the empty string as the unset sentinel:
/// the identifier alphabets never admit an empty value on the wire.
/// Protocol versions 1 through 5 are accepted and the protocol versus
/// extension grammar is total.
/// </summary>
public sealed class ChallengeRecord
{
    public string Nonce { get; set; } = "";
    public string Scope { get; set; } = "";
    public string BindingTag { get; set; } = "";
    public long IssuedAt { get; set; }
    public long ExpiresAt { get; set; }
    public string Algorithm { get; set; } = "";
    public int MKib { get; set; }
    public int T { get; set; }
    public int P { get; set; }
    public int TargetBits { get; set; }
    public string Salt { get; set; } = "";
    public string Prefix { get; set; } = "";
    public string Challenge { get; set; } = "";
    public int MinDurationMs { get; set; }

    public long IssuedAtNs { get; set; }
    public int ProtocolVersion { get; set; }
    public string Region { get; set; } = "";
    public int PolicyVersion { get; set; }
    public string RequestBinding { get; set; } = "";
    public string Issuer { get; set; } = "";
    public int Kid { get; set; }
    public string Hostname { get; set; } = "";

    public string DecoyField { get; set; } = "";
    public string ExecutionProgram { get; set; } = "";
    public int ExecutionVersion { get; set; }
    public string ExecutionCommitment { get; set; } = "";
    public string RswModulusSha256 { get; set; } = "";
    public string ServerMac { get; set; } = "";

    /// <summary>A strict wire schema violation.</summary>
    public sealed class MalformedRecordException : Exception
    {
        public MalformedRecordException(string reason)
            : base("kiwicaptcha: malformed record: " + reason)
        {
        }
    }

    /// <summary>The legacy v1 name of the binding tag.</summary>
    public string IpHash() => BindingTag;

    /// <summary>Degrades an unset epoch to the default 1, the Rust reader's view.</summary>
    public int PolicyVersionOrOne() => PolicyVersion == 0 ? 1 : PolicyVersion;

    /// <summary>Degrades an unset key id to the default 1.</summary>
    public int KidOrOne() => Kid == 0 ? 1 : Kid;

    /// <summary>The wire keys of the canonical schema, in emission order.</summary>
    public static readonly IReadOnlyList<string> WireKeys = new[]
    {
        "nonce", "scope", "binding_tag", "issued_at", "expires_at",
        "algorithm", "m_kib", "t", "p", "target_bits", "salt", "prefix",
        "challenge", "min_duration_ms", "issued_at_ns", "protocol_version",
        "attempts_used", "region", "policy_version", "request_binding",
        "issuer", "kid", "hostname", "decoy_field", "execution_program",
        "execution_version", "execution_commitment", "rsw_modulus_sha256",
        "server_mac",
    };

    private static readonly IReadOnlyList<string> RequiredKeys = new[]
    {
        "nonce", "scope", "binding_tag", "issued_at", "expires_at",
        "algorithm", "m_kib", "t", "p", "target_bits", "salt", "prefix",
        "challenge", "min_duration_ms",
    };

    private const long U32Max = 4_294_967_295L;
    private const long U64Max = long.MaxValue;

    /// <summary>
    /// The one protocol versus extension matrix every boundary
    /// applies, so the decoder and the verifier can never disagree
    /// about which records are structurally valid.
    /// </summary>
    public static bool ProtocolExtensionGrammarOk(int protocolVersion, bool decoyPresent,
        bool executionPresent, bool rswIdentityPresent) => protocolVersion switch
    {
        1 => !decoyPresent && !executionPresent && !rswIdentityPresent,
        Kiwi.BaseProtocolVersion => !decoyPresent && !executionPresent,
        Kiwi.DecoyProtocolVersion => decoyPresent && !executionPresent,
        Kiwi.ExecutionProtocolVersion => executionPresent,
        Kiwi.RswIdentityProtocolVersion => rswIdentityPresent,
        _ => false,
    };

    /// <summary>The narrow security identifier alphabet with a length cap.</summary>
    public static bool IsValidIdentifier(string value, int maxBytes)
    {
        if (value.Length == 0 || value.Length > maxBytes)
        {
            return false;
        }
        foreach (var c in value)
        {
            var ok = c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9')
                or '.' or '_' or ':' or '-';
            if (!ok)
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// The honeypot field name alphabet: 1 to 64 bytes of
    /// [A-Za-z0-9_-]. The alphabet excludes the canonical separators,
    /// so a stored name can never alter the structure of the signed
    /// payload.
    /// </summary>
    public static bool IsValidDecoyFieldName(string value)
    {
        if (value.Length == 0 || value.Length > 64)
        {
            return false;
        }
        foreach (var c in value)
        {
            var ok = c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9')
                or '_' or '-';
            if (!ok)
            {
                return false;
            }
        }
        return true;
    }

    internal static bool IsHex64(string value)
    {
        if (value.Length != 64)
        {
            return false;
        }
        foreach (var c in value)
        {
            var ok = c is (>= '0' and <= '9') or (>= 'a' and <= 'f');
            if (!ok)
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Renders the canonical wire schema for storage. The legacy
    /// ip_hash key is never emitted beside binding_tag, and the
    /// optional extension keys are omitted when unset, so unarmed
    /// records keep the exact pre-extension byte format.
    /// </summary>
    public Dictionary<string, object?> ToWireMap()
    {
        var data = new Dictionary<string, object?>
        {
            ["nonce"] = Nonce,
            ["scope"] = Scope,
            ["binding_tag"] = BindingTag,
            ["issued_at"] = IssuedAt,
            ["expires_at"] = ExpiresAt,
            ["algorithm"] = Algorithm,
            ["m_kib"] = MKib,
            ["t"] = T,
            ["p"] = P,
            ["target_bits"] = TargetBits,
            ["salt"] = Salt,
            ["prefix"] = Prefix,
            ["challenge"] = Challenge,
            ["min_duration_ms"] = MinDurationMs,
            ["issued_at_ns"] = IssuedAtNs,
            ["protocol_version"] = ProtocolVersion,
            ["attempts_used"] = 0,
            ["region"] = JsonNullString(Region),
            ["policy_version"] = PolicyVersionOrOne(),
            ["request_binding"] = JsonNullString(RequestBinding),
            ["issuer"] = JsonNullString(Issuer),
            ["kid"] = KidOrOne(),
            ["hostname"] = JsonNullString(Hostname),
        };
        if (DecoyField.Length > 0)
        {
            data["decoy_field"] = DecoyField;
        }
        if (ExecutionProgram.Length > 0)
        {
            data["execution_program"] = ExecutionProgram;
        }
        if (ExecutionVersion != 0)
        {
            data["execution_version"] = ExecutionVersion;
        }
        if (ExecutionCommitment.Length > 0)
        {
            data["execution_commitment"] = ExecutionCommitment;
        }
        if (RswModulusSha256.Length > 0)
        {
            data["rsw_modulus_sha256"] = RswModulusSha256;
        }
        if (ServerMac.Length > 0)
        {
            data["server_mac"] = ServerMac;
        }
        return data;
    }

    private static object? JsonNullString(string value) => value.Length == 0 ? null : value;

    /// <summary>
    /// Emits the wire schema in the canonical key order, with json
    /// null for the always present option fields, byte-compatible
    /// with the php and Rust writers.
    /// </summary>
    public string MarshalJson()
    {
        var sb = new StringBuilder();
        sb.Append('{');
        var first = true;
        void WriteField(string name, string raw)
        {
            if (!first)
            {
                sb.Append(',');
            }
            first = false;
            JsonObject.WriteJsonString(sb, name);
            sb.Append(':').Append(raw);
        }
        string NullableString(string v) => v.Length == 0 ? "null" : JsonString(v);
        static string JsonString(string v)
        {
            var sb2 = new StringBuilder();
            JsonObject.WriteJsonString(sb2, v);
            return sb2.ToString();
        }
        WriteField("nonce", JsonString(Nonce));
        WriteField("scope", JsonString(Scope));
        WriteField("binding_tag", JsonString(BindingTag));
        WriteField("issued_at", IssuedAt.ToString());
        WriteField("expires_at", ExpiresAt.ToString());
        WriteField("algorithm", JsonString(Algorithm));
        WriteField("m_kib", MKib.ToString());
        WriteField("t", T.ToString());
        WriteField("p", P.ToString());
        WriteField("target_bits", TargetBits.ToString());
        WriteField("salt", JsonString(Salt));
        WriteField("prefix", JsonString(Prefix));
        WriteField("challenge", JsonString(Challenge));
        WriteField("min_duration_ms", MinDurationMs.ToString());
        WriteField("issued_at_ns", IssuedAtNs.ToString());
        WriteField("protocol_version", ProtocolVersion.ToString());
        WriteField("attempts_used", "0");
        WriteField("region", NullableString(Region));
        WriteField("policy_version", PolicyVersionOrOne().ToString());
        WriteField("request_binding", NullableString(RequestBinding));
        WriteField("issuer", NullableString(Issuer));
        WriteField("kid", KidOrOne().ToString());
        WriteField("hostname", NullableString(Hostname));
        if (DecoyField.Length > 0)
        {
            WriteField("decoy_field", JsonString(DecoyField));
        }
        if (ExecutionProgram.Length > 0)
        {
            WriteField("execution_program", JsonString(ExecutionProgram));
        }
        if (ExecutionVersion != 0)
        {
            WriteField("execution_version", ExecutionVersion.ToString());
        }
        if (ExecutionCommitment.Length > 0)
        {
            WriteField("execution_commitment", JsonString(ExecutionCommitment));
        }
        if (RswModulusSha256.Length > 0)
        {
            WriteField("rsw_modulus_sha256", JsonString(RswModulusSha256));
        }
        if (ServerMac.Length > 0)
        {
            WriteField("server_mac", JsonString(ServerMac));
        }
        sb.Append('}');
        return sb.ToString();
    }

    /// <summary>
    /// The strict serde mirror parser over stored bytes. It accepts
    /// exactly what the Rust ChallengeRecord parser accepts,
    /// including the legacy ip_hash alias, which must never appear
    /// beside binding_tag. Unknown keys, partial execution triplets,
    /// forbidden protocol and extension combinations, duplicate keys
    /// and out-of-range integers are rejected.
    /// </summary>
    public static ChallengeRecord Parse(byte[] data)
    {
        object? value;
        try
        {
            value = StrictJson.Decode(data);
        }
        catch (ArgumentException e)
        {
            throw new MalformedRecordException(e.Message);
        }
        if (value is not Dictionary<string, object?> decodedMap)
        {
            throw new MalformedRecordException("a record must decode from a json object");
        }
        return FromMap(decodedMap);
    }

    /// <summary>Parses one record from an already decoded strict map.</summary>
    public static ChallengeRecord FromMap(Dictionary<string, object?> data)
    {
        foreach (var key in data.Keys)
        {
            if (key != "ip_hash" && !WireKeys.Contains(key))
            {
                throw new MalformedRecordException("unknown record key: " + key);
            }
        }
        var hasBinding = data.ContainsKey("binding_tag");
        var rawBinding = data.TryGetValue("binding_tag", out var bindingValue) ? bindingValue : null;
        if (data.TryGetValue("ip_hash", out var ipHashValue))
        {
            if (hasBinding)
            {
                throw new MalformedRecordException("binding_tag and ip_hash are duplicate fields");
            }
            rawBinding = ipHashValue;
            hasBinding = true;
        }
        foreach (var field in RequiredKeys)
        {
            if (field == "binding_tag")
            {
                if (!hasBinding)
                {
                    throw new MalformedRecordException("missing record field: " + field);
                }
                continue;
            }
            if (!data.ContainsKey(field))
            {
                throw new MalformedRecordException("missing record field: " + field);
            }
        }
        var nonce = RequireString(data, "nonce");
        var scope = RequireString(data, "scope");
        var bindingTag = WireString(rawBinding, "binding_tag");
        var salt = RequireString(data, "salt");
        var prefix = RequireString(data, "prefix");
        var challenge = RequireString(data, "challenge");
        var issuedAt = WireInt(data["issued_at"], "issued_at", 0, U64Max);
        var expiresAt = WireInt(data["expires_at"], "expires_at", 0, U64Max);
        var minDurationMs = WireInt(data["min_duration_ms"], "min_duration_ms", 0, U64Max);
        long issuedAtNs = 0;
        if (data.ContainsKey("issued_at_ns"))
        {
            issuedAtNs = WireInt(data["issued_at_ns"], "issued_at_ns", 0, U64Max);
        }
        var mKib = WireInt(data["m_kib"], "m_kib", 0, U32Max);
        var t = WireInt(data["t"], "t", 0, U32Max);
        var p = WireInt(data["p"], "p", 0, U32Max);
        var targetBits = WireInt(data["target_bits"], "target_bits", 0, U32Max);
        if (data.ContainsKey("attempts_used"))
        {
            WireInt(data["attempts_used"], "attempts_used", 0, U32Max);
        }
        long policyVersion = 1;
        if (data.ContainsKey("policy_version"))
        {
            policyVersion = WireInt(data["policy_version"], "policy_version", 0, U32Max);
        }
        long kid = 1;
        if (data.ContainsKey("kid"))
        {
            kid = WireInt(data["kid"], "kid", 0, U32Max);
        }
        long protocolVersion = 1;
        if (data.ContainsKey("protocol_version"))
        {
            protocolVersion = WireInt(data["protocol_version"], "protocol_version", 1, Kiwi.MaxProtocolVersion);
        }
        var algorithm = RequireString(data, "algorithm");
        if (algorithm is not ("sha256" or "argon2id" or "rsw"))
        {
            throw new MalformedRecordException("invalid algorithm: " + algorithm);
        }
        var region = OptionalIdentifier(data, "region", 64);
        var requestBinding = OptionalIdentifier(data, "request_binding", 128);
        var issuer = OptionalIdentifier(data, "issuer", 128);
        var decoyField = "";
        if (data.TryGetValue("decoy_field", out var decoyValue) && decoyValue != null)
        {
            decoyField = WireString(decoyValue, "decoy_field");
            if (!IsValidDecoyFieldName(decoyField))
            {
                throw new MalformedRecordException("invalid decoy field name");
            }
        }
        var executionProgram = "";
        if (data.TryGetValue("execution_program", out var programValue) && programValue != null)
        {
            executionProgram = WireString(programValue, "execution_program");
            if (executionProgram.Length > KiwiCaptcha.ExecutionProgram.MaxProgramBase64)
            {
                throw new MalformedRecordException("execution_program exceeds the wire cap");
            }
            if (!KiwiCaptcha.ExecutionProgram.IsValidExecutionProgram(executionProgram))
            {
                throw new MalformedRecordException("invalid execution program");
            }
        }
        var hasExecutionVersion = false;
        long executionVersion = 0;
        if (data.TryGetValue("execution_version", out var versionValue) && versionValue != null)
        {
            hasExecutionVersion = true;
            executionVersion = WireInt(versionValue, "execution_version", 0, 255);
            if (executionVersion < 1 || executionVersion > Kiwi.MaxExecutionVersion)
            {
                throw new MalformedRecordException("invalid execution version: " + executionVersion);
            }
        }
        var hasExecutionCommitment = false;
        var executionCommitment = "";
        if (data.TryGetValue("execution_commitment", out var commitmentValue) && commitmentValue != null)
        {
            hasExecutionCommitment = true;
            executionCommitment = WireString(commitmentValue, "execution_commitment");
            if (!IsHex64(executionCommitment))
            {
                throw new MalformedRecordException("invalid execution commitment");
            }
        }
        if (executionProgram.Length > 0 || hasExecutionVersion || hasExecutionCommitment)
        {
            if (executionProgram.Length == 0 || !hasExecutionVersion || !hasExecutionCommitment)
            {
                throw new MalformedRecordException("incomplete execution fields");
            }
            if (KiwiCaptcha.ExecutionProgram.Commitment(executionProgram) != executionCommitment)
            {
                throw new MalformedRecordException("execution commitment mismatch");
            }
        }
        var rswIdentity = ParseRswIdentity(data, algorithm, protocolVersion);
        if (!ProtocolExtensionGrammarOk((int)protocolVersion, decoyField.Length > 0,
                executionProgram.Length > 0, rswIdentity.Length > 0))
        {
            throw new MalformedRecordException(
                "invalid protocol and extension combination: " + protocolVersion);
        }
        var serverMac = "";
        if (data.TryGetValue("server_mac", out var macValue) && macValue != null)
        {
            serverMac = WireString(macValue, "server_mac");
            if (!IsHex64(serverMac))
            {
                throw new MalformedRecordException("server_mac must be 64 lowercase hex characters");
            }
        }
        var hostname = "";
        if (data.TryGetValue("hostname", out var hostnameValue) && hostnameValue != null)
        {
            hostname = WireString(hostnameValue, "hostname");
            if (hostname.Length == 0)
            {
                throw new MalformedRecordException("hostname must be a non-empty string or null");
            }
            foreach (var c in hostname)
            {
                if (c <= 0x20 || c == 0x7f)
                {
                    throw new MalformedRecordException(
                        "hostname must carry no whitespace or control characters");
                }
            }
        }
        return new ChallengeRecord
        {
            Nonce = nonce,
            Scope = scope,
            BindingTag = bindingTag,
            IssuedAt = issuedAt,
            ExpiresAt = expiresAt,
            Algorithm = algorithm,
            MKib = (int)mKib,
            T = (int)t,
            P = (int)p,
            TargetBits = (int)targetBits,
            Salt = salt,
            Prefix = prefix,
            Challenge = challenge,
            MinDurationMs = (int)minDurationMs,
            IssuedAtNs = issuedAtNs,
            ProtocolVersion = (int)protocolVersion,
            Region = region,
            PolicyVersion = (int)policyVersion,
            RequestBinding = requestBinding,
            Issuer = issuer,
            Kid = (int)kid,
            Hostname = hostname,
            DecoyField = decoyField,
            ExecutionProgram = executionProgram,
            ExecutionVersion = (int)executionVersion,
            ExecutionCommitment = executionCommitment,
            RswModulusSha256 = rswIdentity,
            ServerMac = serverMac,
        };
    }

    private static string ParseRswIdentity(Dictionary<string, object?> data, string algorithm,
        long protocolVersion)
    {
        if (!data.TryGetValue("rsw_modulus_sha256", out var value) || value == null)
        {
            return "";
        }
        var identity = WireString(value, "rsw_modulus_sha256");
        if (!IsHex64(identity))
        {
            throw new MalformedRecordException("rsw_modulus_sha256 must be 64 lowercase hex characters");
        }
        if (algorithm != "rsw")
        {
            throw new MalformedRecordException("rsw_modulus_sha256 may only ride an rsw record");
        }
        if (protocolVersion == 1)
        {
            throw new MalformedRecordException("rsw_modulus_sha256 may not ride the v1 canonical");
        }
        return identity;
    }

    private static string RequireString(Dictionary<string, object?> data, string field)
    {
        if (!data.ContainsKey(field))
        {
            throw new MalformedRecordException("missing record field: " + field);
        }
        return WireString(data[field], field);
    }

    private static string WireString(object? value, string field)
    {
        if (value is not string text)
        {
            throw new MalformedRecordException(field + " must be a string");
        }
        if (text.Length > Kiwi.MaxStringBytes)
        {
            throw new MalformedRecordException(
                field + $" exceeds the {Kiwi.MaxStringBytes} byte wire cap");
        }
        return text;
    }

    private static long WireInt(object? value, string field, long min, long max)
    {
        long parsed;
        switch (value)
        {
            case JsonNumber number:
                try
                {
                    parsed = number.LongValue();
                }
                catch (FormatException)
                {
                    throw new MalformedRecordException(
                        field + $" must be an integer within {min}..{max}");
                }
                break;
            case long l:
                parsed = l;
                break;
            case int i:
                parsed = i;
                break;
            default:
                throw new MalformedRecordException(field + $" must be an integer within {min}..{max}");
        }
        if (parsed < min || parsed > max)
        {
            throw new MalformedRecordException(field + $" must be an integer within {min}..{max}");
        }
        return parsed;
    }

    private static string OptionalIdentifier(Dictionary<string, object?> data, string field, int cap)
    {
        if (!data.TryGetValue(field, out var value) || value == null)
        {
            return "";
        }
        var text = WireString(value, field);
        if (!IsValidIdentifier(text, cap))
        {
            throw new MalformedRecordException(field + " must match the narrow identifier alphabet");
        }
        return text;
    }
}

/// <summary>
/// Envelope encoding helpers: the stored document is emitted in the
/// canonical key order with the compact separators and the ascii
/// escaping of the reference writers, so an envelope written by this
/// SDK is byte-compatible with the php and Python ones.
/// </summary>
public static class WireJson
{
    /// <summary>The runtime marker keys that ride beside the record fields.</summary>
    public static readonly string[] EnvelopeRuntimeKeys =
    {
        "state", "consumed_result", "operation_identity", "resume_owner", "resume_until",
    };

    /// <summary>Encodes one envelope document in the canonical key order.</summary>
    public static string EncodeEnvelope(Dictionary<string, object?> envelope)
    {
        var sb = new StringBuilder();
        sb.Append('{');
        var first = true;
        void Emit(string name)
        {
            if (!envelope.ContainsKey(name))
            {
                return;
            }
            if (!first)
            {
                sb.Append(',');
            }
            first = false;
            JsonObject.WriteJsonString(sb, name);
            sb.Append(':');
            WriteWireValue(sb, envelope[name]);
        }
        foreach (var key in ChallengeRecord.WireKeys)
        {
            Emit(key);
        }
        foreach (var key in EnvelopeRuntimeKeys)
        {
            Emit(key);
        }
        if (!first)
        {
            // Every envelope key must come from the fixed orderings
            // above; a foreign key would silently reorder the document.
            foreach (var name in envelope.Keys)
            {
                if (!ChallengeRecord.WireKeys.Contains(name) && !EnvelopeRuntimeKeys.Contains(name))
                {
                    throw new ArgumentException(
                        "kiwicaptcha: envelope carries a key outside the wire schema: " + name);
                }
            }
        }
        sb.Append('}');
        return sb.ToString();
    }

    private static void WriteWireValue(StringBuilder sb, object? value)
    {
        switch (value)
        {
            case null:
                sb.Append("null");
                break;
            case bool b:
                sb.Append(b ? "true" : "false");
                break;
            case string s:
                JsonObject.WriteJsonString(sb, s);
                break;
            case int i:
                sb.Append(i);
                break;
            case long l:
                sb.Append(l);
                break;
            case JsonNumber n:
                sb.Append(n.Raw);
                break;
            default:
                throw new ArgumentException("kiwicaptcha: envelope value of unsupported type");
        }
    }

    /// <summary>Encodes one json string value.</summary>
    public static string EncodeJsonString(string value)
    {
        var sb = new StringBuilder();
        JsonObject.WriteJsonString(sb, value);
        return sb.ToString();
    }
}
