using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace KiwiCaptcha;

/// <summary>One machine readable failure of the verify path.</summary>
public enum VerifyError
{
    BadSignature,
    Expired,
    WrongScope,
    IpMismatch,
    MissingClientIp,
    WrongRegion,
    WrongIssuer,
    WrongPolicyVersion,
    UnknownKid,
    TooFast,
    InsufficientWork,
    MalformedRecord,
    RecordNotFound,
    MalformedToken,
    UnsupportedArgon2,
    TooManyAttempts,
    TelemetryRejected,
    CapacityExceeded,
    AdmissionUnavailable,
    StorageUnavailable,
    ConsumeIndeterminate,
    AlreadyConsumed,
    RequestBinding,
    ExecutionMismatch,
    UnsupportedRswParams,
}

/// <summary>Extensions over the failure vocabulary: codes and polarity.</summary>
public static class VerifyErrorExtensions
{
    /// <summary>The stable snake_case wire code of this failure.</summary>
    public static string Code(this VerifyError error) => error switch
    {
        VerifyError.BadSignature => "bad_signature",
        VerifyError.Expired => "expired",
        VerifyError.WrongScope => "wrong_scope",
        VerifyError.IpMismatch => "ip_mismatch",
        VerifyError.MissingClientIp => "missing_client_ip",
        VerifyError.WrongRegion => "wrong_region",
        VerifyError.WrongIssuer => "wrong_issuer",
        VerifyError.WrongPolicyVersion => "wrong_policy_version",
        VerifyError.UnknownKid => "unknown_kid",
        VerifyError.TooFast => "too_fast",
        VerifyError.InsufficientWork => "insufficient_work",
        VerifyError.MalformedRecord => "malformed_record",
        VerifyError.RecordNotFound => "record_not_found",
        VerifyError.MalformedToken => "malformed_token",
        VerifyError.UnsupportedArgon2 => "unsupported_argon2_params",
        VerifyError.TooManyAttempts => "too_many_attempts",
        VerifyError.TelemetryRejected => "telemetry_rejected",
        VerifyError.CapacityExceeded => "capacity_exceeded",
        VerifyError.AdmissionUnavailable => "admission_unavailable",
        VerifyError.StorageUnavailable => "storage_unavailable",
        VerifyError.ConsumeIndeterminate => "consume_indeterminate",
        VerifyError.AlreadyConsumed => "already_consumed",
        VerifyError.RequestBinding => "request_binding_mismatch",
        VerifyError.ExecutionMismatch => "execution_mismatch",
        VerifyError.UnsupportedRswParams => "unsupported_rsw_params",
        _ => error.ToString(),
    };

    /// <summary>The operator facing explanation; switch on the code, not this.</summary>
    public static string Description(this VerifyError error) => error switch
    {
        VerifyError.BadSignature => "challenge signature is invalid",
        VerifyError.Expired => "challenge has expired",
        VerifyError.WrongScope => "challenge was issued for a different scope",
        VerifyError.IpMismatch => "challenge was issued to a different client ip",
        VerifyError.MissingClientIp => "challenge is ip-bound but no client ip was supplied",
        VerifyError.WrongRegion => "challenge was issued for a different region",
        VerifyError.WrongIssuer => "challenge was issued by a different deployment",
        VerifyError.WrongPolicyVersion => "challenge was issued under a different security-policy epoch",
        VerifyError.UnknownKid => "unknown signing key id",
        VerifyError.TooFast => "solution arrived faster than the theoretical minimum, server measured",
        VerifyError.InsufficientWork => "solution does not meet the difficulty target",
        VerifyError.MalformedRecord => "stored challenge record is malformed",
        VerifyError.RecordNotFound => "challenge record not found, unknown or already deleted",
        VerifyError.MalformedToken => "solution token is malformed",
        VerifyError.UnsupportedArgon2 => "argon2id parameters exceed the supported process ceilings",
        VerifyError.TooManyAttempts => "too many verification attempts",
        VerifyError.TelemetryRejected => "bot-signal telemetry rejected the solution",
        VerifyError.CapacityExceeded => "verification capacity exceeded, try again shortly",
        VerifyError.AdmissionUnavailable => "verification admission backend unavailable, try again shortly",
        VerifyError.StorageUnavailable => "verification storage backend unavailable, try again shortly",
        VerifyError.ConsumeIndeterminate => "verification storage response indeterminate, the challenge may or may not have been consumed",
        VerifyError.AlreadyConsumed => "the challenge was already consumed by a different logical operation",
        VerifyError.RequestBinding => "the challenge is not bound to the expected application transaction",
        VerifyError.ExecutionMismatch => "the execution digest does not match the expected program trace of the challenge",
        VerifyError.UnsupportedRswParams => "the rsw challenge cannot be verified: this verifier is not configured with the matching rsw trapdoor, or the signed sequential cost is outside the supported bounds",
        _ => error.Code(),
    };

    /// <summary>
    /// Whether this failure is exempt from the one-shot policy. The
    /// exempt set describes the original redemption's circumstances:
    /// the signed expiry, the network binding, the missing client ip,
    /// and the client side telemetry evidence. A consumed record
    /// failing one of them may still resolve through the consumed
    /// branch. Every security verdict stands regardless of a matching
    /// operation identity.
    /// </summary>
    public static bool IsReplayExempt(this VerifyError error) => error is
        VerifyError.Expired or VerifyError.IpMismatch
        or VerifyError.MissingClientIp or VerifyError.TelemetryRejected;
}

/// <summary>
/// The result of one solution verification. A valid outcome exposes
/// the nonce, the consumed record's application transaction binding,
/// the server-measured solve duration and the authenticated honeypot
/// field name. Every field is the zero value on a non-valid outcome.
/// </summary>
public sealed record VerifyOutcome
{
    public bool Valid { get; init; }
    public VerifyError? Error { get; init; }
    public string Detail { get; init; } = "";
    public string Nonce { get; init; } = "";
    public string RequestBinding { get; init; } = "";
    public bool FromStoredResult { get; init; }
    public long SolveDurationMs { get; init; }
    public bool SolveDurationSet { get; init; }
    public string DecoyField { get; init; } = "";

    public static VerifyOutcome ValidOutcome(string nonce, string requestBinding, bool fromStoredResult,
        long solveDurationMs, bool solveDurationSet, string decoyField) => new()
    {
        Valid = true,
        Nonce = nonce,
        RequestBinding = requestBinding,
        FromStoredResult = fromStoredResult,
        SolveDurationMs = solveDurationMs,
        SolveDurationSet = solveDurationSet,
        DecoyField = decoyField,
    };

    public static VerifyOutcome InvalidOutcome(VerifyError error) => new() { Error = error };

    public static VerifyOutcome MalformedTokenOutcome(string detail) => new()
    {
        Error = VerifyError.MalformedToken,
        Detail = detail,
    };

    /// <summary>Whether the proof verified.</summary>
    public bool Ok => Valid;

    /// <summary>The machine readable error code, empty when valid.</summary>
    public string Code => Valid || Error == null ? "" : Error.Value.Code();

    public override string ToString() => Valid
        ? "VerifyOutcome(valid=true, nonce redacted)"
        : $"VerifyOutcome(valid=false, error={(Error == null ? "" : Error.Value.Code())})";
}

/// <summary>
/// The client submitted solution token and its wire grammar, a port
/// of the php SolutionToken. The wire format is
/// base64(nonce "." counter "." duration_ms "." telemetry_json
/// ["." execution_digest[":" execution_trace]] ["." rsw_proof]).
/// The telemetry segment may contain dots, so decoding splits on all
/// dots and peels the optional suffix segments right to left. The rsw
/// final value peels first, exactly when the last segment is 512
/// lowercase hex; the execution evidence segment peels next. Numeric
/// segments are canonical decimal, so each value has exactly one wire
/// spelling in every implementation.
/// </summary>
public sealed record SolutionToken
{
    public const string DecodeErrInvalidBase64 = "invalid_base64";
    public const string DecodeErrInvalidUtf8 = "invalid_utf8";
    public const string DecodeErrMalformed = "malformed";
    public const string DecodeErrInvalidCounter = "invalid_counter";
    public const string DecodeErrInvalidCount = "counter exceeds solver maximum";
    public const string DecodeErrInvalidDur = "invalid_duration";

    /// <summary>A solution token wire grammar failure with its machine reason.</summary>
    public sealed class DecodeException : Exception
    {
        public string Code { get; }

        internal DecodeException(string code)
            : base("kiwicaptcha: token decode error: " + code)
        {
            Code = code;
        }
    }

    public string Nonce { get; init; } = "";
    public long Counter { get; init; }
    public long DurationMs { get; init; }
    public JsonObject Telemetry { get; init; } = new();
    public string ExecutionDigest { get; init; } = "";
    public string ExecutionTrace { get; init; } = "";
    public string RswProof { get; init; } = "";

    /// <summary>The telemetry boolean of the key, or null.</summary>
    public bool? TelemetryBool(string key) => Telemetry.BoolOrNull(key);

    /// <summary>Assembles the canonical wire bytes of this token.</summary>
    public string Encode()
    {
        var plain = new StringBuilder();
        plain.Append(Nonce).Append('.').Append(Counter).Append('.').Append(DurationMs)
            .Append('.').Append(Telemetry.Encode());
        if (ExecutionDigest.Length > 0)
        {
            plain.Append('.').Append(ExecutionDigest);
            if (ExecutionTrace.Length > 0)
            {
                var translated = ExecutionTrace.Replace('+', '-').Replace('/', '_').TrimEnd('=');
                plain.Append(':').Append(translated);
            }
        }
        if (RswProof.Length > 0)
        {
            plain.Append('.').Append(RswProof);
        }
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(plain.ToString()));
    }

    /// <summary>Parses wire bytes and throws a typed DecodeException on any violation.</summary>
    public static SolutionToken Decode(string raw)
    {
        if (raw.Length > Kiwi.MaxTokenBytes)
        {
            throw new DecodeException(DecodeErrMalformed);
        }
        var plainBytes = Canonical.B64CanonicalDecode(raw);
        if (plainBytes == null)
        {
            throw new DecodeException(DecodeErrInvalidBase64);
        }
        var plain = Encoding.UTF8.GetString(plainBytes);
        if (!IsValidUtf8(plainBytes))
        {
            throw new DecodeException(DecodeErrInvalidUtf8);
        }
        var parts = plain.Split('.');
        if (parts.Length < 4)
        {
            throw new DecodeException(DecodeErrMalformed);
        }
        var end = parts.Length;
        string rswProof = "";
        string executionDigest = "";
        string executionTrace = "";
        if (end >= 5 && IsHexN(parts[end - 1], 512))
        {
            rswProof = parts[end - 1];
            end--;
        }
        if (end >= 5)
        {
            var segment = parts[end - 1];
            var colon = segment.IndexOf(':');
            var digestPart = colon >= 0 ? segment[..colon] : segment;
            if (IsHexN(digestPart, 64))
            {
                executionDigest = digestPart;
                if (colon >= 0)
                {
                    executionTrace = segment[(colon + 1)..];
                    if (!CanonicalB64UrlCheck(executionTrace))
                    {
                        throw new DecodeException(DecodeErrMalformed);
                    }
                }
                end--;
            }
        }
        var telemetryStr = string.Join(".", parts[3..end]);
        var nonce = parts[0];
        var counterStr = parts[1];
        var durationStr = parts[2];

        // The nonce is base64 of 32 random bytes: exactly 44 chars with
        // one padding character, pinned by the canonical re-encode
        // check to exactly one wire spelling.
        if (nonce.Length != 44 || !nonce.EndsWith("=") || nonce.Contains('-') || nonce.Contains('_'))
        {
            throw new DecodeException(DecodeErrMalformed);
        }
        var nonceBytes = Canonical.B64CanonicalDecode(nonce);
        if (nonceBytes == null || nonceBytes.Length != Kiwi.NonceB64Bytes)
        {
            throw new DecodeException(DecodeErrMalformed);
        }
        var counter = CanonicalDecimal(counterStr);
        if (counter < 0)
        {
            throw new DecodeException(DecodeErrInvalidCounter);
        }
        if (counterStr.Length > 8 || counter >= Kiwi.MaxSolverCounter)
        {
            throw new DecodeException(DecodeErrInvalidCount);
        }
        var duration = CanonicalDecimal(durationStr);
        if (duration < 0)
        {
            throw new DecodeException(DecodeErrInvalidDur);
        }
        if (duration > Kiwi.MaxDurationMs)
        {
            throw new DecodeException(DecodeErrInvalidDur);
        }
        JsonObject telemetry;
        try
        {
            telemetry = JsonObject.ParseObject(telemetryStr);
        }
        catch (ArgumentException)
        {
            throw new DecodeException(DecodeErrMalformed);
        }
        catch (FormatException)
        {
            throw new DecodeException(DecodeErrMalformed);
        }
        if (executionDigest.Length > 0 && !IsHexN(executionDigest, 64))
        {
            throw new DecodeException(DecodeErrMalformed);
        }
        return new SolutionToken
        {
            Nonce = nonce,
            Counter = counter,
            DurationMs = duration,
            Telemetry = telemetry,
            ExecutionDigest = executionDigest,
            ExecutionTrace = executionTrace,
            RswProof = rswProof,
        };
    }

    /// <summary>Assembles one solution token, the mirror of decode for tests and solvers.</summary>
    public static SolutionToken Create(string nonce, long counter, long durationMs, JsonObject? telemetry,
        string? executionDigest = null, string? executionTrace = null, string? rswProof = null) => new()
    {
        Nonce = nonce,
        Counter = counter,
        DurationMs = durationMs,
        Telemetry = telemetry ?? new JsonObject(),
        ExecutionDigest = executionDigest ?? "",
        ExecutionTrace = executionTrace ?? "",
        RswProof = rswProof ?? "",
    };

    internal static bool IsDigits(string s)
    {
        if (s.Length == 0)
        {
            return false;
        }
        foreach (var c in s)
        {
            if (c is < '0' or > '9')
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>Canonical decimal: digits only, no leading zero unless exactly "0".</summary>
    internal static long CanonicalDecimal(string s)
    {
        if (!IsDigits(s))
        {
            return -1;
        }
        if (s.Length > 1 && s[0] == '0')
        {
            return -1;
        }
        return long.TryParse(s, out var value) ? value : -1;
    }

    internal static bool IsHexN(string s, int n)
    {
        if (s.Length != n)
        {
            return false;
        }
        foreach (var c in s)
        {
            var ok = c is >= '0' and <= '9' or >= 'a' and <= 'f';
            if (!ok)
            {
                return false;
            }
        }
        return true;
    }

    internal static string B64UrlToStandard(string trace)
    {
        var standard = trace.Replace('-', '+').Replace('_', '/');
        var pad = (4 - standard.Length % 4) % 4;
        return standard + new string('=', pad);
    }

    /// <summary>Requires one canonical unpadded base64url spelling, the driver's format.</summary>
    internal static bool CanonicalB64UrlCheck(string trace)
    {
        if (trace.Length == 0 || trace.Length > Kiwi.MaxTraceB64Length)
        {
            return false;
        }
        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(B64UrlToStandard(trace));
        }
        catch (FormatException)
        {
            return false;
        }
        var reencoded = Convert.ToBase64String(decoded).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        return reencoded == trace;
    }

    private static bool IsValidUtf8(byte[] bytes)
    {
        try
        {
            var strict = new UTF8Encoding(false, true);
            strict.GetString(bytes);
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }
}

/// <summary>
/// The signed canonical payload, revision 4, byte-identical with the
/// php Issuer and the Rust canonical_signing_input_v2, plus every
/// signing and binding primitive the verifier composes. Verify is
/// pure-local: the only inputs are the secret-derived keys, the
/// stored bytes and the caller's store adapter.
/// </summary>
public static class Canonical
{
    /// <summary>Raised when exactly one half of the execution commitment pair is presented.</summary>
    public sealed class ExecutionPairException : Exception
    {
        public ExecutionPairException()
            : base("kiwicaptcha: execution_version and execution_commitment must be passed together")
        {
        }
    }

    /// <summary>Raised for an input that is not a plain IPv4 or IPv6 address.</summary>
    public sealed class InvalidIpException : Exception
    {
        public InvalidIpException()
            : base("kiwicaptcha: invalid ip address")
        {
        }
    }

    /// <summary>Raised when a master secret is below the 32-byte entropy floor.</summary>
    public sealed class SecretTooShortException : Exception
    {
        public SecretTooShortException()
            : base($"kiwicaptcha: the master secret must be at least {Kiwi.MinSecretBytes} bytes")
        {
        }
    }

    /// <summary>Builds the revision 4 canonical payload string.</summary>
    public static string CanonicalPayload(int protocolVersion, string nonce, string scope, string bindingTag,
        long issuedAt, long expiresAt, string algorithm, int mKib, int t, int p, int targetBits,
        string salt, int minDurationMs, string region, int policyVersion, string requestBinding,
        string issuer, int kid, string decoyField, int executionVersion, string executionCommitment,
        string rswModulusSha256, bool serverMacCommitted)
    {
        var b = new StringBuilder(256);
        b.Append("v4|").Append(protocolVersion).Append('|').Append(nonce).Append('|')
            .Append(scope).Append('|').Append(bindingTag).Append('|')
            .Append(issuedAt).Append('|').Append(expiresAt).Append('|')
            .Append(algorithm).Append('|').Append(mKib).Append('|')
            .Append(t).Append('|').Append(p).Append('|').Append(targetBits).Append('|')
            .Append(salt).Append('|').Append(minDurationMs).Append('|')
            .Append(region).Append('|').Append(policyVersion).Append('|')
            .Append(requestBinding).Append('|').Append(issuer).Append('|').Append(kid);
        if (!string.IsNullOrEmpty(decoyField))
        {
            b.Append("|d=").Append(decoyField);
        }
        var executionPresent = executionVersion != 0 || !string.IsNullOrEmpty(executionCommitment);
        if (executionPresent)
        {
            b.Append("|e=").Append(executionVersion).Append(',')
                .Append(executionCommitment ?? "");
        }
        if (!string.IsNullOrEmpty(rswModulusSha256))
        {
            b.Append("|r=").Append(rswModulusSha256);
        }
        if (serverMacCommitted)
        {
            b.Append("|m=1");
        }
        return b.ToString();
    }

    /// <summary>CanonicalPayload with the execution pair arity check issuers must respect.</summary>
    public static string CanonicalPayloadChecked(int protocolVersion, string nonce, string scope,
        string bindingTag, long issuedAt, long expiresAt, string algorithm, int mKib, int t, int p,
        int targetBits, string salt, int minDurationMs, string region, int policyVersion,
        string requestBinding, string issuer, int kid, string decoyField, int executionVersion,
        string executionCommitment, string rswModulusSha256, bool serverMacCommitted)
    {
        if ((executionVersion != 0) != (!string.IsNullOrEmpty(executionCommitment)))
        {
            throw new ExecutionPairException();
        }
        return CanonicalPayload(protocolVersion, nonce, scope, bindingTag, issuedAt, expiresAt,
            algorithm, mKib, t, p, targetBits, salt, minDurationMs, region, policyVersion,
            requestBinding, issuer, kid, decoyField, executionVersion, executionCommitment,
            rswModulusSha256, serverMacCommitted);
    }

    /// <summary>
    /// Strict canonical standard base64 decode: the input must be
    /// exactly the canonical padded encoding of its bytes. Returns
    /// null instead of throwing.
    /// </summary>
    public static byte[]? B64CanonicalDecode(string? raw)
    {
        if (raw == null)
        {
            return null;
        }
        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(raw);
        }
        catch (FormatException)
        {
            return null;
        }
        return Convert.ToBase64String(decoded) == raw ? decoded : null;
    }

    /// <summary>The legacy v1 canonical: four untagged segments.</summary>
    public static string LegacyV1Payload(string nonce, string scope, string ipHash, long issuedAt) =>
        $"{nonce}|{scope}|{ipHash}|{issuedAt}";

    /// <summary>The legacy v1 signature: the hex hmac under the master secret directly.</summary>
    public static string SignPayloadV1(string payload, string secretKey) =>
        HmacHex(Encoding.UTF8.GetBytes(secretKey), payload);

    /// <summary>
    /// The v2 signature: the hex hmac under the derived challenge
    /// purpose key. The master secret is never used directly as the
    /// signing key.
    /// </summary>
    public static string SignPayloadV2(string payload, string secretKey, string tenantId) =>
        HmacHex(DerivedKeys.FromMaster(secretKey, tenantId).ChallengeKey, payload);

    /// <summary>Returns the hex tag after the last dot of the challenge string.</summary>
    public static string SignatureFromChallenge(string challenge)
    {
        var dot = challenge.LastIndexOf('.');
        return dot < 0 ? "" : challenge[(dot + 1)..];
    }

    /// <summary>The legacy v1 binding value: the sha256 hex of secret plus ip.</summary>
    public static string HashIpV1(string ip, string secret) =>
        Hex(Sha256(Encoding.UTF8.GetBytes(secret + ip)));

    /// <summary>
    /// The family byte plus the packed bytes of one address: 0x04 plus
    /// the 4-byte form, or 0x06 plus the 16-byte form. An IPv4-mapped
    /// or deprecated IPv4-compatible IPv6 form folds to its 4-byte
    /// form, so two textual spellings of one address produce the same
    /// bytes. A zoned IPv6 literal is rejected.
    /// </summary>
    public static byte[] CanonicalIpFamily(string ip)
    {
        if (ip.Contains('%'))
        {
            throw new InvalidIpException();
        }
        if (ip.Contains(':'))
        {
            var raw = ParseIpv6(ip);
            var allZeroTop = true;
            for (var i = 0; i < 10; i++)
            {
                if (raw[i] != 0)
                {
                    allZeroTop = false;
                    break;
                }
            }
            var mapped = allZeroTop && raw[10] == 0xff && raw[11] == 0xff;
            var compatiblePrefix = allZeroTop && raw[10] == 0 && raw[11] == 0;
            var low = (raw[12] << 24) | (raw[13] << 16) | (raw[14] << 8) | raw[15];
            var compatible = compatiblePrefix && low != 0 && low != 1;
            if (mapped || compatible)
            {
                var out4 = new byte[5];
                out4[0] = 0x04;
                Array.Copy(raw, 12, out4, 1, 4);
                return out4;
            }
            var out16 = new byte[17];
            out16[0] = 0x06;
            Array.Copy(raw, 0, out16, 1, 16);
            return out16;
        }
        var four = ParseIpv4(ip);
        var outBytes = new byte[5];
        outBytes[0] = 0x04;
        Array.Copy(four, 0, outBytes, 1, 4);
        return outBytes;
    }

    /// <summary>
    /// The v2 binding tag: a nonce bound hmac over the canonical ip
    /// bytes, keyed by the ip binding purpose key. The tag is a nonce
    /// bound hmac, never a stable ip derived identifier.
    /// </summary>
    public static string BindingTag(string nonce, string ip, string secret, string tenantId)
    {
        var family = CanonicalIpFamily(ip);
        var keys = DerivedKeys.FromMaster(secret, tenantId);
        using var mac = new HMACSHA256(keys.IpBindKey);
        var domain = Encoding.UTF8.GetBytes(Kiwi.IpBindDomain + "\0" + nonce + "\0");
        var input = new byte[domain.Length + family.Length];
        Array.Copy(domain, input, domain.Length);
        Array.Copy(family, 0, input, domain.Length, family.Length);
        return Hex(mac.ComputeHash(input));
    }

    /// <summary>Constant-time equality over the utf-8 encodings of two strings.</summary>
    public static bool ConstantTimeEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    /// <summary>Constant-time byte array equality.</summary>
    public static bool ConstantTimeEquals(byte[] a, byte[] b) =>
        CryptographicOperations.FixedTimeEquals(a, b);

    /// <summary>Counts the leading zero bits of a digest in big-endian bit order.</summary>
    public static int LeadingZeroBits(byte[] digest)
    {
        var count = 0;
        foreach (var b in digest)
        {
            var by = b;
            if (by == 0)
            {
                count += 8;
                continue;
            }
            while ((by & 0x80) == 0)
            {
                count++;
                by <<= 1;
            }
            break;
        }
        return count;
    }

    /// <summary>
    /// Whether the signed canonical carries the m=1 marker. The
    /// marker is parsed from the challenge string itself, never
    /// inferred from the stored mac presence, so an m=1 record must
    /// carry a valid mac regardless of any stored value.
    /// </summary>
    public static bool SignedCanonicalCommitsRecordMeta(string challenge)
    {
        var dot = challenge.LastIndexOf('.');
        if (dot < 0)
        {
            return false;
        }
        var canonical = B64CanonicalDecode(challenge[..dot]);
        if (canonical == null)
        {
            return false;
        }
        var text = Encoding.UTF8.GetString(canonical);
        return text.StartsWith("v4|") && text.EndsWith("|m=1");
    }

    internal static void MacLengthPrefix(StringBuilder sb, string value) =>
        sb.Append(Encoding.UTF8.GetByteCount(value)).Append(':').Append(value);

    internal static void MacOptional(StringBuilder sb, string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            sb.Append('0');
            return;
        }
        sb.Append("1:");
        MacLengthPrefix(sb, value);
    }

    /// <summary>Assembles the record metadata mac input.</summary>
    public static string RecordMetaInput(string challenge, long issuedAtNs, string hostname)
    {
        var sb = new StringBuilder();
        sb.Append(Kiwi.RecordMetaDomain).Append('\n');
        MacLengthPrefix(sb, challenge);
        sb.Append('\n').Append(issuedAtNs).Append('\n');
        MacOptional(sb, hostname);
        return sb.ToString();
    }

    /// <summary>Assembles the consumed result mac input.</summary>
    public static string ConsumedResultInput(string challenge, bool valid, string binding,
        string operationIdentity)
    {
        var sb = new StringBuilder();
        sb.Append(Kiwi.ConsumedResultDomain).Append('\n');
        MacLengthPrefix(sb, challenge);
        sb.Append('\n').Append(valid ? '1' : '0').Append('\n');
        MacOptional(sb, binding);
        sb.Append('\n');
        MacOptional(sb, operationIdentity);
        return sb.ToString();
    }

    /// <summary>The server state purpose key of the secret and tenant pair.</summary>
    public static byte[] ServerStateMacKey(string secret, string tenantId) =>
        DerivedKeys.FromMaster(secret, tenantId).ServerStateKey;

    /// <summary>Computes the record metadata mac.</summary>
    public static string ServerStateMacRecordMeta(byte[] key, string challenge, long issuedAtNs,
        string hostname) => HmacHex(key, RecordMetaInput(challenge, issuedAtNs, hostname));

    /// <summary>Computes the consumed result mac.</summary>
    public static string ServerStateMacConsumedResult(byte[] key, string challenge, bool valid,
        string binding, string operationIdentity) =>
        HmacHex(key, ConsumedResultInput(challenge, valid, binding, operationIdentity));

    /// <summary>
    /// Recomputes the expected signature of a record and compares it
    /// constant-time. Protocol v1 uses the legacy canonical signed
    /// under the master secret; v2 and above use the full parameter
    /// canonical signed under the derived challenge key. The signed
    /// m=1 marker requires a valid record metadata mac; a record
    /// signed without the marker accepts an absent mac and always
    /// verifies a present one.
    /// </summary>
    public static bool VerifyRecordSignature(ChallengeRecord record, string secretKey, string tenantId)
    {
        var commitsMac = SignedCanonicalCommitsRecordMeta(record.Challenge);
        string expected;
        if (record.ProtocolVersion == 1)
        {
            expected = SignPayloadV1(
                LegacyV1Payload(record.Nonce, record.Scope, record.BindingTag, record.IssuedAt),
                secretKey);
        }
        else
        {
            string payload;
            try
            {
                payload = CanonicalPayloadChecked(
                    record.ProtocolVersion, record.Nonce, record.Scope, record.BindingTag,
                    record.IssuedAt, record.ExpiresAt, record.Algorithm, record.MKib, record.T,
                    record.P, record.TargetBits, record.Salt, record.MinDurationMs, record.Region,
                    record.PolicyVersionOrOne(), record.RequestBinding, record.Issuer,
                    record.KidOrOne(), record.DecoyField, record.ExecutionVersion,
                    record.ExecutionCommitment, record.RswModulusSha256, commitsMac);
            }
            catch (Exception)
            {
                return false;
            }
            expected = SignPayloadV2(payload, secretKey, tenantId);
        }
        if (!ConstantTimeEquals(expected, SignatureFromChallenge(record.Challenge)))
        {
            return false;
        }
        var key = ServerStateMacKey(secretKey, tenantId);
        var computed = ServerStateMacRecordMeta(key, record.Challenge, record.IssuedAtNs, record.Hostname);
        if (commitsMac)
        {
            return record.ServerMac.Length > 0 && ConstantTimeEquals(computed, record.ServerMac);
        }
        return record.ServerMac.Length == 0 || ConstantTimeEquals(computed, record.ServerMac);
    }

    /// <summary>One sha256 digest over the input bytes.</summary>
    public static byte[] Sha256(byte[] input) => SHA256.HashData(input);

    /// <summary>The lowercase hex spelling of the bytes.</summary>
    public static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    /// <summary>The lowercase hex hmac of the input under the key.</summary>
    public static string HmacHex(byte[] key, string input)
    {
        using var mac = new HMACSHA256(key);
        return Hex(mac.ComputeHash(Encoding.UTF8.GetBytes(input)));
    }

    private static byte[] ParseIpv4(string ip)
    {
        var parts = ip.Split('.');
        if (parts.Length != 4)
        {
            throw new InvalidIpException();
        }
        var outBytes = new byte[4];
        for (var i = 0; i < 4; i++)
        {
            var part = parts[i];
            if (part.Length == 0 || part.Length > 3)
            {
                throw new InvalidIpException();
            }
            if (part.Length > 1 && part[0] == '0')
            {
                throw new InvalidIpException();
            }
            var value = 0;
            foreach (var c in part)
            {
                if (c is < '0' or > '9')
                {
                    throw new InvalidIpException();
                }
                value = value * 10 + (c - '0');
                if (value > 255)
                {
                    throw new InvalidIpException();
                }
            }
            outBytes[i] = (byte)value;
        }
        return outBytes;
    }

    private static byte[] ParseIpv6(string ip)
    {
        var groups = new long[8];
        var doubleColon = ip.IndexOf("::", StringComparison.Ordinal);
        if (doubleColon >= 0)
        {
            if (ip.IndexOf("::", doubleColon + 1, StringComparison.Ordinal) >= 0)
            {
                throw new InvalidIpException();
            }
            var left = ip[..doubleColon];
            var right = ip[(doubleColon + 2)..];
            var head = ParseGroupRun(left, groups, 0);
            var rightCount = right.Length == 0 ? 0 : CountGroups(right);
            var tail = 8 - rightCount;
            if (head + rightCount > 7)
            {
                throw new InvalidIpException();
            }
            ParseGroupRun(right, groups, tail);
            return PackGroups(groups);
        }
        if (ip.Contains('.'))
        {
            var sep = ip.LastIndexOf(':');
            var headPart = sep >= 0 ? ip[..sep] : "";
            var fourPart = sep >= 0 ? ip[(sep + 1)..] : ip;
            var four = ParseIpv4(fourPart);
            groups[6] = four[0] * 256L + four[1];
            groups[7] = four[2] * 256L + four[3];
            var head = headPart.Length == 0 ? 6 : ParseGroupRun(headPart, groups, 0);
            if (head != 6)
            {
                throw new InvalidIpException();
            }
            return PackGroups(groups);
        }
        if (ParseGroupRun(ip, groups, 0) != 8)
        {
            throw new InvalidIpException();
        }
        return PackGroups(groups);
    }

    private static int ParseGroupRun(string text, long[] groups, int offset)
    {
        if (text.Length == 0)
        {
            return offset;
        }
        var parts = text.Split(':');
        for (var i = 0; i < parts.Length; i++)
        {
            var part = parts[i];
            var index = offset + i;
            if (part.Contains('.'))
            {
                if (index + 2 > 8)
                {
                    throw new InvalidIpException();
                }
                var four = ParseIpv4(part);
                groups[index] = four[0] * 256L + four[1];
                groups[index + 1] = four[2] * 256L + four[3];
                if (i != parts.Length - 1)
                {
                    throw new InvalidIpException();
                }
                return index + 2;
            }
            if (part.Length == 0 || part.Length > 4)
            {
                throw new InvalidIpException();
            }
            var value = 0;
            foreach (var c in part)
            {
                var digit = HexDigit(c);
                if (digit < 0)
                {
                    throw new InvalidIpException();
                }
                value = value * 16 + digit;
            }
            if (index > 7)
            {
                throw new InvalidIpException();
            }
            groups[index] = value;
        }
        return offset + parts.Length;
    }

    private static int HexDigit(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => -1,
    };

    private static int CountGroups(string text)
    {
        var parts = text.Split(':');
        var count = 0;
        foreach (var part in parts)
        {
            count += part.Contains('.') ? 2 : 1;
        }
        return count;
    }

    private static byte[] PackGroups(long[] groups)
    {
        var outBytes = new byte[16];
        for (var i = 0; i < 8; i++)
        {
            outBytes[i * 2] = (byte)(groups[i] >> 8);
            outBytes[i * 2 + 1] = (byte)groups[i];
        }
        return outBytes;
    }
}

/// <summary>
/// The four purpose keys derived from one master secret,
/// byte-identical with the php DerivedKeys. The construction is the
/// RFC 5869 extract and expand step over sha256:
/// prk = hmac-sha256(salt, master); k_x = hmac-sha256(prk, info + 0x01).
/// </summary>
public sealed record DerivedKeys
{
    public required byte[] ChallengeKey { get; init; }
    public required byte[] IpBindKey { get; init; }
    public required byte[] ResultKey { get; init; }
    public required byte[] ServerStateKey { get; init; }

    private static readonly object CacheLock = new();
    private static readonly Dictionary<string, DerivedKeys> Cache = new();

    /// <summary>
    /// Derives the purpose keys for one master secret, memoized per
    /// distinct master and tenant pair. A tenant id scopes the keys
    /// under the per-tenant root, so tenants sharing a master secret
    /// cannot forge each other's challenges or binding tags.
    /// </summary>
    public static DerivedKeys FromMaster(string master, string? tenantId)
    {
        if (Encoding.UTF8.GetByteCount(master) < Kiwi.MinSecretBytes)
        {
            throw new Canonical.SecretTooShortException();
        }
        var cacheKey = "0\0" + master;
        var salt = Encoding.UTF8.GetBytes(Kiwi.HkdfDeploySalt);
        var material = Encoding.UTF8.GetBytes(master);
        if (!string.IsNullOrEmpty(tenantId))
        {
            var root = HkdfSha256(Encoding.UTF8.GetBytes(master),
                Encoding.UTF8.GetBytes(Kiwi.InfoTenantRootPrefix + tenantId), salt, 32);
            cacheKey = "1\0" + tenantId + "\0" + master;
            salt = Array.Empty<byte>();
            material = root;
        }
        lock (CacheLock)
        {
            if (Cache.TryGetValue(cacheKey, out var cached))
            {
                return cached;
            }
            var derived = new DerivedKeys
            {
                ChallengeKey = HkdfSha256(material, Encoding.UTF8.GetBytes(Kiwi.InfoChallengeSign), salt, 32),
                IpBindKey = HkdfSha256(material, Encoding.UTF8.GetBytes(Kiwi.InfoIpBind), salt, 32),
                ResultKey = HkdfSha256(material, Encoding.UTF8.GetBytes(Kiwi.InfoResultToken), salt, 32),
                ServerStateKey = HkdfSha256(material, Encoding.UTF8.GetBytes(Kiwi.InfoServerState), salt, 32),
            };
            if (Cache.Count >= 64)
            {
                Cache.Clear();
            }
            Cache[cacheKey] = derived;
            return derived;
        }
    }

    /// <summary>One extract and expand step of RFC 5869 with sha256.</summary>
    public static byte[] HkdfSha256(byte[] ikm, byte[] info, byte[] salt, int length)
    {
        var effectiveSalt = salt.Length == 0 ? new byte[32] : salt;
        byte[] prk;
        using (var extract = new HMACSHA256(effectiveSalt))
        {
            prk = extract.ComputeHash(ikm);
        }
        var outBytes = new byte[length];
        byte[] t = Array.Empty<byte>();
        var produced = 0;
        var counter = 1;
        while (produced < length)
        {
            using var expand = new HMACSHA256(prk);
            expand.TransformBlock(t, 0, t.Length, null, 0);
            expand.TransformBlock(info, 0, info.Length, null, 0);
            expand.TransformFinalBlock(new[] { (byte)counter }, 0, 1);
            t = expand.Hash!;
            var take = Math.Min(t.Length, length - produced);
            Array.Copy(t, 0, outBytes, produced, take);
            produced += take;
            counter++;
        }
        return outBytes;
    }
}

/// <summary>Static BigInteger helpers shared by the rsw arithmetic.</summary>
public static class BigInt
{
    /// <summary>Reads unsigned big-endian bytes into a positive BigInteger.</summary>
    public static BigInteger FromUnsignedBigEndian(byte[] raw)
    {
        var little = (byte[])raw.Clone();
        Array.Reverse(little);
        var padded = new byte[little.Length + 1];
        Array.Copy(little, padded, little.Length);
        return new BigInteger(padded);
    }
}
