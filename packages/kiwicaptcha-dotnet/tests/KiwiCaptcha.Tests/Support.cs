using System.Numerics;
using System.Text;
using Xunit.Sdk;

namespace KiwiCaptcha.Tests;

/// <summary>
/// Shared test support: the canonical vectors, the corpus paths and
/// the record and token builders every suite composes. The vector
/// values are the Rust-generated protocol corpus the php and Go
/// suites pin, so every implementation holds one acceptance split.
/// </summary>
internal static class Support
{
    internal const string TestSecret = "0123456789abcdef0123456789abcdef";
    internal const string TestClientIp = "203.0.113.7";
    internal const long TestIssuedAt = 1_800_000_000L;
    internal const long TestNow = 1_800_000_100L;
    internal const string TestIpHash = "9c50b8d493de847656a168d0408bd4455994df2fc0b1e94bab5a85d64850034b";

    /// <summary>One entry of the Rust-generated canonical corpus.</summary>
    internal sealed record ProtocolVector(string Nonce, string Challenge, string Salt, string Prefix,
        string Algorithm, int MKib, int T, int P, int TargetBits, int Counter);

    internal static readonly ProtocolVector ShaVector = new(
        "2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=",
        "MmwwSVZoMXh1S05qemNDRHlWK1gwbHJjZU1IbEh2bXFDczVNZER3OHR3MD18bG9naW58"
        + "OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1"
        + "ZDY0ODUwMDM0YnwxODAwMDAwMDAw."
        + "dee1893de8e9f57e974af43ec5b6e7523f7d09cee038a8edd5df59ad2f9248ba",
        "phUfA189G9A5KMv3r+wzLA==",
        "MmwwSVZoMXh1S05qemNDRHlWK1gwbHJjZU1IbEh2bXFDczVNZER3OHR3MD18bG9naW58"
        + "OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1"
        + "ZDY0ODUwMDM0YnwxODAwMDAwMDAw."
        + "dee1893de8e9f57e974af43ec5b6e7523f7d09cee038a8edd5df59ad2f9248ba"
        + "|phUfA189G9A5KMv3r+wzLA==|",
        "sha256", 0, 1, 1, 8, 158);

    internal static readonly ProtocolVector Argon2Vector = new(
        "Sn89Ua2qPftlfNO2K9jZSWB52OpcuYwRD1kf2GDhAX4=",
        "U244OVVhMnFQZnRsZk5PMks5alpTV0I1Mk9wY3VZd1JEMWtmMkdEaEFYND18bG9naW58"
        + "OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1"
        + "ZDY0ODUwMDM0YnwxODAwMDAwMDAw."
        + "2757c7cdabe01a52d31cb91900d64eaaae881dd25353dd79267ce35298b3c239",
        "6HL5BOgvD4ryefTBPNhS8A==",
        "U244OVVhMnFQZnRsZk5PMks5alpTV0I1Mk9wY3VZd1JEMWtmMkdEaEFYND18bG9naW58"
        + "OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1"
        + "ZDY0ODUwMDM0YnwxODAwMDAwMDAw."
        + "2757c7cdabe01a52d31cb91900d64eaaae881dd25353dd79267ce35298b3c239"
        + "|6HL5BOgvD4ryefTBPNhS8A==|",
        "argon2id", 64, 3, 1, 4, 21);

    internal static ChallengeRecord VectorRecord(ProtocolVector vector) => new()
    {
        Nonce = vector.Nonce,
        Scope = "login",
        BindingTag = TestIpHash,
        IssuedAt = TestIssuedAt,
        ExpiresAt = TestIssuedAt + 120,
        Algorithm = vector.Algorithm,
        MKib = vector.MKib,
        T = vector.T,
        P = vector.P,
        TargetBits = vector.TargetBits,
        Salt = vector.Salt,
        Prefix = vector.Prefix,
        Challenge = vector.Challenge,
        MinDurationMs = 0,
        IssuedAtNs = TestIssuedAt * 1_000_000,
        ProtocolVersion = 1,
    };

    internal static string VectorToken(ProtocolVector vector, long counter, int durationMs)
    {
        var telemetry = JsonObject.Of(
            ("wd", false),
            ("me", new JsonNumber("3")),
            ("ke", new JsonNumber("1")),
            ("et", new List<object?> { new JsonNumber("100"), new JsonNumber("250"), new JsonNumber("480") }));
        var effectiveCounter = counter < 0 ? vector.Counter : counter;
        var effectiveDuration = durationMs < 0 ? 5000 : durationMs;
        return SolutionToken.Create(vector.Nonce, effectiveCounter, effectiveDuration,
            telemetry).Encode();
    }

    /// <summary>One mint option set for the record builder.</summary>
    internal sealed class MintOptions
    {
        internal byte[] NonceBytes = DeterministicBytes(32);
        internal byte[] SaltBytes = DeterministicBytes(16);
        internal string Scope = "login";
        internal string BindingIp = "";
        internal string RequestBinding = "";
        internal long IssuedAt = TestIssuedAt;
        internal long Ttl = 120;
        internal string Algorithm = "sha256";
        internal int MKib = 1;
        internal int T = 1;
        internal int TargetBits = 4;
        internal int MinDurationMs = 0;
        internal string Region = "";
        internal int PolicyVersion = 1;
        internal string Issuer = "";
        internal int Kid = 1;
        internal int ProtocolVersion = 2;
        internal string DecoyField = "";
        internal string Hostname = "";
        internal bool MintMetaMac;
        internal string TenantId = "";
        internal string ExecutionProgram = "";
    }

    private static byte[] DeterministicBytes(int n)
    {
        var outBytes = new byte[n];
        for (var i = 0; i < n; i++)
        {
            outBytes[i] = (byte)i;
        }
        return outBytes;
    }

    internal static ChallengeRecord MintRecord(MintOptions options)
    {
        var nonce = Convert.ToBase64String(options.NonceBytes);
        var salt = Convert.ToBase64String(options.SaltBytes);
        var expiresAt = options.IssuedAt + options.Ttl;
        var issuedAtNs = options.IssuedAt * 1_000_000;
        string bindingTag = "";
        if (options.ProtocolVersion == 1)
        {
            bindingTag = Canonical.Hex(Canonical.Sha256(
                Encoding.UTF8.GetBytes(TestSecret + ClientOrDefaultIp(options))));
        }
        else if (options.BindingIp.Length > 0)
        {
            bindingTag = Canonical.BindingTag(nonce, ClientOrDefaultIp(options), TestSecret, options.TenantId);
        }
        var payload = Canonical.CanonicalPayloadChecked(
            options.ProtocolVersion, nonce, options.Scope, bindingTag, options.IssuedAt, expiresAt,
            options.Algorithm, options.MKib, options.T, 1, options.TargetBits, salt,
            options.MinDurationMs, options.Region, options.PolicyVersion, options.RequestBinding,
            options.Issuer, options.Kid, options.DecoyField,
            ExecutionVersionFor(options), ExecutionCommitmentFor(options), "",
            options.MintMetaMac);
        var signature = Canonical.SignPayloadV2(payload, TestSecret, options.TenantId);
        var challenge = Convert.ToBase64String(Encoding.UTF8.GetBytes(payload)) + "." + signature;
        var serverMac = "";
        if (options.MintMetaMac)
        {
            var key = Canonical.ServerStateMacKey(TestSecret, options.TenantId);
            serverMac = Canonical.ServerStateMacRecordMeta(key, challenge, issuedAtNs, options.Hostname);
        }
        return new ChallengeRecord
        {
            Nonce = nonce,
            Scope = options.Scope,
            BindingTag = bindingTag,
            IssuedAt = options.IssuedAt,
            ExpiresAt = expiresAt,
            Algorithm = options.Algorithm,
            MKib = options.MKib,
            T = options.T,
            P = 1,
            TargetBits = options.TargetBits,
            Salt = salt,
            Prefix = challenge + "|" + salt + "|",
            Challenge = challenge,
            MinDurationMs = options.MinDurationMs,
            IssuedAtNs = issuedAtNs,
            ProtocolVersion = options.ProtocolVersion,
            Region = options.Region,
            PolicyVersion = options.PolicyVersion,
            RequestBinding = options.RequestBinding,
            Issuer = options.Issuer,
            Kid = options.Kid,
            Hostname = options.Hostname,
            DecoyField = options.DecoyField,
            ExecutionProgram = options.ExecutionProgram,
            ExecutionVersion = ExecutionVersionFor(options),
            ExecutionCommitment = ExecutionCommitmentFor(options),
            ServerMac = serverMac,
        };
    }

    private static string ClientOrDefaultIp(MintOptions options) =>
        options.BindingIp.Length > 0 ? options.BindingIp : TestClientIp;

    private static int ExecutionVersionFor(MintOptions options) =>
        options.ExecutionProgram.Length == 0 ? 0 : 1;

    private static string ExecutionCommitmentFor(MintOptions options) =>
        options.ExecutionProgram.Length == 0 ? "" : ExecutionProgram.Commitment(options.ExecutionProgram);

    /// <summary>Builds one well-formed v1 program blob: eight add records.</summary>
    internal static string MinimalProgramB64(string scope, string action)
    {
        var scopeBytes = Encoding.UTF8.GetBytes(scope);
        var actionBytes = Encoding.UTF8.GetBytes(action);
        var body = new byte[2 + scopeBytes.Length + actionBytes.Length + 3 + 8 * 9];
        var offset = 0;
        body[offset++] = 1;
        body[offset++] = (byte)scopeBytes.Length;
        Array.Copy(scopeBytes, 0, body, offset, scopeBytes.Length);
        offset += scopeBytes.Length;
        body[offset++] = (byte)actionBytes.Length;
        Array.Copy(actionBytes, 0, body, offset, actionBytes.Length);
        offset += actionBytes.Length;
        body[offset++] = 1;
        body[offset++] = 8;
        for (var i = 0; i < 8; i++)
        {
            body[offset++] = 0;
            body[offset++] = (byte)(i + 1);
            body[offset++] = 0;
            body[offset++] = 0;
            body[offset++] = 0;
            body[offset++] = 1;
            body[offset++] = 0;
            body[offset++] = 0;
            body[offset++] = 0;
        }
        return Convert.ToBase64String(body);
    }

    /// <summary>Searches the sha256 counter to the target difficulty.</summary>
    internal static int SolveSha(string prefix, string saltB64, int targetBits)
    {
        var saltBytes = Convert.FromBase64String(saltB64);
        for (var counter = 0; ; counter++)
        {
            var prefixBytes = Encoding.UTF8.GetBytes(prefix + counter);
            var input = new byte[prefixBytes.Length + saltBytes.Length];
            Array.Copy(prefixBytes, input, prefixBytes.Length);
            Array.Copy(saltBytes, 0, input, prefixBytes.Length, saltBytes.Length);
            if (Canonical.LeadingZeroBits(Canonical.Sha256(input)) >= targetBits)
            {
                return counter;
            }
        }
    }

    /// <summary>Searches the argon2id counter to the target difficulty.</summary>
    internal static int SolveArgon2(string prefix, string saltB64, int targetBits, int t, int mKib)
    {
        var saltBytes = Convert.FromBase64String(saltB64);
        for (var counter = 0; ; counter++)
        {
            var digest = Argon2Id.Derive(Encoding.UTF8.GetBytes(prefix + counter), saltBytes,
                t, mKib, 1, 32, Array.Empty<byte>(), Array.Empty<byte>());
            if (Canonical.LeadingZeroBits(digest) >= targetBits)
            {
                return counter;
            }
        }
    }

    /// <summary>Performs the client's T sequential squarings.</summary>
    internal static string SolveRsw(string prefix, string nonce, BigInteger n, int t)
    {
        var value = Rsw.DeriveBase(prefix, nonce, n);
        for (var i = 0; i < t; i++)
        {
            value = value * value % n;
        }
        return Rsw.ProofHex(value);
    }

    internal static Verifier NewTestVerifier(Verifier.Config config, long now)
    {
        config.NowSecs = () => now;
        return new Verifier(new MemoryStore(), config);
    }

    internal static void StoreRecord(Store.IStoreAdapter store, ChallengeRecord record) =>
        ((Store.IStorer)store).StoreRecord(record);

    internal static void RequireCode(VerifyOutcome outcome, VerifyError expected)
    {
        if (outcome.Valid)
        {
            throw new Xunit.Sdk.XunitException($"expected {expected.Code()}, got a valid outcome");
        }
        if (outcome.Error != expected)
        {
            throw new Xunit.Sdk.XunitException(
                $"expected {expected.Code()}, got {outcome.Code} (detail {outcome.Detail})");
        }
    }

    internal static void RequireValid(VerifyOutcome outcome)
    {
        if (!outcome.Valid)
        {
            throw new Xunit.Sdk.XunitException(
                $"expected a valid outcome, got {outcome.Code} (detail {outcome.Detail})");
        }
    }

    /// <summary>Walks up from the working directory to locate a repository path.</summary>
    internal static string? WalkUp(string relative)
    {
        var dir = Directory.GetCurrentDirectory();
        while (dir != null)
        {
            var candidate = Path.Combine(dir, relative);
            if (File.Exists(candidate))
            {
                return candidate;
            }
            dir = Path.GetDirectoryName(dir);
        }
        return null;
    }

    internal static string ProtocolPathOrSkip(string relative)
    {
        var found = WalkUp(Path.Combine("protocol", relative));
        if (found == null)
        {
            throw new Xunit.Sdk.XunitException($"the shared protocol corpus is not present: {relative}");
        }
        return found;
    }

    internal static string TestdataPath(string relative)
    {
        var found = WalkUp(Path.Combine("testdata", relative));
        if (found == null)
        {
            throw new Xunit.Sdk.XunitException($"testdata fixture not found: {relative}");
        }
        return found;
    }

    internal static Dictionary<string, object?> StrictJson(string path)
    {
        var decoded = global::KiwiCaptcha.StrictJson.Decode(File.ReadAllBytes(path));
        if (decoded is not Dictionary<string, object?> map)
        {
            throw new Xunit.Sdk.XunitException("the fixture must decode to a json object");
        }
        return map;
    }

    /// <summary>The committed PHP-issued golden vector document, shared by the suites.</summary>
    internal static Dictionary<string, object?> GoldenVectors() =>
        StrictJson(TestdataPath(Path.Combine("golden", "golden-php-vectors.json")));

    internal static string GoldenString(Dictionary<string, object?> document, string key) =>
        Convert.ToString(document[key], System.Globalization.CultureInfo.InvariantCulture) ?? "";

    internal static ChallengeRecord GoldenRecord(Dictionary<string, object?> golden)
    {
        var recordMap = (Dictionary<string, object?>)golden["record"];
        return ChallengeRecord.FromMap(recordMap);
    }

    internal static byte[] Filled(int length, int value)
    {
        var outBytes = new byte[length];
        Array.Fill(outBytes, (byte)value);
        return outBytes;
    }

    internal static byte[] Rising16()
    {
        var salt = new byte[16];
        for (var i = 0; i < 16; i++)
        {
            salt[i] = (byte)i;
        }
        return salt;
    }
}
