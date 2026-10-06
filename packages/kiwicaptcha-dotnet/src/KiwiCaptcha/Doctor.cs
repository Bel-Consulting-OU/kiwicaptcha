using System.Security.Cryptography;
using System.Text;

namespace KiwiCaptcha;

/// <summary>
/// Deployment settings: the four-setting quickstart and the verifier
/// factory. Settings carries the deployment inputs the SDK needs at
/// boot: the signing secret, the store url, the accepted scopes and
/// the profile naming the challenge budget the deployment issues.
/// Everything else stays optional.
/// </summary>
public sealed class Settings
{
    /// <summary>The hmac master secret, at least 32 bytes.</summary>
    public string Secret { get; set; } = "";

    /// <summary>A store url: memory:// (the default) or redis://host:port.</summary>
    public string StoreUrl { get; set; } = "memory://";

    /// <summary>The accepted challenge scopes; an empty list accepts any scope.</summary>
    public IReadOnlyList<string> Scopes { get; set; } = Array.Empty<string>();

    /// <summary>The deployment's issuance budget: standard, argon16, argon32 or argon64.</summary>
    public string Profile { get; set; } = "standard";

    /// <summary>Pins the expected deployment region when set.</summary>
    public string Region { get; set; } = "";

    /// <summary>Pins the security-policy epoch when set.</summary>
    public int ExpectedPolicyVersion { get; set; }

    /// <summary>Declares the rollout window below the expected epoch.</summary>
    public int PolicyVersionFloor { get; set; }

    /// <summary>Pins the deployment issuer when set.</summary>
    public string ExpectedIssuer { get; set; } = "";

    /// <summary>Scopes the derived purpose keys when set.</summary>
    public string TenantId { get; set; } = "";

    /// <summary>Opens the bounded v1 migration window.</summary>
    public bool AcceptLegacyV1 { get; set; }

    /// <summary>The named challenge budgets, mirroring the issuance-side profiles.</summary>
    public static readonly IReadOnlyList<string> Profiles =
        new[] { "standard", "argon16", "argon32", "argon64" };

    /// <summary>Reports whether the profile names a shipped budget.</summary>
    public static bool ProfileKnown(string profile) => Profiles.Contains(profile);

    /// <summary>The argon2id rung (m_kib, t, p) each argon profile issues.</summary>
    public static (int MemoryKib, int T, int P)? ProfileArgonParams(string profile) => profile switch
    {
        "argon16" => (16 * 1024, 3, 1),
        "argon32" => (32 * 1024, 3, 1),
        "argon64" => (64 * 1024, 3, 1),
        _ => null,
    };

    /// <summary>
    /// Whether this verifier runtime can recompute the argon2id rung:
    /// inside the process ceilings and the protocol derivation profile
    /// (p == 1, t at least 3).
    /// </summary>
    public static bool RungVerifiable(int memoryKib, int t, int p) =>
        memoryKib >= Kiwi.MinArgonMemoryKib && memoryKib <= Kiwi.MaxArgonMemoryKib
        && t >= Kiwi.MinArgonTime && t <= Kiwi.MaxArgonTime
        && p == 1;

    /// <summary>Wires the settings into a verifier over the store the url selects.</summary>
    public Verifier BuildVerifier()
    {
        if (Encoding.UTF8.GetByteCount(Secret) < Kiwi.MinSecretBytes)
        {
            throw new Canonical.SecretTooShortException();
        }
        if (!ProfileKnown(Profile))
        {
            throw new ArgumentException(
                "kiwicaptcha: the profile must be one of standard, argon16, argon32, argon64");
        }
        // The issuer guard: a profile naming a rung this verifier
        // cannot verify is a loud configuration error, never a silent
        // downgrade.
        var rung = ProfileArgonParams(Profile);
        if (rung is { } r && !RungVerifiable(r.MemoryKib, r.T, r.P))
        {
            throw new ArgumentException(
                $"kiwicaptcha: profile {Profile} issues an argon2id rung (m_kib={r.MemoryKib} t={r.T} p={r.P}) this verifier cannot verify \u2014 refusing to issue it (never silently downgraded)");
        }
        var config = new Verifier.Config
        {
            AcceptLegacyV1 = AcceptLegacyV1,
            Region = Region,
            ExpectedPolicyVersion = ExpectedPolicyVersion,
            PolicyVersionFloor = PolicyVersionFloor,
            ExpectedIssuer = ExpectedIssuer,
            TenantId = TenantId,
        };
        Verifier.ValidateConfig(config);
        var storage = OpenStore(StoreUrl);
        return new Verifier(storage, config);
    }

    /// <summary>
    /// Builds a store adapter from a url. memory:// builds the
    /// in-process store, redis://host:port or rediss:// builds the
    /// shared backend over the shipped wire protocol client, and
    /// sqlite://path builds the file-backed single-node adapter over
    /// Microsoft.Data.Sqlite (the schema and state machine of the php
    /// SqliteStorage). The empty url defaults to memory://.
    /// </summary>
    public static Store.IStoreAdapter OpenStore(string url)
    {
        var scheme = url ?? "";
        var idx = scheme.IndexOf("://", StringComparison.Ordinal);
        var path = "";
        if (idx >= 0)
        {
            scheme = scheme[..idx];
            path = url![(idx + 3)..];
        }
        return scheme.ToLowerInvariant() switch
        {
            "" or "memory" => new MemoryStore(),
            "redis" or "rediss" => new RedisStore(RespClient.Dial(url), Kiwi.EnvelopeDefaultPrefix),
            "sqlite" => new SqliteStore(path == "" ? "kiwicaptcha.sqlite3" : path),
            _ => throw new ArgumentException(
                "kiwicaptcha: unsupported store url scheme: use memory://, redis:// or sqlite://"),
        };
    }
}

/// <summary>
/// The doctor checks: one surface that validates a deployment. The
/// command form lives in the KiwiCaptchaDoctor console project and
/// runs four checks against a deployment description: the settings
/// shape, the secret length, a full store roundtrip (store, find,
/// consume, commit, delete) and the proof budget of the configured
/// profile. Exit code 0 means every check passed.
/// </summary>
public static class Doctor
{
    /// <summary>One named check result.</summary>
    public sealed record Check(string Name, bool Ok, string Detail);

    private sealed record ProfileBudget(string Algorithm, int Bits, int MemoryKib);

    private static ProfileBudget? ProfileBudgetOf(string profile) => profile switch
    {
        "standard" => new ProfileBudget("sha256", 12, 0),
        "argon16" => new ProfileBudget("argon2id", 8, 16),
        "argon32" => new ProfileBudget("argon2id", 6, 32),
        "argon64" => new ProfileBudget("argon2id", 4, 64),
        _ => null,
    };

    /// <summary>Validates the settings shape and the secret length.</summary>
    public static Check CheckSettings(string secret, string profile)
    {
        if (Encoding.UTF8.GetByteCount(secret) < Kiwi.MinSecretBytes)
        {
            return new Check("settings", false,
                $"the secret must be at least {Kiwi.MinSecretBytes} bytes");
        }
        if (Settings.ProfileKnown(profile))
        {
            return new Check("settings", true, "the settings shape is valid");
        }
        return new Check("settings", false,
            "the profile must be one of standard, argon16, argon32, argon64");
    }

    /// <summary>Mints a locally signed self-check record that never leaves the store.</summary>
    public static ChallengeRecord DoctorSelfCheckRecord()
    {
        const string secret = "kiwicaptcha-doctor-self-check-secret-0000";
        var nonceBytes = RandomNumberGenerator.GetBytes(Kiwi.NonceB64Bytes);
        var saltBytes = RandomNumberGenerator.GetBytes(Kiwi.SaltB64Bytes);
        var nonce = Convert.ToBase64String(nonceBytes);
        var salt = Convert.ToBase64String(saltBytes);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var expires = now + 60;
        var payload = Canonical.CanonicalPayload(2, nonce, "doctor", "", now, expires,
            "sha256", 1, 1, 1, 1, salt, 0, "", 1, "", "", 1, "", 0, "", "", false);
        var signature = Canonical.SignPayloadV2(payload, secret, "");
        var challenge = payload + "." + signature;
        return new ChallengeRecord
        {
            Nonce = nonce,
            Scope = "doctor",
            IssuedAt = now,
            ExpiresAt = expires,
            Algorithm = "sha256",
            MKib = 1,
            T = 1,
            P = 1,
            TargetBits = 1,
            Salt = salt,
            Prefix = challenge + "|" + salt + "|",
            Challenge = challenge,
            ProtocolVersion = 2,
            PolicyVersion = 1,
            Kid = 1,
        };
    }

    /// <summary>Opens the store url and runs a full one-shot roundtrip.</summary>
    public static Check CheckStore(string storeUrl)
    {
        Store.IStoreAdapter storage;
        try
        {
            storage = Settings.OpenStore(storeUrl);
        }
        catch (Exception e)
        {
            return new Check("store", false, "the store did not open: " + e.Message);
        }
        ChallengeRecord record;
        try
        {
            record = DoctorSelfCheckRecord();
        }
        catch (Exception e)
        {
            return new Check("store", false, "the self-check record failed: " + e.Message);
        }
        if (storage is not Store.IStorer storer)
        {
            return new Check("store", false, "the store cannot accept records");
        }
        try
        {
            storer.StoreRecord(record);
        }
        catch (Exception e)
        {
            return new Check("store", false, "the store rejected the record: " + e.Message);
        }
        ChallengeRecord? found;
        try
        {
            found = storage.Find(record.Nonce);
        }
        catch (Exception e)
        {
            return new Check("store", false, "the store read failed: " + e.Message);
        }
        if (found == null)
        {
            return new Check("store", false, "the store lost the record");
        }
        Store.ConsumedRecord? consumed;
        try
        {
            consumed = storage.Consume(record.Nonce);
        }
        catch (Exception e)
        {
            return new Check("store", false, "the consume failed: " + e.Message);
        }
        if (consumed == null || !consumed.ConsumedNow)
        {
            return new Check("store", false, "the consume transition did not win");
        }
        bool committed;
        try
        {
            committed = storage.CommitResult(record.Nonce, true, "");
        }
        catch (Exception e)
        {
            return new Check("store", false, "the commit failed: " + e.Message);
        }
        if (!committed)
        {
            return new Check("store", false, "the commit refused");
        }
        bool deleted;
        try
        {
            deleted = storage.Delete(record.Nonce);
        }
        catch (Exception e)
        {
            return new Check("store", false, "the delete failed: " + e.Message);
        }
        if (!deleted)
        {
            return new Check("store", false, "the delete refused");
        }
        return new Check("store", true, "the store roundtrip is one-shot and clean");
    }

    /// <summary>Validates every configured scope.</summary>
    public static Check CheckScopes(IReadOnlyList<string> scopes)
    {
        foreach (var scope in scopes)
        {
            if (!ChallengeRecord.IsValidIdentifier(scope, 128))
            {
                return new Check("scopes", false, "the scope " + scope + " is not a valid identifier");
            }
        }
        if (scopes.Count == 0)
        {
            return new Check("scopes", true, "no scopes configured (every scope is accepted)");
        }
        return new Check("scopes", true, "every scope is a valid identifier: " + string.Join(" ", scopes));
    }

    /// <summary>Measures the proof budget of the configured profile.</summary>
    public static Check CheckProofBudget(string profile)
    {
        var budget = ProfileBudgetOf(profile);
        if (budget == null)
        {
            return new Check("proof_budget", false,
                "the profile must be one of standard, argon16, argon32, argon64");
        }
        var salt = new byte[Kiwi.SaltB64Bytes];
        var started = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (budget.Algorithm == "sha256")
        {
            const string prefix = "doctor|";
            for (var counter = 0; counter <= 2_000_000; counter++)
            {
                var digest = Canonical.Sha256(Encoding.UTF8.GetBytes(prefix + counter));
                if (Canonical.LeadingZeroBits(digest) >= budget.Bits)
                {
                    var elapsed = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - started;
                    return new Check("proof_budget", true,
                        $"sha256 at {budget.Bits} bits solved in {elapsed} ms ({counter} iterations)");
                }
            }
            return new Check("proof_budget", false, "the sha256 budget search ran away");
        }
        Argon2Id.Derive(Encoding.UTF8.GetBytes("doctor"), salt, 3, budget.MemoryKib, 1, 32,
            Array.Empty<byte>(), Array.Empty<byte>());
        var argonElapsed = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - started;
        return new Check("proof_budget", true,
            $"argon2id m={budget.MemoryKib} t=3 derived in {argonElapsed} ms; " +
            $"the {profile} rung accepts {budget.Bits} target bits");
    }

    /// <summary>Executes every check and reports them in order.</summary>
    public static IReadOnlyList<Check> Run(string secret, string storeUrl,
        IReadOnlyList<string> scopes, string profile)
    {
        var results = new List<Check> { CheckSettings(secret, profile) };
        results.Add(CheckStore(storeUrl));
        results.Add(CheckScopes(scopes));
        results.Add(CheckProofBudget(profile));
        return results;
    }
}
