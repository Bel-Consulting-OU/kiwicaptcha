using System.Numerics;
using System.Text;
using Xunit;

namespace KiwiCaptcha.Tests;

/// <summary>
/// The single conformance entry a CI run can point at: it walks the
/// shared protocol corpora the SDK contract pins, the same corpus the
/// php, Go, Python and JVM suites replay, so behavior cannot drift.
/// </summary>
public class ConformanceTests
{
    private static bool ThrowsDecode(Action action)
    {
        try
        {
            action();
            return false;
        }
        catch (SolutionToken.DecodeException)
        {
            return true;
        }
    }

    private static Verifier.Options Options(string? scope, string? clientIp) => new()
    {
        SecretKey = Support.TestSecret,
        ExpectedScope = scope ?? "",
        ClientIp = clientIp ?? "",
    };

    [Fact]
    public void CanonicalVectorsEndToEnd()
    {
        foreach (var vector in new[] { Support.ShaVector, Support.Argon2Vector })
        {
            var record = Support.VectorRecord(vector);
            Assert.True(Canonical.VerifyRecordSignature(record, Support.TestSecret, ""),
                vector.Algorithm + ": the canonical signature must verify");
            var config = new Verifier.Config { AcceptLegacyV1 = true };
            var verifier = Support.NewTestVerifier(config, Support.TestNow);
            Support.StoreRecord(verifier.Storage(), record);
            var outcome = verifier.Verify(Support.VectorToken(vector, -1, -1),
                Options("login", Support.TestClientIp));
            Support.RequireValid(outcome);
        }
    }

    [Fact]
    public void SolutionTokenBoundaryFixture()
    {
        var fixture = Support.StrictJson(Support.ProtocolPathOrSkip("solution-token-v1/fixtures.json"));
        var accepted = (Dictionary<string, object?>)fixture["accepted"];
        foreach (var entry in accepted)
        {
            var token = SolutionToken.Decode(Convert.ToString(entry.Value));
            XAssert.Equal(Convert.ToString(entry.Value)!, token.Encode(), "accepted " + entry.Key);
        }
        var rejected = (Dictionary<string, object?>)fixture["rejected"];
        foreach (var entry in rejected)
        {
            var raw = Convert.ToString(entry.Value);
            XAssert.True(ThrowsDecode(() => SolutionToken.Decode(raw!)),
                "rejected " + entry.Key);
        }
        var cross = (Dictionary<string, object?>)fixture["cross_language"];
        var crossToken = SolutionToken.Decode(Convert.ToString(cross["encoded"]));
        XAssert.Equal(Convert.ToString(cross["encoded"])!, crossToken.Encode(), "cross_language");
    }

    [Fact]
    public void IpHashVector()
    {
        Assert.Equal(Support.TestIpHash,
            Canonical.Hex(Canonical.Sha256(Encoding.UTF8.GetBytes(Support.TestSecret + Support.TestClientIp))));
    }

    [Fact]
    public void RswIdentityFixture()
    {
        var fixture = Support.StrictJson(Support.ProtocolPathOrSkip("rsw-identity-v1/fixtures.json"));
        var modulus = Convert.ToString(fixture["modulus_n_b64"])!;
        Assert.Equal(Convert.ToString(fixture["rsw_modulus_n_sha256"]), Rsw.Fingerprint(modulus));
        Assert.Equal(Convert.ToString(fixture["legacy_base64_text_sha256"]), Rsw.LegacyIdentity(modulus));
        // The shared trapdoor verifies its own expected proof.
        var lambda = Convert.ToString(fixture["lambda_b64"])!;
        var rsw = Rsw.Of(modulus, lambda);
        var proof = Support.SolveRsw("prefix|", "nonce", rsw.Modulus(), 10000);
        Assert.Equal(rsw.ExpectedProofHex("prefix|", "nonce", 10000), proof);
    }

    [Fact]
    public void OutcomesMappingFixture()
    {
        var fixture = Support.StrictJson(Support.ProtocolPathOrSkip("risk-v1/outcomes-vectors.json"));
        Assert.Equal(Outcomes.OutcomesVersion, ((JsonNumber)fixture["version"]).IntValue());
    }

    [Fact]
    public void PhpIssuedGoldenRecordsVerify()
    {
        var golden = Support.GoldenVectors();
        var records = (List<object?>)golden["records"];
        Assert.True(records.Count >= 7);
        foreach (var item in records)
        {
            var entry = (Dictionary<string, object?>)item!;
            if ("tampered_signature".Equals(Convert.ToString(entry["name"])))
            {
                continue;
            }
            var record = Support.GoldenRecord(entry);
            Assert.True(Canonical.VerifyRecordSignature(record, Support.TestSecret, ""),
                entry["name"] + ": the php signature must verify");
        }
    }

    [Fact]
    public void GoldenCanonicalSpellings()
    {
        var golden = Support.GoldenVectors();
        var canonical = (Dictionary<string, object?>)golden["canonical"];
        var basePayload = Convert.ToString(canonical["base"])!;
        Assert.Equal(Convert.ToString(canonical["signature_hex"]),
            Canonical.SignPayloadV2(basePayload, Support.TestSecret, ""));
        // The tagged segments ride in capability order after the base.
        Assert.Contains("|d=billing_address_line_", Convert.ToString(canonical["v3_decoy"]));
        Assert.Contains("|e=1,aaa", Convert.ToString(canonical["v4_execution"]));
        Assert.Contains("|r=bbb", Convert.ToString(canonical["v5_identity"]));
        Assert.Equal('|', basePayload[2]);
    }

    [Fact]
    public void GoldenServerStateMacs()
    {
        var golden = Support.GoldenVectors();
        var macs = (Dictionary<string, object?>)golden["server_state_mac"];
        var key = Canonical.ServerStateMacKey(Support.TestSecret, "");
        var metaInput = Convert.ToString(macs["record_meta_input"])!.Replace("\\n", "\n");
        var resultInput = Convert.ToString(macs["consumed_result_input"])!.Replace("\\n", "\n");
        Assert.Equal(Convert.ToString(macs["record_meta_hex"]), Canonical.HmacHex(key, metaInput));
        Assert.Equal(Convert.ToString(macs["consumed_result_hex"]), Canonical.HmacHex(key, resultInput));
        Assert.Contains(Kiwi.RecordMetaDomain, metaInput);
        Assert.Contains(Kiwi.ConsumedResultDomain, resultInput);
    }

    [Fact]
    public void ExecutionArmedGoldenStillFailsClosedHere()
    {
        // The shared v4 execution program validates structurally and
        // its commitment matches, but no digest can satisfy the armed
        // binding without the browser-trace walker.
        var mint = new Support.MintOptions { ProtocolVersion = 4, ExecutionProgram = Support.MinimalProgramB64("login", "submit") };
        var record = Support.MintRecord(mint);
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        var token = SolutionToken.Create(record.Nonce,
            Support.SolveSha(record.Prefix, record.Salt, record.TargetBits), 5000,
            new JsonObject(), executionDigest: new string('a', 32) + new string('b', 32)).Encode();
        Support.RequireCode(verifier.Verify(token, Options("login", Support.TestClientIp)),
            VerifyError.ExecutionMismatch);
    }

    [Fact]
    public void RswEndToEndWithTheCommittedTrapdoor()
    {
        var fixture = Support.StrictJson(Support.ProtocolPathOrSkip("rsw-identity-v1/fixtures.json"));
        var modulus = Convert.ToString(fixture["modulus_n_b64"])!;
        var lambda = Convert.ToString(fixture["lambda_b64"])!;
        var config = new Verifier.Config { RswModulusN = modulus, RswLambda = lambda };
        var verifier = Support.NewTestVerifier(config, Support.TestNow);
        var mint = new Support.MintOptions { Algorithm = "rsw", T = 10000, TargetBits = Kiwi.RswTargetBitsPin };
        var record = Support.MintRecord(mint);
        Support.StoreRecord(verifier.Storage(), record);
        var rsw = Rsw.Of(modulus, lambda);
        var proof = Support.SolveRsw(record.Prefix, record.Nonce, rsw.Modulus(), record.T);
        var token = SolutionToken.Create(record.Nonce, 0, 5000,
            JsonObject.Of(("v", new JsonNumber("1"))), rswProof: proof).Encode();
        Support.RequireValid(verifier.Verify(token, Options("login", Support.TestClientIp)));
        // Replay answers already consumed.
        Support.RequireCode(verifier.Verify(token, Options("login", Support.TestClientIp)),
            VerifyError.AlreadyConsumed);
    }

    [Fact]
    public void WireBytesStayUtf8Clean()
    {
        // The token encoder escapes non-ascii telemetry to the exact
        // reference bytes.
        var telemetry = JsonObject.Of(("emoji", "héllo"));
        var token = SolutionToken.Create("2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=", 1, 10, telemetry);
        var encoded = token.Encode();
        var decoded = SolutionToken.Decode(encoded);
        Assert.Equal(token.Encode(), decoded.Encode());
        Assert.Contains("\\u00e9", decoded.Telemetry.Encode());
    }

    [Fact]
    public void BigBearIntegersNeverEnterScientificNotation()
    {
        var big = BigInteger.Parse("1791176126942062");
        Assert.Equal("1791176126942062", big.ToString());
    }
}
