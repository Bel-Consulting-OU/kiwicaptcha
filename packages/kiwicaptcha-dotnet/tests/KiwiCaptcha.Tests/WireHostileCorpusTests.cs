using System.Collections.Generic;
using System.IO;
using KiwiCaptcha;
using Xunit;

namespace KiwiCaptcha.Tests;

/// <summary>
/// The shared hostile wire corpus against the .NET decoder. The fixture
/// is expanded by the PHP generator and read byte-for-byte by every
/// hosted SDK suite; the expected verdicts are the reference decoder's.
/// </summary>
public sealed class WireHostileCorpusTests
{
    private static JsonObject Corpus()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "fixtures", "wire-hostile-corpus.json");
        return JsonObject.ParseObject(File.ReadAllText(path));
    }

    public static IEnumerable<object[]> Rows()
    {
        var document = Corpus();
        var counts = (JsonObject)document.Get("counts")!;
        var total = int.Parse(((JsonNumber)counts.Get("total")!).Raw);
        Assert.True(total >= 100, "the corpus must stay broad");
        var vectors = (IEnumerable<object?>)document.Get("vectors")!;
        foreach (var row in vectors)
        {
            yield return new object[] { row! };
        }
    }

    private static string Classify(string code) => code switch
    {
        SolutionToken.DecodeErrInvalidBase64 => "base64",
        SolutionToken.DecodeErrInvalidUtf8 => "utf8",
        SolutionToken.DecodeErrInvalidCounter or SolutionToken.DecodeErrInvalidCount => "counter",
        SolutionToken.DecodeErrInvalidDur => "duration",
        _ => "malformed",
    };

    private static string Optional(object? value) => value as string ?? "";

    [Fact]
    public void OversizedCounterSpellingIsACeilingRejection()
    {
        // The ceiling rejection outranks a native long overflow: a nine
        // or more digit spelling is a solver-ceiling failure, never a
        // syntax failure.
        const string nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        foreach (var counter in new[]
                 {
                     "9223372036854775808",
                     "18446744073709551616",
                     new string('9', 100),
                 })
        {
            var raw = Convert.ToBase64String(
                System.Text.Encoding.UTF8.GetBytes(nonce + "." + counter + ".2.{}"));
            var error = Assert.Throws<SolutionToken.DecodeException>(() => SolutionToken.Decode(raw));
            Assert.Equal(SolutionToken.DecodeErrInvalidCount, error.Code);
        }
    }

    [Theory]
    [MemberData(nameof(Rows))]
    public void EveryCorpusRowHasTheReferenceVerdict(JsonObject row)
    {
        var id = (string)row.Get("id")!;
        var raw = (string)row.Get("raw")!;
        var expected = (JsonObject)row.Get("expect")!;
        var verdict = (string)expected.Get("verdict")!;

        if (verdict == "accept")
        {
            var token = SolutionToken.Decode(raw);
            Assert.Equal(long.Parse(((JsonNumber)expected.Get("counter")!).Raw), token.Counter);
            Assert.Equal(long.Parse(((JsonNumber)expected.Get("duration_ms")!).Raw), token.DurationMs);
            Assert.Equal(Optional(expected.Get("execution_digest")), token.ExecutionDigest);
            Assert.Equal(Optional(expected.Get("execution_trace")), token.ExecutionTrace);
            Assert.Equal(Optional(expected.Get("rsw_proof")), token.RswProof);
            if (expected.Get("telemetry") is JsonObject telemetry)
            {
                Assert.Equal(telemetry.Encode(), token.Telemetry.Encode());
            }
            if (expected.Get("telemetry_score") is bool telemetryScore)
            {
                Assert.Equal(
                    telemetryScore,
                    Telemetry.ScoreTelemetry(token.Telemetry, token.DurationMs));
            }
            return;
        }

        var error = Assert.Throws<SolutionToken.DecodeException>(() => SolutionToken.Decode(raw));
        var wanted = (string)expected.Get("class")!;
        if (wanted != "any")
        {
            Assert.Equal(wanted, Classify(error.Code));
        }
    }
}
