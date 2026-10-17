using Xunit;

namespace KiwiCaptcha.Tests;

/// <summary>
/// The shared decision register: protocol/decision-v1/corpus.json. The
/// .NET side asserts every wire code and every authority row against
/// the same table the D3.17 campaign reads.
/// </summary>
public class DecisionCorpusTests
{
    private static Dictionary<string, object?> Corpus() =>
        Support.StrictJson(Support.ProtocolPathOrSkip("decision-v1/corpus.json"));

    [Fact]
    public void EveryWireCodeMapsToItsRegisteredDisposition()
    {
        var corpus = Corpus();
        var codes = (Dictionary<string, object?>)corpus["codes"]!;
        foreach (var (code, want) in codes)
        {
            var error = code.FromCodeOrNull();
            Assert.NotNull(error);
            var decision = Decision.FromOutcome(VerifyOutcome.InvalidOutcome(error!.Value), "");
            Assert.False(decision.Ok, code);
            Assert.True((string)want! == decision.Disposition, $"{code}: {decision.Disposition}");
            Assert.True(code == decision.Error, $"{code}: {decision.Error}");
        }
    }

    [Fact]
    public void TheRetryTableIsExactlyTheFourTransientCodes()
    {
        var corpus = Corpus();
        var registered = ((List<object?>)corpus["retry_codes"]!)
            .Select(value => (string)value!)
            .ToHashSet();
        foreach (var code in registered)
        {
            var decision = Decision.FromOutcome(
                VerifyOutcome.InvalidOutcome(code.FromCodeOrNull()!.Value), "");
            XAssert.Equal(Decision.DispositionRetry, decision.Disposition, code);
        }
        var http = (Dictionary<string, object?>)corpus["http"]!;
        Assert.Equal(200, int.Parse(((JsonNumber)http["allow_status"]!).Raw));
        Assert.Equal(503, int.Parse(((JsonNumber)http["retry_status"]!).Raw));
        var deny = (Dictionary<string, object?>)http["deny_status"]!;
        Assert.Equal(403, int.Parse(((JsonNumber)deny["dotnet"]!).Raw));
    }

    [Fact]
    public void EveryAuthorityRowResolvesUnderRejectOnConflict()
    {
        var authority = (Dictionary<string, object?>)Corpus()["authority"]!;
        Assert.Equal("token_source_conflict", (string)authority["conflict_code"]!);
        Assert.Equal("malformed_token", (string)authority["missing_code"]!);
        foreach (var entry in (List<object?>)authority["matrix"]!)
        {
            var row = (Dictionary<string, object?>)entry!;
            var name = (string)row["case"]!;
            var result = TokenSourceResolver.ResolveValues(
                ((List<object?>)row["header"]!).Select(value => (string)value!),
                ((List<object?>)row["form"]!).Select(value => (string)value!),
                ((List<object?>)row["query"]!).Select(value => (string)value!));
            switch ((string)row["verdict"]!)
            {
                case "verify":
                    Assert.True(result.Ok, name);
                    Assert.True((string)row["token"]! == result.Token, name);
                    break;
                case "conflict":
                    Assert.True(VerifyError.TokenSourceConflict == result.Error, name);
                    Assert.Null(result.Token);
                    break;
                default:
                    Assert.True(VerifyError.MalformedToken == result.Error, name);
                    break;
            }
        }
    }
}
