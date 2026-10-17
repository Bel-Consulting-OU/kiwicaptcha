using System.Collections.Generic;
using System.IO;
using System.Linq;
using KiwiCaptcha;
using Xunit;

namespace KiwiCaptcha.Tests;

/// <summary>
/// The shared challenge-signature corpus against the .NET verifier.
/// The fixture is expanded by the PHP generator and read byte-for-byte
/// by every hosted SDK suite.
/// </summary>
public sealed class WireSignatureCorpusTests
{
    private static JsonObject Corpus()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "fixtures", "wire-signature-corpus.json");
        return JsonObject.ParseObject(File.ReadAllText(path));
    }

    public static IEnumerable<object[]> Rows()
    {
        var document = Corpus();
        var counts = (JsonObject)document.Get("counts")!;
        var total = int.Parse(((JsonNumber)counts.Get("total")!).Raw);
        Assert.True(total >= 40, "the signature corpus must stay broad");
        foreach (var row in (IEnumerable<object?>)document.Get("vectors")!)
        {
            yield return new object[] { row! };
        }
    }

    private static Dictionary<string, object?> ToMap(JsonObject value)
    {
        var map = new Dictionary<string, object?>();
        foreach (var key in value.Keys)
        {
            var item = value.Get(key);
            map[key] = item switch
            {
                JsonObject nested => ToMap(nested),
                IEnumerable<object?> list => list.Select(entry =>
                    entry is JsonObject nested ? ToMap(nested) : entry).ToList(),
                _ => item,
            };
        }
        return map;
    }

    [Theory]
    [MemberData(nameof(Rows))]
    public void EveryCorpusRowHasTheReferenceVerdict(JsonObject row)
    {
        var id = (string)row.Get("id")!;
        var record = ChallengeRecord.FromMap(ToMap((JsonObject)row.Get("record")!));
        Assert.Equal((string)row.Get("challenge")!, record.Challenge);
        var verified = Canonical.VerifyRecordSignature(
            record,
            (string)row.Get("verify_secret")!,
            (string?)row.Get("verify_tenant"));
        Assert.Equal("accept".Equals(row.Get("expect")), verified);
    }
}
