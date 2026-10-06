using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using KiwiCaptcha;
using Xunit;

/**
 * The shared client-IP test vectors, asserted against the dotnet
 * resolver. Every SDK runs the same scenarios from
 * tools/client-ip/test-vectors.json, so one request resolves to one
 * canonical IP everywhere.
 */
public class ClientIpResolverTests
{
    private static JsonElement Vectors()
    {
        var path = Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", "..",
            "..", "..", "..", "tools", "client-ip", "test-vectors.json");
        Assert.True(File.Exists(path), $"shared vectors found at {path}");
        return JsonDocument.Parse(File.ReadAllText(path)).RootElement;
    }

    private static List<string>? Lines(JsonElement scenario)
    {
        if (!scenario.TryGetProperty("xff_lines", out var lines) || lines.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        var outLines = new List<string>();
        foreach (var line in lines.EnumerateArray())
        {
            outLines.Add(line.GetString() ?? "");
        }
        return outLines;
    }

    private static List<string> Strings(JsonElement element)
    {
        var outList = new List<string>();
        foreach (var entry in element.EnumerateArray())
        {
            outList.Add(entry.GetString() ?? "");
        }
        return outList;
    }

    [Fact]
    public void SharedCidrCases()
    {
        foreach (var caseRow in Vectors().GetProperty("cidr_cases").EnumerateArray())
        {
            var matched = ClientIpResolver.InTrusted(
                caseRow.GetProperty("ip").GetString(),
                new[] { caseRow.GetProperty("cidr").GetString() });
            Assert.Equal(caseRow.GetProperty("matches").GetBoolean(), matched);
        }
    }

    [Fact]
    public void SharedScenarios()
    {
        foreach (var scenario in Vectors().GetProperty("scenarios").EnumerateArray())
        {
            // The ASP.NET surface sees every header line, so the
            // duplicate scenario asserts the fail-closed expectation.
            var resolved = ClientIpResolver.Resolve(
                scenario.GetProperty("peer").GetString() ?? "",
                Lines(scenario),
                scenario.TryGetProperty("real_ip", out var realIp) && realIp.ValueKind == JsonValueKind.String
                    ? realIp.GetString()
                    : null,
                Strings(scenario.GetProperty("trusted")));
            Assert.Equal(scenario.GetProperty("expected").GetString(), resolved);
        }
    }

    [Fact]
    public void CanonicalIpEdges()
    {
        Assert.Equal("192.0.2.10", ClientIpResolver.CanonicalIp(" 192.0.2.10:4711 "));
        Assert.Equal("2001:db8::1", ClientIpResolver.CanonicalIp("[2001:DB8::1]"));
        Assert.Equal("2001:db8::1", ClientIpResolver.CanonicalIp("[2001:db8::1]:4711"));
        Assert.Equal("198.51.100.5", ClientIpResolver.CanonicalIp("::ffff:198.51.100.5"));
        Assert.Equal("2001:db8::1", ClientIpResolver.CanonicalIp("2001:0db8:0:0:0:0:0:1"));
        Assert.Null(ClientIpResolver.CanonicalIp(""));
        Assert.Null(ClientIpResolver.CanonicalIp("unknown"));
        Assert.Null(ClientIpResolver.CanonicalIp("_obfuscated"));
        Assert.Null(ClientIpResolver.CanonicalIp("[2001:db8::1]:notaport"));
        Assert.Null(ClientIpResolver.CanonicalIp("[2001:db8::1]garbage"));
        Assert.Null(ClientIpResolver.CanonicalIp("1.2.3.4:0"));
        Assert.Null(ClientIpResolver.CanonicalIp("0:1.2.3.4"));
        Assert.Null(ClientIpResolver.CanonicalIp("1.2.3.4.5"));
        Assert.Null(ClientIpResolver.CanonicalIp("3232235521"));
        Assert.Null(ClientIpResolver.CanonicalIp("01.2.3.4"));
    }
}
