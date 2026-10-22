using System.Diagnostics;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Xunit;

namespace KiwiCaptcha.Tests;

/// <summary>
/// The sidecar delegation plane: the spawned kiwicaptcha-verifier (the
/// full Rust core with the real execution verifier) fronts an
/// execution-armed challenge; the SDK's fail-closed default refuses it,
/// the sidecar policy delegates and accepts. Skipped where the verifier
/// crate is unavailable.
/// </summary>
public class ExecutionPolicyTests
{
    private static readonly string SidecarBin = Path.GetFullPath(
        Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", "..", "..",
            "target", "debug", "kiwicaptcha-verifier"));
    private const string Secret = "dotnet-sidecar-delegation-0123456789abcdef";

    private static bool SidecarBuilt()
    {
        if (!File.Exists(SidecarBin))
        {
            Build();
        }
        return File.Exists(SidecarBin);
    }

    private static void Build()
    {
        var root = Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", "..", ".."));
        var build = Process.Start(new ProcessStartInfo("cargo",
            "build -q -p kiwicaptcha-verifier --features test-fixtures")
        {
            WorkingDirectory = root,
            RedirectStandardError = true,
        });
        build?.WaitForExit(TimeSpan.FromMinutes(10));
    }

    private static int FreePort()
    {
        var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private record Evidence(ChallengeRecord Record, string Trace, string Digest);

    private static Evidence MintEvidence(string storeDir)
    {
        var helper = Process.Start(new ProcessStartInfo(SidecarBin,
            $"exec-evidence --secret {Secret} --scope login --action login-action --version 1 --store-dir {storeDir}")
        {
            RedirectStandardOutput = true,
        });
        var doc = helper!.StandardOutput.ReadLine();
        helper.WaitForExit(TimeSpan.FromMinutes(1));
        var parsed = JsonDocument.Parse(doc ?? "{}").RootElement;
        var record = ChallengeRecord.Parse(
            Encoding.UTF8.GetBytes(parsed.GetProperty("record").GetRawText()));
        Assert.NotEqual("", record.ExecutionProgram);
        return new Evidence(record,
            parsed.GetProperty("trace").GetString()!,
            parsed.GetProperty("digest").GetString()!);
    }

    [Fact]
    public void FailClosedDefaultThenSidecarDelegation()
    {
        if (!SidecarBuilt())
        {
            return;
        }
        var storeDir = Path.Combine(Path.GetTempPath(), "kiwi-sidecar-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(storeDir);
        var evidence = MintEvidence(storeDir);
        var port = FreePort();

        var sidecar = Process.Start(new ProcessStartInfo(SidecarBin)
        {
            RedirectStandardError = true,
            EnvironmentVariables =
            {
                ["KIWI_LISTEN"] = $"http://127.0.0.1:{port}",
                ["KIWI_SECRET"] = Secret,
                ["KIWI_STORE"] = $"file={storeDir}",
                ["KIWI_BINDING"] = "none",
                ["KIWI_PROFILE"] = "sha16",
            },
        });
        try
        {
            var base_ = $"http://127.0.0.1:{port}";
            var healthy = false;
            using (var client = new HttpClient())
            {
                for (var i = 0; i < 100 && !healthy; i++)
                {
                    try
                    {
                        var answer = client.GetAsync(base_ + "/healthz").GetAwaiter().GetResult();
                        healthy = answer.IsSuccessStatusCode;
                    }
                    catch (Exception)
                    {
                        Thread.Sleep(150);
                    }
                }
            }
            Assert.True(healthy, "the sidecar never answered /healthz");

            var token = SolutionToken.Create(evidence.Record.Nonce,
                Support.SolveSha(evidence.Record.Prefix, evidence.Record.Salt, evidence.Record.TargetBits),
                5000, JsonObject.Of(), evidence.Digest, evidence.Trace, "").Encode();

            // One fresh verifier and record copy per leg: the local
            // one-shot bookkeeping of a refused leg must never shadow
            // the next leg.
            VerifyOutcome Leg(ExecutionPolicy? policy)
            {
                var verifier = Support.NewTestVerifier(new Verifier.Config(),
                    DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                Support.StoreRecord(verifier.Storage(), evidence.Record);
                return verifier.Verify(token, new Verifier.Options
                {
                    SecretKey = Secret,
                    ExpectedScope = "login",
                    ClientIp = Support.TestClientIp,
                    ExecutionPolicy = policy,
                });
            }

            // The fail-closed default: the armed record refuses exactly
            // as before the delegation plane existed.
            var refused = Leg(null);
            Assert.False(refused.Valid);
            Assert.Equal(VerifyError.ExecutionMismatch, refused.Error);

            // The sidecar policy: the delegation accepts.
            var accepted = Leg(new ExecutionPolicy { SidecarUrl = base_ });
            Assert.True(accepted.Valid, $"the delegation must accept: {accepted.Error}");

            // Single-use: the sidecar consumed; a replay never re-accepts.
            var replay = Leg(new ExecutionPolicy { SidecarUrl = base_ });
            Assert.False(replay.Valid);
            Assert.True(replay.Error == VerifyError.AlreadyConsumed
                || replay.Error == VerifyError.RecordNotFound,
                $"the replay answers the consumed vocabulary: {replay.Error}");

            // An unreachable sidecar answers the retry disposition.
            var down = Leg(new ExecutionPolicy { SidecarUrl = "http://127.0.0.1:1", TimeoutMs = 300 });
            Assert.False(down.Valid);
            Assert.Equal(VerifyError.StorageUnavailable, down.Error);
        }
        finally
        {
            try
            {
                sidecar?.Kill(entireProcessTree: true);
            }
            catch (Exception)
            {
                // already gone
            }
            Directory.Delete(storeDir, recursive: true);
        }
    }

    /// <summary>
    /// The delegation body carries every field the sidecar parses —
    /// the parity contract with the Go, Node and Python clients. A
    /// body that dropped expected_request_binding would leave the
    /// sidecar's full-core pass enforcing a weaker posture than the
    /// SDK's own cheap phase.
    /// </summary>
    [Fact]
    public void DelegationBodyCarriesTheSharedVerificationPosture()
    {
        var minimal = ExecutionPolicy.BuildVerifyBody("tok", "login", "", null, false, "");
        Assert.Equal("{\"token\":\"tok\",\"scope\":\"login\"}", minimal);

        var full = ExecutionPolicy.BuildVerifyBody(
            "tok", "login", "203.0.113.7", "", true, "op-abc_1");
        Assert.Equal(
            "{\"token\":\"tok\",\"scope\":\"login\",\"remoteip\":\"203.0.113.7\",\"expected_request_binding\":\"\",\"enforce_telemetry\":true,\"operation_identity\":\"op-abc_1\"}",
            full);

        var bound = ExecutionPolicy.BuildVerifyBody(
            "tok", "login", "203.0.113.7", "req-1:abc.de", false, "");
        Assert.Contains("\"expected_request_binding\":\"req-1:abc.de\"", bound);
        Assert.DoesNotContain("enforce_telemetry", bound);
        Assert.DoesNotContain("operation_identity", bound);

        // Escaping stays canonical: a quote in the binding never
        // forges a second field.
        var escaped = ExecutionPolicy.BuildVerifyBody(
            "tok", "login", "", "a\"b", false, "");
        Assert.Contains("\"expected_request_binding\":\"a\\\"b\"", escaped);
    }
}
