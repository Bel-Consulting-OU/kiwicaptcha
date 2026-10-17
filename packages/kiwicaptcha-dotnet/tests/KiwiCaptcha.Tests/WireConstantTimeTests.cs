using System.Diagnostics;
using KiwiCaptcha;
using Xunit;

namespace KiwiCaptcha.Tests;

[CollectionDefinition("wire-timing", DisableParallelization = true)]
public sealed class WireTimingCollection
{
}

/// <summary>
/// The constant-time comparison behind the signature and rsw checks,
/// measured against an early-exit comparator that calibrates the noise
/// floor. A position-dependent timing difference on the production
/// comparator fails the test.
/// </summary>
[Collection("wire-timing")]
public sealed class WireConstantTimeTests
{
    private const int Length = 65536;
    private const int Rounds = 25;
    private const int Calls = 20;

    private static bool Leaking(byte[] a, byte[] b)
    {
        for (var i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }
        return true;
    }

    private static double Measure(Func<byte[], byte[], bool> compare, byte[] a, byte[] b)
    {
        for (var i = 0; i < Calls * 20; i++)
        {
            compare(a, b);
        }
        var best = double.PositiveInfinity;
        for (var round = 0; round < Rounds; round++)
        {
            var start = Stopwatch.GetTimestamp();
            for (var call = 0; call < Calls; call++)
            {
                compare(a, b);
            }
            var elapsed = Stopwatch.GetElapsedTime(start).TotalNanoseconds / Calls;
            best = Math.Min(best, elapsed);
        }
        return best;
    }

    [Fact]
    public void TheSecretComparisonDoesNotLeakTheMismatchPosition()
    {
        var first = Enumerable.Repeat((byte)'a', Length).ToArray();
        var head = (byte[])first.Clone();
        head[0] = (byte)'b';
        var last = (byte[])first.Clone();
        last[Length - 1] = (byte)'b';

        var noiseA = Measure(Leaking, first, first);
        var noiseB = Measure(Leaking, first, first);
        var noise = Math.Max(1.0, Math.Abs(noiseA - noiseB));

        var leakFirst = Measure(Leaking, first, head);
        var leakLast = Measure(Leaking, first, last);
        Assert.True(
            leakLast > leakFirst * 2 + 1_000,
            $"the measurement must see an early exit: first={leakFirst}ns last={leakLast}ns noise={noise}ns");

        var realFirst = Measure(Canonical.ConstantTimeEquals, first, head);
        var realLast = Measure(Canonical.ConstantTimeEquals, first, last);
        var realDelta = Math.Abs(realLast - realFirst);
        var budget = Math.Max(Math.Max(noise * 10, realFirst * 0.20), 2_000);
        Assert.True(
            realDelta <= budget,
            $"ConstantTimeEquals leaked the mismatch position: first={realFirst}ns last={realLast}ns noise={noise}ns");
    }
}
