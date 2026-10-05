namespace KiwiCaptcha.Tests;

/// <summary>Small assertion helpers with context messages.</summary>
internal static class XAssert
{
    internal static void Equal(string expected, string actual, string context)
    {
        if (expected != actual)
        {
            throw new Xunit.Sdk.XunitException($"{context}: expected <{expected}>, actual <{actual}>");
        }
    }

    internal static void Equal(long expected, long actual, string context)
    {
        if (expected != actual)
        {
            throw new Xunit.Sdk.XunitException($"{context}: expected <{expected}>, actual <{actual}>");
        }
    }

    internal static void True(bool condition, string context)
    {
        if (!condition)
        {
            throw new Xunit.Sdk.XunitException(context);
        }
    }
}
