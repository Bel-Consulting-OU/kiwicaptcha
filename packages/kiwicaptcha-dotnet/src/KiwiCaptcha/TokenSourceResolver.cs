namespace KiwiCaptcha;

/// <summary>
/// The shared token authority rule of the server SDKs, pinned by
/// protocol/decision-v1/corpus.json.
///
/// Every non-empty value is collected from all three sources (the
/// x-kiwi-token header, the kiwi_token form field, the kiwi_token query
/// parameter), repeated values included. One distinct value verifies,
/// however many sources carry it. Two or more distinct values refuse
/// the request with token_source_conflict before any candidate is
/// verified, so a trusted gateway's header can never be shadowed by an
/// attacker-controlled body field.
/// </summary>
public static class TokenSourceResolver
{
    /// <summary>The resolution result: one token or one typed failure.</summary>
    public readonly record struct Result(string? Token, VerifyError? Error)
    {
        /// <summary>Whether one agreed token is available.</summary>
        public bool Ok => Error is null;
    }

    /// <summary>Splits merged header lines. The token alphabet has no
    /// comma, so a comma-joined list is a list of distinct candidates.</summary>
    public static IEnumerable<string> SplitHeader(IEnumerable<string> values)
    {
        foreach (var value in values)
        {
            foreach (var part in value.Split(','))
            {
                var trimmed = part.Trim();
                if (trimmed.Length > 0)
                {
                    yield return trimmed;
                }
            }
        }
    }

    /// <summary>Applies the rule to the collected source values.</summary>
    public static Result ResolveValues(
        IEnumerable<string> headerValues,
        IEnumerable<string> formValues,
        IEnumerable<string> queryValues)
    {
        string? token = null;
        foreach (var value in headerValues.Concat(formValues).Concat(queryValues))
        {
            if (string.IsNullOrEmpty(value))
            {
                continue;
            }
            if (token is null)
            {
                token = value;
                continue;
            }
            if (!string.Equals(token, value, StringComparison.Ordinal))
            {
                return new Result(null, VerifyError.TokenSourceConflict);
            }
        }
        return token is null
            ? new Result(null, VerifyError.MalformedToken)
            : new Result(token, null);
    }
}
