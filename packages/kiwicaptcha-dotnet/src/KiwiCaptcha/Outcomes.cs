namespace KiwiCaptcha;

/// <summary>Helpers over the subject-address dimensions.</summary>
public static class HandleDimensionExtensions
{
    /// <summary>The dimension wire name.</summary>
    public static string Wire(this Outcomes.HandleDimension dimension) => dimension switch
    {
        Outcomes.HandleDimension.Nonce => "nonce",
        Outcomes.HandleDimension.DecisionId => "decisionId",
        Outcomes.HandleDimension.Principal => "principal",
        Outcomes.HandleDimension.Target => "target",
        Outcomes.HandleDimension.Session => "session",
        Outcomes.HandleDimension.Agent => "agent",
        _ => dimension.ToString(),
    };

    /// <summary>Reports the two ledger dimensions, whose entries confirm decisions.</summary>
    public static bool IsLedger(this Outcomes.HandleDimension dimension) =>
        dimension is Outcomes.HandleDimension.Nonce or Outcomes.HandleDimension.DecisionId;

    /// <summary>Reports the four identity dimensions, which carry pseudonyms only.</summary>
    public static bool IsIdentity(this Outcomes.HandleDimension dimension) => !dimension.IsLedger();

    /// <summary>The mark bucket of an identity dimension, null for the ledger ones.</summary>
    public static string? MarkDimension(this Outcomes.HandleDimension dimension) =>
        dimension.IsLedger() ? null : dimension.Wire();
}

/// <summary>
/// The versioned outcomes mapping and its reporting client, a port of
/// packages/kiwicaptcha-risk-php/src/Outcomes. One mapping table
/// resolves each of the eight typed outcomes onto the risk-v1 event
/// channels, the always-on outcome ledger and the long-memory marks.
/// The trust polarity is a table property: exactly the three
/// server-confirmed trust outcomes may subtract risk, and exactly the
/// four abuse outcomes write marks; the two classes are disjoint. The
/// vectors at protocol/risk-v1/outcomes-vectors.json pin the table
/// contents across the languages.
/// </summary>
public static class Outcomes
{
    /// <summary>The mapping table version.</summary>
    public const int OutcomesVersion = 1;

    /// <summary>The typed outcome vocabulary, in table order.</summary>
    public enum Outcome
    {
        ConfirmedLegitimate,
        StepUpCompleted,
        AuthenticationSuccess,
        AuthenticationFailure,
        SpamReported,
        Chargeback,
        AccountBanned,
        FraudConfirmed,
    }

    /// <summary>The typed outcome wire name.</summary>
    public static string Wire(this Outcome outcome) => outcome switch
    {
        Outcome.ConfirmedLegitimate => "confirmedLegitimate",
        Outcome.StepUpCompleted => "stepUpCompleted",
        Outcome.AuthenticationSuccess => "authenticationSuccess",
        Outcome.AuthenticationFailure => "authenticationFailure",
        Outcome.SpamReported => "spamReported",
        Outcome.Chargeback => "chargeback",
        Outcome.AccountBanned => "accountBanned",
        Outcome.FraudConfirmed => "fraudConfirmed",
        _ => outcome.ToString(),
    };

    /// <summary>The risk-v1 event channel values.</summary>
    public const int ChannelConfirmedLegitimate = 12;
    public const int ChannelProtectedActionSuccess = 8;
    public const int ChannelAuthenticationSuccess = 10;
    public const int ChannelAuthenticationFailure = 11;
    public const int ChannelProtectedActionFailure = 9;
    public const int ChannelConfirmedAbuse = 13;

    /// <summary>The subject-address dimensions.</summary>
    public enum HandleDimension
    {
        Nonce,
        DecisionId,
        Principal,
        Target,
        Session,
        Agent,
    }

    /// <summary>The vocabulary order of the dimensions.</summary>
    public static readonly IReadOnlyList<HandleDimension> HandleDimensionOrder = new[]
    {
        HandleDimension.Nonce, HandleDimension.DecisionId, HandleDimension.Principal,
        HandleDimension.Target, HandleDimension.Session, HandleDimension.Agent,
    };

    /// <summary>The four identity dimensions.</summary>
    public static readonly IReadOnlyList<HandleDimension> IdentityDimensions = new[]
    {
        HandleDimension.Principal, HandleDimension.Target,
        HandleDimension.Session, HandleDimension.Agent,
    };

    private static bool IsPseudonym(string? value)
    {
        if (value == null || value.Length != 32)
        {
            return false;
        }
        foreach (var c in value)
        {
            var ok = c is (>= '0' and <= '9') or (>= 'a' and <= 'f');
            if (!ok)
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// The shared key-safety rule for caller-supplied identifiers. A
    /// 32-char lowercase hex id always passes; otherwise the value
    /// must be non-empty and free of control characters, ':' and '}',
    /// the key separator and the hash-tag closing byte.
    /// </summary>
    public static void AssertKeySafeIdentifier(string? value)
    {
        if (IsPseudonym(value))
        {
            return;
        }
        if (string.IsNullOrEmpty(value))
        {
            throw new ArgumentException(
                "kiwicaptcha: identifiers must be a 32-char lowercase hex id or a non-empty value free of control characters, ':' and '}'");
        }
        foreach (var c in value)
        {
            if (c <= 0x1f || c == 0x7f || c == ':' || c == '}')
            {
                throw new ArgumentException(
                    "kiwicaptcha: identifiers must be free of control characters, ':' and '}'");
            }
        }
        // The utf-8 continuation bytes of the reference control set.
        for (var i = 0; i < value.Length - 1; i++)
        {
            if (value[i] == (char)0xc2)
            {
                var next = value[i + 1];
                if (next >= 0x80 && next <= 0x9f)
                {
                    throw new ArgumentException(
                        "kiwicaptcha: identifiers must be free of control characters, ':' and '}'");
                }
            }
        }
    }

    /// <summary>
    /// One subject address of a typed outcome report. The principal,
    /// target and session dimensions carry pseudonyms, never raw
    /// identifiers, so a raw-looking value is rejected at
    /// construction, fail-closed.
    /// </summary>
    public sealed record OutcomeHandle(HandleDimension Dimension, string Id)
    {
        /// <summary>Validates one handle.</summary>
        public static OutcomeHandle Of(HandleDimension dimension, string? identifier)
        {
            var pseudonymOnly = dimension is HandleDimension.Principal
                or HandleDimension.Target or HandleDimension.Session;
            if (pseudonymOnly && !IsPseudonym(identifier))
            {
                throw new ArgumentException(
                    "kiwicaptcha: identity handles must carry the 32-char lowercase hex pseudonym, never a raw identifier");
            }
            if (!pseudonymOnly)
            {
                AssertKeySafeIdentifier(identifier);
            }
            return new OutcomeHandle(dimension, identifier ?? "");
        }
    }

    /// <summary>One immutable table row: channel, ledger and mark behavior.</summary>
    public sealed record OutcomeMapping(
        Outcome Outcome,
        int Channel,
        bool? LedgerLegitimate,
        bool WritesAbuseMark,
        bool ServerConfirmed,
        bool MaySubtractRisk,
        IReadOnlyList<HandleDimension> AcceptedHandles)
    {
        /// <summary>Whether the dimension is reportable for the row.</summary>
        public bool Accepts(HandleDimension dimension) => AcceptedHandles.Contains(dimension);

        /// <summary>The abuse mark the row writes, empty when none.</summary>
        public string MarkKind() => WritesAbuseMark ? Outcome.Wire() : "";

        /// <summary>Whether the row books a ledger entry.</summary>
        public bool HasLedgerAction() => LedgerLegitimate != null;
    }

    private static readonly IReadOnlyDictionary<Outcome, OutcomeMapping> OutcomeTable =
        new Dictionary<Outcome, OutcomeMapping>
        {
            [Outcome.ConfirmedLegitimate] = new(Outcome.ConfirmedLegitimate,
                ChannelConfirmedLegitimate, true, false, true, true, HandleDimensionOrder),
            [Outcome.StepUpCompleted] = new(Outcome.StepUpCompleted,
                ChannelProtectedActionSuccess, null, false, true, true, IdentityDimensions),
            [Outcome.AuthenticationSuccess] = new(Outcome.AuthenticationSuccess,
                ChannelAuthenticationSuccess, null, false, true, true, IdentityDimensions),
            [Outcome.AuthenticationFailure] = new(Outcome.AuthenticationFailure,
                ChannelAuthenticationFailure, null, false, false, false, IdentityDimensions),
            [Outcome.SpamReported] = new(Outcome.SpamReported,
                ChannelProtectedActionFailure, null, true, true, false, IdentityDimensions),
            [Outcome.Chargeback] = new(Outcome.Chargeback,
                ChannelConfirmedAbuse, false, true, true, false, HandleDimensionOrder),
            [Outcome.AccountBanned] = new(Outcome.AccountBanned,
                ChannelConfirmedAbuse, false, true, true, false, HandleDimensionOrder),
            [Outcome.FraudConfirmed] = new(Outcome.FraudConfirmed,
                ChannelConfirmedAbuse, false, true, true, false, HandleDimensionOrder),
        };

    /// <summary>The one versioned mapping table, total over the vocabulary.</summary>
    public sealed class OutcomeMap
    {
        /// <summary>Resolves the row of one outcome.</summary>
        public OutcomeMapping ForOutcome(Outcome outcome)
        {
            if (!OutcomeTable.TryGetValue(outcome, out var row))
            {
                throw new ArgumentException("kiwicaptcha: no outcome mapping row for " + outcome.Wire());
            }
            return row;
        }

        /// <summary>Returns the rows in vocabulary order.</summary>
        public IReadOnlyList<OutcomeMapping> All() =>
            Enum.GetValues<Outcome>().Select(o => OutcomeTable[o]).ToList();
    }

    /// <summary>The outcome of one report: what was booked where.</summary>
    public sealed record OutcomeReceipt(
        Outcome Outcome,
        HandleDimension HandleDimension,
        int Status,
        bool ChannelBooked,
        int MarksWritten,
        int MarkCount,
        string EventId);

    /// <summary>
    /// The injectable dispatch surface of the reporting client. The
    /// shipped memory sink keeps marks and ledger actions in-process;
    /// binding the sink to a shared deployment is a deployment
    /// composition, not a protocol concern.
    /// </summary>
    public interface IOutcomeSink
    {
        int ConfirmOutcome(string decisionId, bool legitimate);

        void RegisterOutcome(string decisionId, long atMs);

        int WriteMark(string dimension, string identifier, string kind, long atMs);

        int ForgetMarks(string dimension, string identifier);

        string RecordOutcomeFeedback(int channel, string idempotencyKey);
    }

    /// <summary>
    /// The in-process sink. Status follows the ledger confirm
    /// contract: 1 confirmed as legitimate, minus 1 confirmed as
    /// abusive, 0 when no ledger entry existed. Marks accumulate per
    /// key.
    /// </summary>
    public sealed class MemoryOutcomeSink : IOutcomeSink
    {
        /// <summary>The deployment namespace of the sink keys.</summary>
        public string Namespace { get; }

        private readonly object _lock = new();
        private readonly Dictionary<string, List<(bool Legitimate, long AtMs)>> _ledger = new();
        private readonly Dictionary<string, List<(string Kind, long AtMs)>> _marks = new();

        /// <summary>Builds the sink under one namespace.</summary>
        public MemoryOutcomeSink(string namespaceId) => Namespace = namespaceId;

        /// <summary>Renders the mark bucket key of one subject.</summary>
        public string MarkKey(string dimension, string identifier) =>
            "mark:{kiwi:" + Namespace + "}:" + dimension + ":" + identifier;

        public int ConfirmOutcome(string decisionId, bool legitimate)
        {
            lock (_lock)
            {
                if (!_ledger.TryGetValue(decisionId, out var entries) || entries.Count == 0)
                {
                    return 0;
                }
                var last = entries[^1].AtMs;
                entries.Add((legitimate, last));
                return legitimate ? 1 : -1;
            }
        }

        public void RegisterOutcome(string decisionId, long atMs)
        {
            lock (_lock)
            {
                if (!_ledger.TryGetValue(decisionId, out var entries))
                {
                    entries = new List<(bool, long)>();
                    _ledger[decisionId] = entries;
                }
                entries.Add((false, atMs));
            }
        }

        public int WriteMark(string dimension, string identifier, string kind, long atMs)
        {
            var key = MarkKey(dimension, identifier);
            lock (_lock)
            {
                if (!_marks.TryGetValue(key, out var entries))
                {
                    entries = new List<(string, long)>();
                    _marks[key] = entries;
                }
                entries.Add((kind, atMs));
            }
            return 1;
        }

        public int ForgetMarks(string dimension, string identifier)
        {
            var key = MarkKey(dimension, identifier);
            lock (_lock)
            {
                if (_marks.TryGetValue(key, out var removed))
                {
                    _marks.Remove(key);
                    return removed.Count;
                }
                return 0;
            }
        }

        public string RecordOutcomeFeedback(int channel, string idempotencyKey) => idempotencyKey;

        /// <summary>Lists the live marks of one subject, for tests.</summary>
        public IReadOnlyList<string> MarksOf(string dimension, string identifier)
        {
            lock (_lock)
            {
                if (_marks.TryGetValue(MarkKey(dimension, identifier), out var entries))
                {
                    return entries.Select(e => e.Kind).ToList();
                }
                return Array.Empty<string>();
            }
        }
    }

    /// <summary>The typed outcome reporter, mirroring the php KiwiOutcomes.</summary>
    public sealed class OutcomesClient
    {
        private readonly IOutcomeSink _sink;
        private readonly Func<long> _time;

        /// <summary>Binds the reporter to a sink over the wall clock.</summary>
        public OutcomesClient(IOutcomeSink sink) : this(sink, () => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())
        {
        }

        /// <summary>Binds the reporter to a sink and a millisecond clock.</summary>
        public OutcomesClient(IOutcomeSink sink, Func<long> time)
        {
            _sink = sink;
            _time = time;
        }

        /// <summary>
        /// Books one typed outcome onto one handle. The mapping
        /// decides acceptance, the ledger action and the abuse mark,
        /// so a report can never bypass the table's trust polarity.
        /// atMs 0 means now.
        /// </summary>
        public OutcomeReceipt Report(Outcome outcome, OutcomeHandle handle, string idempotencyKey, long atMs)
        {
            var mapping = new OutcomeMap().ForOutcome(outcome);
            if (!mapping.Accepts(handle.Dimension))
            {
                throw new ArgumentException("kiwicaptcha: outcome " + outcome.Wire()
                    + " cannot be reported on a " + handle.Dimension.Wire() + " handle");
            }
            var at = atMs != 0 ? atMs : _time();
            if (handle.Dimension.IsLedger())
            {
                var status = 0;
                if (mapping.HasLedgerAction())
                {
                    status = _sink.ConfirmOutcome(handle.Id, mapping.LedgerLegitimate!.Value);
                }
                var channelBooked = status != 0;
                var eventId = channelBooked
                    ? _sink.RecordOutcomeFeedback(mapping.Channel, idempotencyKey)
                    : "";
                return new OutcomeReceipt(outcome, handle.Dimension, status, channelBooked, 0, 0, eventId);
            }
            var markCount = 0;
            var marksWritten = 0;
            if (mapping.WritesAbuseMark)
            {
                markCount = _sink.WriteMark(handle.Dimension.MarkDimension()!, handle.Id,
                    mapping.MarkKind(), at);
                marksWritten = 1;
            }
            var bookedEventId = _sink.RecordOutcomeFeedback(mapping.Channel, idempotencyKey);
            return new OutcomeReceipt(outcome, handle.Dimension, 0, true, marksWritten, markCount,
                bookedEventId);
        }

        /// <summary>Clears the marks of one handle's subject.</summary>
        public int Forget(OutcomeHandle handle)
        {
            var dimension = handle.Dimension.MarkDimension();
            if (dimension == null)
            {
                return 0;
            }
            return _sink.ForgetMarks(dimension, handle.Id);
        }
    }
}
