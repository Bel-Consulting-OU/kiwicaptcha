defmodule Kiwicaptcha.OutcomesTest do
  use ExUnit.Case, async: true

  import Kiwicaptcha.TestSupport

  alias Kiwicaptcha.Outcomes

  # The outcomes mapping against the risk-v1 vectors, the handle
  # grammar, the mark and idempotency keys: the same vectors the Ruby
  # suite runs, so the two tables cannot drift.
  test "every accepted outcome vector resolves through the mapping" do
    vectors = protocol("risk-v1/outcomes-vectors.json")

    for vector <- vectors["vectors"] do
      outcome = vector["outcome"]
      mapping = Outcomes.outcome_mapping(outcome)
      handle = %{dimension: vector["handle"]["dimension"], id: vector["handle"]["id"]}
      accepted = vector["accepted"]

      dimension_ok = Outcomes.accepts?(mapping, handle.dimension)

      # Acceptance is dimension membership AND the handle grammar: a
      # raw identifier is refused before any mark key is built.
      grammar_ok =
        try do
          Outcomes.validate_outcome_handle!(handle)
          true
        rescue
          Kiwicaptcha.RangeError -> false
        end

      assert accepted == (dimension_ok and grammar_ok), outcome

      if Map.has_key?(vector, "channel_value") do
        assert vector["channel_value"] == mapping.channel, outcome

        cond do
          vector["ledger_action"] == "L" -> assert mapping.ledger_legitimate == true, outcome
          vector["ledger_action"] == "A" -> assert mapping.ledger_legitimate == false, outcome
          true -> assert mapping.ledger_legitimate == nil, outcome
        end
      end
    end
  end

  test "the mapping table is total and versioned" do
    assert 1 == Outcomes.map_version()
    vectors = protocol("risk-v1/outcomes-vectors.json")
    assert vectors["version"] == Outcomes.map_version()

    rows = Outcomes.all_outcome_mappings()
    assert length(Outcomes.outcomes()) == length(rows)

    for row <- rows do
      # Only the server-confirmed outcomes that never write abuse marks
      # may subtract risk, and exactly the abuse outcomes write
      # long-memory marks.
      assert row.may_subtract_risk == (row.server_confirmed and not row.writes_abuse_mark)
      refute row.writes_abuse_mark and not row.server_confirmed

      if row.ledger_legitimate == false do
        assert row.writes_abuse_mark
      end
    end
  end

  test "the handle grammar refuses raw identifiers" do
    pseudonym = String.duplicate("a", 32)

    for dimension <- ~w[principal target session] do
      assert :ok == Outcomes.validate_outcome_handle!(%{dimension: dimension, id: pseudonym})

      assert_raise Kiwicaptcha.RangeError, fn ->
        Outcomes.validate_outcome_handle!(%{dimension: dimension, id: "raw-user@example.test"})
      end
    end

    assert :ok == Outcomes.validate_outcome_handle!(%{dimension: "agent", id: "agent-key-1"})

    assert_raise Kiwicaptcha.RangeError, fn ->
      Outcomes.validate_outcome_handle!(%{dimension: "agent", id: "bad:char"})
    end

    assert_raise Kiwicaptcha.RangeError, fn ->
      Outcomes.validate_outcome_handle!(%{dimension: "agent", id: ""})
    end
  end

  test "the client books the ledger and marks through one sink" do
    sink = Outcomes.MemorySink.new()
    bound = %{sink: sink, module: Outcomes.MemorySink, namespace: "test"}

    {:ok, receipt, sink} =
      Outcomes.report(bound, "confirmedLegitimate", %{
        dimension: "decisionId",
        id: String.duplicate("d", 32)
      })

    assert 12 == receipt.mapping.channel
    assert 1 == receipt.ledger_status
    assert 0 == receipt.marks_written
    assert 1 == length(sink.feedback)

    {:ok, receipt, sink} =
      Outcomes.report(%{bound | sink: sink}, "fraudConfirmed", %{
        dimension: "principal",
        id: String.duplicate("a", 32)
      })

    assert receipt.ledger_status == nil
    assert 1 == receipt.marks_written

    mark = Outcomes.mark_key("test", "principal", String.duplicate("a", 32))
    assert "fraudConfirmed" == Map.fetch!(sink.marks, mark)

    # The forget path erases the dimension's marks; a ledger dimension
    # carries none.
    {erased, _} =
      Outcomes.forget(%{bound | sink: sink}, %{
        dimension: "principal",
        id: String.duplicate("a", 32)
      })

    assert 1 == erased

    {erased, _} =
      Outcomes.forget(%{bound | sink: sink}, %{dimension: "nonce", id: String.duplicate("b", 32)})

    assert 0 == erased

    # A dimension the mapping does not accept is refused before any
    # write: confirmedLegitimate accepts every dimension, the identity
    # outcomes never accept the ledger ones.
    {:ok, _, _} =
      Outcomes.report(%{bound | sink: sink}, "confirmedLegitimate", %{
        dimension: "session",
        id: String.duplicate("c", 32)
      })

    assert_raise Kiwicaptcha.RangeError, fn ->
      Outcomes.report(%{bound | sink: sink}, "stepUpCompleted", %{
        dimension: "nonce",
        id: String.duplicate("c", 32)
      })
    end
  end

  test "the idempotency key is a bounded hmac" do
    handle = %{dimension: "decisionId", id: String.duplicate("d", 32)}
    key = Outcomes.default_idempotency_key(handle)
    assert 32 == String.length(key)
    assert Regex.match?(~r/\A[0-9a-f]{32}\z/, key)
    assert key == Outcomes.default_idempotency_key(handle)
    refute key == Outcomes.default_idempotency_key(handle, "other-secret")
  end

  test "an unknown outcome has no row" do
    assert_raise KeyError, fn -> Outcomes.outcome_mapping("mysteryOutcome") end
  end
end
