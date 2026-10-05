defmodule Kiwicaptcha.ConformanceTest do
  use ExUnit.Case, async: true

  import Kiwicaptcha.TestSupport

  # The cross-SDK conformance runner: the shared protocol corpus
  # (solution-token-v1, limits.json, risk-v1 outcome vectors) plus the
  # PHP-issued golden records, asserted end to end so behavior cannot
  # drift from the other cores.
  test "the shared registers agree with the implementation constants" do
    limits = protocol("limits.json")
    assert limits["solver_max_hashes"] == Kiwicaptcha.Pow.solver_max_hashes()
    assert limits["solver_max_hashes"] == Kiwicaptcha.Token.solver_max_hashes()
    assert limits["ttl_max_secs"] == Kiwicaptcha.Verify.max_ttl_secs()
    assert limits["token_max_duration_ms"] == Kiwicaptcha.Token.max_duration_ms()
    assert limits["min_master_bytes"] == Kiwicaptcha.Keys.min_secret_bytes()
    assert limits["rsw_t_min"] == Kiwicaptcha.Rsw.t_min()
    assert limits["rsw_t_max"] == Kiwicaptcha.Rsw.t_max()
    assert limits["execution_max_program_base64"] == Kiwicaptcha.Record.max_program_base64()

    fixture = protocol("solution-token-v1/fixtures.json")
    assert fixture["solver_max_hashes"] == Kiwicaptcha.Pow.solver_max_hashes()
  end

  test "every verify error code is in the shared vocabulary" do
    expected = ~w[
      admission_unavailable already_consumed bad_signature capacity_exceeded
      consume_indeterminate execution_mismatch expired insufficient_work
      ip_mismatch malformed_record malformed_token missing_client_ip
      record_not_found request_binding_mismatch storage_unavailable
      telemetry_rejected too_fast too_many_attempts unknown_kid
      unsupported_argon2_params unsupported_rsw_params wrong_issuer
      wrong_policy_version wrong_region wrong_scope
    ]

    assert Enum.sort(expected) ==
             Enum.map(Kiwicaptcha.VerifyError.all(), &to_string/1) |> Enum.sort()

    for code <- Kiwicaptcha.VerifyError.all() do
      assert Regex.match?(~r/\A[a-z0-9_]+\z/, to_string(code))
      # A non-string description crashes the length call: the assert
      # doubles as the type check without a provably dead comparison.
      description = Kiwicaptcha.VerifyError.describe(code)
      assert String.length(description) > 0
    end
  end

  test "every golden record verifies to its php pinned verdict" do
    for row <- golden()["records"] do
      name = row["name"]
      record = record_from_row(row)
      # The record JSON survives a strict parse and a canonical rewrite.
      token = Kiwicaptcha.Token.decode!(row["token_b64"])
      assert row["token_b64"] == Kiwicaptcha.Token.encode(token), name

      {:ok, pid} = Kiwicaptcha.Stores.Memory.start(now: fn -> record.issued_at + 10 end)
      storage = Kiwicaptcha.Stores.Memory.adapter(pid)
      Kiwicaptcha.Stores.Memory.store(pid, record)

      opts = golden_options(row["verify_opts"], record, storage)
      result = Kiwicaptcha.verify(row["token_b64"], opts)

      assert row["expected"]["ok"] == result.ok, "#{name}: ok mismatch (#{result.code})"

      if Map.has_key?(row["expected"], "code") do
        assert row["expected"]["code"] == to_string(result.code), "#{name}: code mismatch"
      end

      if Map.has_key?(row["expected"], "decoyField") do
        assert row["expected"]["decoyField"] == result.decoy_field, name
      end
    end
  end

  test "the outcome channels match the risk v1 event kinds" do
    vectors = protocol("risk-v1/outcomes-vectors.json")

    for vector <- vectors["vectors"], vector["accepted"] do
      mapping = Kiwicaptcha.Outcomes.outcome_mapping(vector["outcome"])
      assert vector["channel_value"] == mapping.channel
    end
  end

  test "a consumed golden record replays the identical denial code" do
    row = golden_record("sha_plain")
    record = record_from_row(row)

    {:ok, pid} = Kiwicaptcha.Stores.Memory.start(now: fn -> record.issued_at + 10 end)
    storage = Kiwicaptcha.Stores.Memory.adapter(pid)
    Kiwicaptcha.Stores.Memory.store(pid, record)

    wrong =
      row["token_b64"]
      |> Kiwicaptcha.Token.decode!()
      |> Map.merge(%{counter: 12_345})
      |> Kiwicaptcha.Token.encode()

    opts = golden_options(row["verify_opts"], record, storage)
    first = Kiwicaptcha.verify(wrong, opts)
    assert first.code == :insufficient_work
    second = Kiwicaptcha.verify(wrong, opts)
    assert second.code == :insufficient_work
  end
end
