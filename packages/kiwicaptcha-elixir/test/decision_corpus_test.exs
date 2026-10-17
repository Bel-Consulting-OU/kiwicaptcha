defmodule Kiwicaptcha.DecisionCorpusTest do
  use ExUnit.Case, async: true

  import Kiwicaptcha.TestSupport

  # The shared decision and authority register:
  # protocol/decision-v1/corpus.json. The Elixir side asserts every
  # wire code, the retry table and every token source matrix row.
  defp corpus, do: protocol("decision-v1/corpus.json")

  test "every wire code maps to its registered disposition" do
    register = corpus()
    expected = register["codes"] |> Map.keys() |> Enum.sort()
    actual = Kiwicaptcha.VerifyError.all() |> Enum.map(&to_string/1) |> Enum.sort()
    assert expected == actual

    Enum.each(register["codes"], fn {code, disposition} ->
      atom = String.to_existing_atom(code)
      assert Kiwicaptcha.Verify.disposition_for(atom) == String.to_atom(disposition), code
    end)
  end

  test "the retry table is exactly the four transient codes" do
    register = corpus()
    registered = Enum.sort(register["retry_codes"])
    actual = Enum.sort(Enum.map(Kiwicaptcha.Verify.retry_codes(), &to_string/1))
    assert actual == registered
  end

  test "the middleware status rows agree" do
    register = corpus()
    assert register["http"]["allow_status"] == 200
    assert register["http"]["retry_status"] == 503
    assert register["http"]["deny_status"]["elixir"] == 422
  end

  test "every authority row resolves under reject on conflict" do
    authority = corpus()["authority"]
    assert authority["conflict_code"] == "token_source_conflict"
    assert authority["missing_code"] == "malformed_token"

    Enum.each(authority["matrix"], fn row ->
      {token, failure} =
        Kiwicaptcha.TokenSource.resolve_values(
          row["header"],
          row["form"],
          row["query"]
        )

      case row["verdict"] do
        "verify" ->
          assert failure == nil, row["case"]
          assert token == row["token"], row["case"]

        "conflict" ->
          assert failure == :token_source_conflict, row["case"]
          assert token == nil, row["case"]

        "missing" ->
          assert failure == :malformed_token, row["case"]
      end
    end)
  end
end
