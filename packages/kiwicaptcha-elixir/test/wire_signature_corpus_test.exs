defmodule Kiwicaptcha.WireSignatureCorpusTest do
  use ExUnit.Case, async: true

  import Kiwicaptcha.TestSupport

  # The shared challenge-signature corpus against the Elixir verifier.
  # The fixture is expanded by the PHP generator and read byte-for-byte
  # by every hosted SDK suite.
  @corpus protocol("solution-token-v1/wire-signature-corpus.json")

  test "the corpus is broad" do
    assert @corpus["counts"]["total"] >= 40
  end

  for row <- @corpus["vectors"] do
    test "signature corpus: #{row["id"]}" do
      row = unquote(Macro.escape(row))
      {:ok, record} = Kiwicaptcha.Record.from_json(row["record"])
      assert record.challenge == row["challenge"], row["id"]

      options = %{tenant_id: row["verify_tenant"]}
      verified = Kiwicaptcha.Verify.verify_record_signature(options, record, row["verify_secret"])
      assert verified == (row["expect"] == "accept"), row["id"]
    end
  end
end
