defmodule Kiwicaptcha.TokenTest do
  use ExUnit.Case, async: true

  import Kiwicaptcha.TestSupport

  # The solution token codec against the shared boundary fixture: the
  # solver hash ceiling and the exact counter spellings both decoders
  # must accept or reject, plus the decode error surface.
  test "the shared fixture acceptance split" do
    fixtures = protocol("solution-token-v1/fixtures.json")
    assert Kiwicaptcha.Pow.solver_max_hashes() == 20_000_000

    for {counter, encoded} <- fixtures["accepted"] do
      {:ok, token} = Kiwicaptcha.Token.decode(encoded)
      assert token.counter == String.to_integer(counter)
      assert Kiwicaptcha.Token.encode(token) == encoded
    end

    for {_counter, encoded} <- fixtures["rejected"] do
      assert {:error, _} = Kiwicaptcha.Token.decode(encoded)
    end

    cross = fixtures["cross_language"]
    {:ok, token} = Kiwicaptcha.Token.decode(cross["encoded"])
    assert token.counter == cross["counter"]
    assert Kiwicaptcha.Token.encode(token) == cross["encoded"]
  end

  test "round trip of a full token" do
    token = %Kiwicaptcha.Token{
      nonce: String.duplicate("A", 43) <> "=",
      counter: 42,
      duration_ms: 1200,
      telemetry: %{"v" => 1, "et" => [1, 2, 3]},
      execution_digest: nil,
      execution_trace: nil,
      rsw_proof: nil
    }

    decoded = token |> Kiwicaptcha.Token.encode() |> Kiwicaptcha.Token.decode!()
    assert decoded.nonce == token.nonce
    assert decoded.counter == token.counter
    assert decoded.duration_ms == token.duration_ms
    assert decoded.telemetry == %{"v" => 1, "et" => [1, 2, 3]}
    assert decoded.execution_digest == nil
    assert decoded.rsw_proof == nil
  end

  test "execution and rsw segments ride the wire" do
    nonce = String.duplicate("A", 43) <> "="
    digest = String.duplicate("a", 64)
    trace = Kiwicaptcha.B64.encode_url("entry1;entry2")

    token = %Kiwicaptcha.Token{
      nonce: nonce,
      counter: 7,
      duration_ms: 10,
      telemetry: %{},
      execution_digest: digest,
      execution_trace: trace,
      rsw_proof: nil
    }

    decoded = token |> Kiwicaptcha.Token.encode() |> Kiwicaptcha.Token.decode!()
    assert decoded.execution_digest == digest
    assert decoded.execution_trace == trace

    proof = String.duplicate("b", 512)

    token = %Kiwicaptcha.Token{
      nonce: nonce,
      counter: 0,
      duration_ms: 10,
      telemetry: %{},
      execution_digest: nil,
      execution_trace: nil,
      rsw_proof: proof
    }

    decoded = token |> Kiwicaptcha.Token.encode() |> Kiwicaptcha.Token.decode!()
    assert decoded.rsw_proof == proof
  end

  test "every decode failure carries its code" do
    nonce = String.duplicate("A", 43) <> "="

    plain_cases = [
      {:invalid_counter, "#{nonce}.01.5.{}"},
      {:counter_exceeds_solver_maximum, "#{nonce}.20000000.5.{}"},
      {:invalid_duration, "#{nonce}.5.01.{}"},
      {:malformed, "#{nonce}.5.5.[]"},
      {:malformed, "#{nonce}.5.5.3"}
    ]

    for {code, plain} <- plain_cases do
      raw = Kiwicaptcha.B64.encode_std(plain)
      assert {:error, ^code} = Kiwicaptcha.Token.decode(raw)
    end

    assert {:error, :invalid_base64} = Kiwicaptcha.Token.decode("not base64!!!")
    assert {:error, :malformed} = Kiwicaptcha.Token.decode("")
    assert {:error, :malformed} = Kiwicaptcha.Token.decode("QQ==")
    # A duration beyond the ceiling is invalid.
    assert {:error, :invalid_duration} =
             Kiwicaptcha.B64.encode_std("#{nonce}.5.3600001.{}") |> Kiwicaptcha.Token.decode()

    # Oversized input is malformed before any decode.
    assert {:error, :malformed} = Kiwicaptcha.Token.decode(String.duplicate("a", 40_000))
  end

  test "non object telemetry is malformed" do
    nonce = String.duplicate("A", 43) <> "="
    raw = Kiwicaptcha.B64.encode_std("#{nonce}.5.5.[1]")
    assert {:error, :malformed} = Kiwicaptcha.Token.decode(raw)
  end
end
