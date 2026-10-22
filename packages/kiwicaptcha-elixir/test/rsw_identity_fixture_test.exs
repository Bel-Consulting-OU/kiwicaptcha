defmodule Kiwicaptcha.RswIdentityFixtureTest do
  use ExUnit.Case, async: true

  import Kiwicaptcha.TestSupport

  # The one canonical rsw modulus identity fixture against the Elixir
  # binding. protocol/rsw-identity-v1/fixtures.json pins the shared
  # 2048-bit test modulus and the identity values every language
  # binding must agree on: the canonical fingerprint (SHA-256 of the
  # decoded 256-byte modulus), the legacy base64-text alias accepted
  # only in the bounded migration mode, and the secondary pair used
  # solely for cross-identity negative tests.
  @fixture protocol("rsw-identity-v1/fixtures.json")

  test "the fixture parses and pins the expected fields" do
    assert @fixture["format_version"] == 1
    assert is_binary(@fixture["modulus_n_b64"])
    assert is_binary(@fixture["lambda_b64"])
    assert @fixture["rsw_modulus_n_sha256"] =~ ~r/^[0-9a-f]{64}$/
    assert @fixture["legacy_base64_text_sha256"] =~ ~r/^[0-9a-f]{64}$/
    assert is_binary(@fixture["secondary"]["modulus_n_b64"])
    assert @fixture["secondary"]["rsw_modulus_n_sha256"] =~ ~r/^[0-9a-f]{64}$/
  end

  test "the canonical and legacy identities match the fixture" do
    modulus = @fixture["modulus_n_b64"]

    assert Kiwicaptcha.Rsw.modulus_fingerprint_hex(modulus) ==
             @fixture["rsw_modulus_n_sha256"]

    assert Kiwicaptcha.Rsw.identity_matches?(@fixture["rsw_modulus_n_sha256"], modulus, false)

    # The legacy base64-text alias matches only while the bounded
    # migration mode is enabled; the binding derives it internally.
    assert Kiwicaptcha.Rsw.identity_matches?(@fixture["legacy_base64_text_sha256"], modulus, true)
    refute Kiwicaptcha.Rsw.identity_matches?(@fixture["legacy_base64_text_sha256"], modulus, false)

    # A foreign identity never matches.
    refute Kiwicaptcha.Rsw.identity_matches?(String.duplicate("f", 64), modulus, true)
  end

  test "the secondary pair fingerprints and never matches the primary" do
    secondary = @fixture["secondary"]

    assert Kiwicaptcha.Rsw.modulus_fingerprint_hex(secondary["modulus_n_b64"]) ==
             secondary["rsw_modulus_n_sha256"]

    refute Kiwicaptcha.Rsw.identity_matches?(
             secondary["rsw_modulus_n_sha256"],
             @fixture["modulus_n_b64"],
             true
           )
  end

  test "the fixture trapdoor pair validates" do
    trapdoor = Kiwicaptcha.Rsw.new_trapdoor(@fixture["modulus_n_b64"], @fixture["lambda_b64"])
    assert trapdoor.n |> Integer.digits(2) |> length() == 2048
  end
end
