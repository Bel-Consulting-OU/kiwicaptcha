defmodule Kiwicaptcha.CanonicalTest do
  use ExUnit.Case, async: true

  import Kiwicaptcha.TestSupport

  # The crypto seams against the shared vectors: the HKDF purpose
  # keys, the canonical payload spellings and signatures, the
  # server-state MAC inputs, the canonical IP family and the binding
  # tags, all pinned byte-exact by the committed fixtures.
  test "hkdf purpose keys match the shared vector" do
    hkdf = golden()["hkdf"]
    derived = Kiwicaptcha.Keys.derived_keys(secret())
    assert Base.encode16(derived.challenge_key, case: :lower) == hkdf["challenge_hex"]
    assert Base.encode16(derived.ip_bind_key, case: :lower) == hkdf["ip_bind_hex"]
    assert Base.encode16(derived.result_key, case: :lower) == hkdf["result_hex"]
    assert Base.encode16(derived.server_state_key, case: :lower) == hkdf["server_state_hex"]
  end

  test "a short secret is refused" do
    assert_raise Kiwicaptcha.RangeError, fn -> Kiwicaptcha.Keys.derived_keys("too short") end
  end

  test "canonical payload spellings match the committed vectors" do
    canonical = golden()["canonical"]

    base = %Kiwicaptcha.Canonical.Args{
      protocol_version: 2,
      nonce: "bm9uY2UtcmV2aXNpb24tMy10ZXN0LXZlY3Rvcg==",
      scope: "login",
      binding_tag: "tag456",
      issued_at: 111,
      expires_at: 222,
      algorithm: "sha256",
      m_kib: 0,
      t: 1,
      p: 1,
      target_bits: 8,
      salt: "c2FsdC1yZXZpc2lvbi0z",
      min_duration_ms: 5,
      region: "eu",
      policy_version: 2,
      request_binding: "bind-1",
      issuer: "prod",
      kid: 3
    }

    assert Kiwicaptcha.Canonical.canonical_payload(base) == canonical["base"]

    # The armed variants travel at their own protocol version with the
    # region unbound, policy 1, and no binding or issuer.
    variant = fn version ->
      %Kiwicaptcha.Canonical.Args{
        protocol_version: version,
        nonce: base.nonce,
        scope: base.scope,
        binding_tag: base.binding_tag,
        issued_at: 111,
        expires_at: 222,
        algorithm: "sha256",
        m_kib: 0,
        t: 1,
        p: 1,
        target_bits: 8,
        salt: base.salt,
        min_duration_ms: 5
      }
    end

    decoy = variant.(3)
    decoy = %{decoy | decoy_field: "billing_address_line_a3f9c21d8e5b7401"}
    assert Kiwicaptcha.Canonical.canonical_payload(decoy) == canonical["v3_decoy"]

    execution = variant.(4)

    execution = %{
      execution
      | execution_version: 1,
        execution_commitment: String.duplicate("a", 64)
    }

    assert Kiwicaptcha.Canonical.canonical_payload(execution) == canonical["v4_execution"]

    identity = variant.(5)
    identity = %{identity | rsw_modulus_sha256: String.duplicate("b", 64)}
    assert Kiwicaptcha.Canonical.canonical_payload(identity) == canonical["v5_identity"]
  end

  test "signature versions match the committed vector" do
    canonical = golden()["canonical"]
    signature = Kiwicaptcha.Canonical.sign_payload_v2(canonical["base"], secret())
    assert signature == canonical["signature_hex"]
  end

  test "server state mac inputs match the committed vectors" do
    vectors = golden()["server_state_mac"]
    key = Base.decode16!(vectors["key_hex"], case: :lower)

    # The fixture input is authoritative; rebuild each field from it
    # and pin the MAC byte-exact.
    meta_input = vectors["record_meta_input"]
    lines = String.split(meta_input, "\n")
    challenge = lines |> Enum.at(1) |> String.split(":", parts: 2) |> Enum.at(1)
    issued_at_ns = lines |> Enum.at(2) |> String.to_integer()

    hostname =
      if Enum.at(lines, 3) == "0",
        do: nil,
        else: Enum.at(lines, 3) |> String.replace(~r/\A1:\d+:/, "")

    rebuilt = Kiwicaptcha.Mac.record_meta_input(challenge, issued_at_ns, hostname)
    assert rebuilt == meta_input

    assert Kiwicaptcha.Mac.record_meta_mac(key, challenge, issued_at_ns, hostname) ==
             vectors["record_meta_hex"]

    result_input = vectors["consumed_result_input"]
    result_lines = String.split(result_input, "\n")
    result_challenge = result_lines |> Enum.at(1) |> String.split(":", parts: 2) |> Enum.at(1)
    valid = Enum.at(result_lines, 2) == "1"

    binding =
      if Enum.at(result_lines, 3) == "0",
        do: nil,
        else: Enum.at(result_lines, 3) |> String.replace(~r/\A1:\d+:/, "")

    identity =
      if Enum.at(result_lines, 4) == "0",
        do: nil,
        else: Enum.at(result_lines, 4) |> String.replace(~r/\A1:\d+:/, "")

    rebuilt = Kiwicaptcha.Mac.consumed_result_input(result_challenge, valid, binding, identity)
    assert rebuilt == result_input

    assert Kiwicaptcha.Mac.consumed_result_mac(key, result_challenge, valid, binding, identity) ==
             vectors["consumed_result_hex"]
  end

  test "m marker parse" do
    record = golden_record("sha_plain") |> record_from_row()
    assert Kiwicaptcha.Canonical.signed_canonical_commits_record_meta?(record.challenge)
    bare = Kiwicaptcha.B64.encode_std("v4|2|") <> "." <> String.duplicate("a", 64)
    refute Kiwicaptcha.Canonical.signed_canonical_commits_record_meta?(bare)
  end

  test "canonical ip family normalizes mapped spellings" do
    assert {:ok, <<4, 203, 0, 113, 7>>} ==
             Kiwicaptcha.Canonical.canonical_ip_family("203.0.113.7")

    assert {:ok, loopback = <<6, _::binary-size(16)>>} =
             Kiwicaptcha.Canonical.canonical_ip_family("::1")

    assert binary_part(loopback, 13, 4) == <<0, 0, 0, 1>>

    mapped = Kiwicaptcha.Canonical.canonical_ip_family("::ffff:203.0.113.7")
    assert mapped == {:ok, <<4, 203, 0, 113, 7>>}

    compatible = Kiwicaptcha.Canonical.canonical_ip_family("::203.0.113.7")
    assert compatible == {:ok, <<4, 203, 0, 113, 7>>}

    assert {:ok, <<6, _::binary-size(16)>>} =
             Kiwicaptcha.Canonical.canonical_ip_family("2001:db8::1")

    assert :error == Kiwicaptcha.Canonical.canonical_ip_family("999.1.1.1")
    assert :error == Kiwicaptcha.Canonical.canonical_ip_family("01.2.3.4")
    assert :error == Kiwicaptcha.Canonical.canonical_ip_family("2001::db8::1")
  end

  test "binding tag is deterministic and v1 hash differs" do
    tag = Kiwicaptcha.Canonical.binding_tag("bm9uY2U=", client_ip(), secret())
    assert tag == Kiwicaptcha.Canonical.binding_tag("bm9uY2U=", client_ip(), secret())

    assert_raise Kiwicaptcha.RangeError, fn ->
      Kiwicaptcha.Canonical.binding_tag("bm9uY2U=", "not-an-ip", secret())
    end

    assert Kiwicaptcha.Canonical.hash_ip(client_ip(), secret()) == ip_hash()
  end

  test "timing safe equals" do
    assert Kiwicaptcha.Mac.timing_safe_equals("abc", "abc")
    refute Kiwicaptcha.Mac.timing_safe_equals("abc", "abd")
    refute Kiwicaptcha.Mac.timing_safe_equals("abc", "abcd")
    refute Kiwicaptcha.Mac.timing_safe_equals(5, "abc")
  end

  test "sha256 pow derivation" do
    vector = sha_vector()
    {:ok, salt} = Kiwicaptcha.B64.decode_std(vector["salt"])
    hash = Kiwicaptcha.Pow.derive_sha256_hash(vector["prefix"], 158, salt)
    assert Kiwicaptcha.Pow.meets_target?(hash, 8)
    refute Kiwicaptcha.Pow.meets_target?(hash, 20)
    assert Kiwicaptcha.Pow.solve_sha256(vector["prefix"], vector["salt"], 8) == 158
  end
end
