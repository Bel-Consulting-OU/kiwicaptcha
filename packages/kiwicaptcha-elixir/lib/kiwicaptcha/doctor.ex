defmodule Kiwicaptcha.Doctor do
  @moduledoc """
  The doctor: the deployment self-check of the shared server SDK
  contract. It validates the quickstart surface (the profile is an
  adoption choice, so the doctor checks the other three): secret
  strength, store reachability and atomicity, and the optional rsw
  trapdoor pair. Findings come back typed and ordered so a wrapper can
  print or assert them.
  """

  @identifier_re ~r/\A[A-Za-z0-9._:-]+\z/

  @doc "Run every deployment check. See the module documentation."
  @spec run(keyword()) :: %{ok: boolean(), checks: [map()]}
  def run(opts) do
    secret = Keyword.fetch!(opts, :secret)
    store = Keyword.fetch!(opts, :store)
    rsw = Keyword.get(opts, :rsw)
    region = Keyword.get(opts, :region)
    issuer = Keyword.get(opts, :issuer)
    profile = Keyword.get(opts, :profile)

    checks =
      [
        secret_check(secret),
        identifier_check("region", region),
        identifier_check("issuer", issuer),
        argon2_check(profile),
        store_check(store)
      ] ++ if(rsw, do: [rsw_check(rsw)], else: [])

    %{ok: Enum.all?(checks, & &1.ok), checks: checks}
  end

  # The argon2id capability flag: a priced ladder that issues Argon
  # rungs fails the check when the native binding is absent; the
  # refusal is loud and typed, never a silent downgrade. The rung
  # budgets are also checked against the protocol power-of-two profile
  # space here at config time — never discovered per request.
  defp argon2_check(profile) do
    available = Kiwicaptcha.Pow.argon2_available?()
    required = profile == nil or profile in ["argon16", "argon32", "argon64", "abuse_first", "high_abuse"]

    rungs_in_space =
      Enum.all?(
        Kiwicaptcha.Settings.argon_rung_memory_kib(),
        &Kiwicaptcha.Settings.valid_argon_memory_kib?/1
      )

    ok = (available or not required) and rungs_in_space

    detail =
      cond do
        not rungs_in_space ->
          "an argon2id rung budget is outside the protocol profile space " <>
            "(powers of two within 8..=65536 KiB); refused at configuration " <>
            "time, never per request"

        available ->
          "native Argon2id binding present (argon2_elixir); argon rungs verify " <>
            "(protocol profile space: powers of two within 8..=65536 KiB)"

        required ->
          "native Argon2id binding missing: the priced ladder issues argon2id rungs " <>
            "that refuse with unsupported_argon2_params (add the optional " <>
            "argon2_elixir dependency or choose a sha-only profile); never silently downgraded"

        true ->
          "native Argon2id binding missing (this profile prices no argon rungs)"
      end

    %{name: "argon2", ok: ok, detail: detail}
  end

  defp secret_check(secret) do
    length = byte_size(IO.iodata_to_binary([secret]))
    floor = Kiwicaptcha.Keys.min_secret_bytes()

    %{
      name: "secret",
      ok: length >= floor,
      detail:
        if length >= floor do
          "#{length} bytes, meets the #{floor}-byte floor"
        else
          "#{length} bytes, below the #{floor}-byte floor"
        end
    }
  end

  defp identifier_check(name, value) do
    ok = is_nil(value) or Regex.match?(@identifier_re, value)

    %{
      name: name,
      ok: ok,
      detail:
        if(ok, do: "identifier shape valid or unset", else: "#{name} must match [A-Za-z0-9._:-]")
    }
  end

  # The store probe writes a nonce-shaped probe record, consumes it,
  # and requires the exactly-once semantics: the second consume must
  # answer consumed_before with no fresh win.
  defp store_check(store) do
    probe = :crypto.strong_rand_bytes(32)
    nonce = Kiwicaptcha.B64.encode_std(probe)
    now = System.system_time(:second)

    record = %Kiwicaptcha.Record{
      nonce: nonce,
      scope: "doctor",
      binding_tag: "",
      issued_at: now,
      expires_at: now + 120,
      algorithm: "sha256",
      m_kib: 0,
      t: 1,
      p: 1,
      target_bits: 1,
      salt: Kiwicaptcha.B64.encode_std(binary_part(probe, 0, 16)),
      prefix: "#{nonce}.",
      challenge: "#{nonce}.sig",
      min_duration_ms: 0,
      issued_at_ns: 0,
      protocol_version: 2,
      region: nil,
      policy_version: 1,
      request_binding: nil,
      issuer: nil,
      kid: 1,
      hostname: nil,
      decoy_field: nil,
      execution_program: nil,
      execution_version: nil,
      execution_commitment: nil,
      rsw_modulus_sha256: nil,
      server_mac: nil
    }

    store.store.(record)

    if store.find.(nonce) == nil do
      %{name: "store", ok: false, detail: "the probe record did not read back"}
    else
      first = store.consume.(nonce, nil)

      if first == nil or not first.consumed_now do
        %{name: "store", ok: false, detail: "the first probe consume did not win"}
      else
        second = store.consume.(nonce, nil)

        if second == nil or not second.consumed_before do
          %{
            name: "store",
            ok: false,
            detail: "the second probe consume won again: the store is not single-use"
          }
        else
          %{name: "store", ok: true, detail: "reachable and single-use under the probe"}
        end
      end
    end
  rescue
    e -> %{name: "store", ok: false, detail: "store probe failed: #{Exception.message(e)}"}
  end

  defp rsw_check(config) do
    trapdoor = Kiwicaptcha.Rsw.new_trapdoor(config.modulus_n, config.lambda)
    head = trapdoor.n |> Integer.to_string(16) |> String.slice(0, 16)
    %{name: "rsw", ok: true, detail: "trapdoor valid for modulus #{head}..."}
  rescue
    e -> %{name: "rsw", ok: false, detail: Exception.message(e)}
  end
end
