defmodule Kiwicaptcha.TestSupport do
  @moduledoc """
  Shared test support: the protocol corpus paths, the PHP-issued
  golden vectors and the record and token builders every suite
  composes.
  """

  # __DIR__ is test/support inside the package: two ups land on the
  # package root, four on the repository root holding protocol/.
  @package_root Path.expand("../..", __DIR__)
  @repo_root Path.expand("../../../..", __DIR__)
  @protocol_dir Path.join(@repo_root, "protocol")
  @fixtures_dir Path.join([@package_root, "test", "fixtures"])

  @secret "0123456789abcdef0123456789abcdef"
  @client_ip "203.0.113.7"

  def package_root, do: @package_root
  def secret, do: @secret
  def client_ip, do: @client_ip

  def protocol(relpath), do: read_json(Path.join(@protocol_dir, relpath))
  def fixture(relpath), do: read_json(Path.join(@fixtures_dir, relpath))

  defp read_json(path) do
    cond do
      Code.ensure_loaded?(JSON) and function_exported?(JSON, :decode, 1) ->
        {_, doc} = JSON.decode(File.read!(path))
        doc

      Code.ensure_loaded?(Jason) and function_exported?(Jason, :decode, 1) ->
        {_, doc} = Jason.decode(File.read!(path))
        doc

      true ->
        raise "no JSON decoder available"
    end
  end

  def golden, do: fixture("golden-php-vectors.json")

  def golden_record(name) do
    Enum.find(golden()["records"], &(&1["name"] == name)) ||
      raise KeyError, "golden record #{name} missing"
  end

  # The frozen test clock: the golden records were issued once by the
  # PHP core, so every test that redeems them travels back to the
  # issuance era on both clocks.
  # Accepts the raw fixture row or the parsed record struct; the TTL
  # clock is a fun, the receipt clock an integer.
  def frozen_clock(record) do
    issued_at =
      if is_map_key(record, :__struct__), do: record.issued_at, else: record["issued_at"]

    issued_at_ns =
      if is_map_key(record, :__struct__), do: record.issued_at_ns, else: record["issued_at_ns"]

    [now: fn -> issued_at + 10 end, now_ns: issued_at_ns + 2_000_000]
  end

  def record_from_row(row) do
    {:ok, record} = Kiwicaptcha.Record.from_json(row["record"])
    record
  end

  def base_options(over \\ %{}) do
    Map.merge(
      %{
        storage: nil,
        secret_key: @secret,
        expected_scope: nil,
        client_ip: nil,
        now_ns: nil,
        now: nil,
        enforce_telemetry: false,
        operation_identity: nil,
        expected_request_binding: nil,
        binding_expectation: :exact,
        expected_policy_version: nil,
        policy_version_floor: nil,
        region: nil,
        expected_issuer: nil,
        secrets_by_kid: %{},
        revoked_kids: [],
        tenant_id: nil,
        accept_legacy_v1: false,
        rsw: nil
      },
      Map.new(over, fn {k, v} -> {k, v} end)
    )
  end

  # The Rust-issued canonical v1 vector, asserted byte-exact across
  # every core suite.
  @sha_vector %{
    "nonce" => "2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=",
    "challenge" =>
      "MmwwSVZoMXh1S05qemNDRHlWK1gwbHJjZU1IbEh2bXFDczVNZER3OHR3MD18bG9naW58" <>
        "OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1" <>
        "ZDY0ODUwMDM0YnwxODAwMDAwMDAw." <>
        "dee1893de8e9f57e974af43ec5b6e7523f7d09cee038a8edd5df59ad2f9248ba",
    "salt" => "phUfA189G9A5KMv3r+wzLA==",
    "prefix" =>
      "MmwwSVZoMXh1S05qemNDRHlWK1gwbHJjZU1IbEh2bXFDczVNZER3OHR3MD18bG9naW58" <>
        "OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1" <>
        "ZDY0ODUwMDM0YnwxODAwMDAwMDAw." <>
        "dee1893de8e9f57e974af43ec5b6e7523f7d09cee038a8edd5df59ad2f9248ba" <>
        "|phUfA189G9A5KMv3r+wzLA==|",
    "algorithm" => "sha256",
    "m_kib" => 0,
    "t" => 1,
    "p" => 1,
    "target_bits" => 8,
    "counter" => 158,
    "outcome" => "Valid"
  }

  def sha_vector, do: @sha_vector
  def ip_hash, do: "9c50b8d493de847656a168d0408bd4455994df2fc0b1e94bab5a85d64850034b"

  def golden_options(verify_opts, record_map, storage) do
    row_opts(%{"verify_opts" => verify_opts}, record_map, storage)
  end

  def row_opts(row, record_map, storage) do
    opts =
      Enum.reduce(
        row["verify_opts"],
        %{base: base_options(storage: storage, secret_key: secret())},
        fn
          {"expected_scope", v}, acc ->
            %{acc | base: Map.put(acc.base, :expected_scope, v)}

          {"region", v}, acc ->
            %{acc | base: Map.put(acc.base, :region, v)}

          {"expected_issuer", v}, acc ->
            %{acc | base: Map.put(acc.base, :expected_issuer, v)}

          {"expected_policy_version", v}, acc ->
            %{acc | base: Map.put(acc.base, :expected_policy_version, v)}

          {"client_ip", v}, acc ->
            %{acc | base: Map.put(acc.base, :client_ip, v)}

          {"expected_request_binding", v}, acc ->
            %{acc | base: Map.put(acc.base, :expected_request_binding, v)}

          {"secrets_by_kid", v}, acc ->
            by_kid =
              Map.new(v, fn {kid, secret} ->
                {String.to_integer(kid), if(is_nil(secret), do: secret(), else: secret)}
              end)

            %{acc | base: Map.put(acc.base, :secrets_by_kid, by_kid)}

          {"rsw", v}, acc ->
            %{
              acc
              | base:
                  Map.put(acc.base, :rsw, %{
                    modulus_n: v["modulus_n"],
                    lambda: v["lambda"],
                    verification_keys: %{},
                    allow_legacy_identity: false
                  })
            }

          _, acc ->
            acc
        end
      )

    Map.merge(opts.base, Map.new(frozen_clock(record_map)))
  end
end

defmodule Kiwicaptcha.Support.MemoryStoreCase do
  @moduledoc false
end
