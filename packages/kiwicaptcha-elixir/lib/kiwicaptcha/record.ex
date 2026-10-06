defmodule Kiwicaptcha.Record do
  @moduledoc """
  The server-side challenge record and its strict serde mirror parser,
  mirroring the Rust ChallengeRecord field names one to one so PHP,
  Rust, Node, Ruby and Elixir share the same Redis and SQLite records.
  """

  @max_protocol_version 5
  @base_protocol_version 2
  @decoy_protocol_version 3
  @execution_protocol_version 4
  @rsw_identity_protocol_version 5
  @max_string_bytes 4096
  @max_execution_version 6
  @max_program_base64 4096
  @u32_max 4_294_967_295

  @wire_keys ~w[
    nonce scope binding_tag issued_at expires_at
    algorithm m_kib t p target_bits salt prefix
    challenge min_duration_ms issued_at_ns protocol_version
    attempts_used region policy_version request_binding
    issuer kid hostname decoy_field execution_program
    execution_version execution_commitment rsw_modulus_sha256
    server_mac
  ]

  @required_keys ~w[
    nonce scope binding_tag issued_at expires_at
    algorithm m_kib t p target_bits salt prefix
    challenge min_duration_ms
  ]

  defstruct [
    :nonce,
    :scope,
    :binding_tag,
    :issued_at,
    :expires_at,
    :algorithm,
    :m_kib,
    :t,
    :p,
    :target_bits,
    :salt,
    :prefix,
    :challenge,
    :min_duration_ms,
    :issued_at_ns,
    :protocol_version,
    :region,
    :policy_version,
    :request_binding,
    :issuer,
    :kid,
    :hostname,
    :decoy_field,
    :execution_program,
    :execution_version,
    :execution_commitment,
    :rsw_modulus_sha256,
    :server_mac
  ]

  @type t :: %__MODULE__{}

  @doc "The wire ceilings the parser enforces."
  def max_protocol_version, do: @max_protocol_version
  def base_protocol_version, do: @base_protocol_version
  def decoy_protocol_version, do: @decoy_protocol_version
  def execution_protocol_version, do: @execution_protocol_version
  def rsw_identity_protocol_version, do: @rsw_identity_protocol_version
  def max_string_bytes, do: @max_string_bytes
  def max_execution_version, do: @max_execution_version
  def max_program_base64, do: @max_program_base64

  @doc """
  The narrow security-identifier alphabet: deployment-bound
  identifiers can never smuggle canonical separators, whitespace or
  multi-byte text into a signed payload segment.
  """
  @spec valid_identifier?(term(), pos_integer()) :: boolean()
  def valid_identifier?(value, max_bytes) when is_binary(value) do
    value != "" and byte_size(value) <= max_bytes and
      Regex.match?(~r/\A[A-Za-z0-9._:-]+\z/, value)
  end

  def valid_identifier?(_, _), do: false

  @doc "The decoy (honeypot) field-name grammar."
  @spec valid_decoy_field_name?(term()) :: boolean()
  def valid_decoy_field_name?(value) when is_binary(value) do
    String.length(value) in 1..64 and Regex.match?(~r/\A[A-Za-z0-9_-]+\z/, value)
  end

  def valid_decoy_field_name?(_), do: false

  @doc """
  The protocol versus extension grammar, the one shared matrix every
  boundary applies: v1 and v2 carry neither extension, v3 requires the
  decoy, v4 requires the execution triplet, v5 requires the rsw
  identity.
  """

  import Bitwise, only: [bsl: 2]

  @spec protocol_extension_grammar_ok?(pos_integer(), boolean(), boolean(), boolean()) ::
          boolean()
  def protocol_extension_grammar_ok?(
        protocol_version,
        decoy_present,
        execution_present,
        rsw_identity_present
      )

  def protocol_extension_grammar_ok?(1, false, false, false), do: true
  def protocol_extension_grammar_ok?(1, _, _, _), do: false
  def protocol_extension_grammar_ok?(2, false, false, _), do: true
  def protocol_extension_grammar_ok?(2, _, _, _), do: false
  def protocol_extension_grammar_ok?(3, true, false, _), do: true
  def protocol_extension_grammar_ok?(3, _, _, _), do: false
  def protocol_extension_grammar_ok?(4, _, true, _), do: true
  def protocol_extension_grammar_ok?(4, _, _, _), do: false
  def protocol_extension_grammar_ok?(5, _, _, true), do: true
  def protocol_extension_grammar_ok?(5, _, _, _), do: false
  def protocol_extension_grammar_ok?(_, _, _, _), do: false

  @doc """
  The base64 wire shape of an execution program: a structural check
  only (canonical base64 within the ceiling). The full grammar runs in
  the issuing interpreter; this boundary keeps persisted reads
  independent of any interpreter.
  """
  @spec valid_program_shape?(term()) :: boolean()
  def valid_program_shape?(program_b64) when is_binary(program_b64) do
    match?({:ok, _}, Kiwicaptcha.B64.decode_std(program_b64))
  end

  def valid_program_shape?(_), do: false

  @doc """
  Rebuild a record from persisted JSON data with the strict serde
  semantics: whitelisted keys only, exact algorithm values, strict
  integer ranges, the legacy ip_hash alias, the total protocol grammar
  and the exact execution triplet equivalence.
  """
  @spec from_json(map() | String.t()) ::
          {:ok, t()} | {:error, Kiwicaptcha.MalformedRecordError.t()}
  def from_json(json) when is_binary(json) do
    case Kiwicaptcha.Json.decode(json) do
      {:ok, decoded} -> from_json(decoded)
      :error -> malformed("the record must be a JSON object")
    end
  end

  def from_json(json) when is_map(json) and not is_struct(json) do
    from_map(stringify_keys(json))
  end

  def from_json(_), do: malformed("the record must be a JSON object")

  defp from_map(data) do
    with :ok <- check_unknown_keys(data),
         {:ok, data} <- maybe_alias_ip_hash(data),
         :ok <- check_required(data),
         {:ok, data} <- parse_ints(data),
         protocol_version = data["protocol_version"],
         {:ok, algorithm} <- fetch_algorithm(data),
         {:ok, data} <- check_identifiers(data),
         {:ok, decoy} <- fetch_decoy(data),
         {:ok, program, execution_version, execution_commitment} <- fetch_execution(data),
         {:ok, rsw_identity} <- fetch_rsw_identity(data, algorithm, protocol_version),
         :ok <- grammar_gate(protocol_version, decoy, program, rsw_identity),
         {:ok, server_mac} <- fetch_server_mac(data),
         {:ok, hostname} <- fetch_hostname(data) do
      {:ok,
       %__MODULE__{
         nonce: data["nonce"],
         scope: data["scope"],
         binding_tag: data["binding_tag"],
         issued_at: data["issued_at"],
         expires_at: data["expires_at"],
         algorithm: algorithm,
         m_kib: data["m_kib"],
         t: data["t"],
         p: data["p"],
         target_bits: data["target_bits"],
         salt: data["salt"],
         prefix: data["prefix"],
         challenge: data["challenge"],
         min_duration_ms: data["min_duration_ms"],
         issued_at_ns: data["issued_at_ns"],
         protocol_version: protocol_version,
         region: opt(data, "region"),
         policy_version: data["policy_version"],
         request_binding: opt(data, "request_binding"),
         issuer: opt(data, "issuer"),
         kid: data["kid"],
         hostname: hostname,
         decoy_field: decoy,
         execution_program: program,
         execution_version: execution_version,
         execution_commitment: execution_commitment,
         rsw_modulus_sha256: rsw_identity,
         server_mac: server_mac
       }}
    end
  end

  defp malformed(message), do: {:error, %Kiwicaptcha.MalformedRecordError{message: message}}

  defp stringify_keys(map), do: Map.new(map, fn {k, v} -> {to_string(k), v} end)

  defp check_unknown_keys(data) do
    Enum.find(data, fn {key, _} -> key != "ip_hash" and key not in @wire_keys end)
    |> case do
      nil -> :ok
      {key, _} -> malformed("unknown record key: #{key}")
    end
  end

  defp maybe_alias_ip_hash(data) do
    if Map.has_key?(data, "ip_hash") do
      if Map.has_key?(data, "binding_tag") do
        malformed("binding_tag and ip_hash may not appear together")
      else
        {:ok, Map.put(data, "binding_tag", data["ip_hash"])}
      end
    else
      {:ok, data}
    end
  end

  defp check_required(data) do
    missing = Enum.find(@required_keys, fn field -> not Map.has_key?(data, field) end)
    if missing, do: malformed("missing record field: #{missing}"), else: :ok
  end

  defp parse_ints(data) do
    with {:ok, data} <-
           require_ints(data, ~w[issued_at expires_at min_duration_ms], :mandatory, bsl(1, 62)),
         {:ok, data} <- require_ints(data, ~w[issued_at_ns], 0, bsl(1, 62)),
         {:ok, data} <- require_ints(data, ~w[m_kib t p target_bits attempts_used], 0, @u32_max),
         {:ok, data} <- require_ints(data, ~w[policy_version kid], 1, @u32_max) do
      require_ints(data, ~w[protocol_version], 1, @max_protocol_version)
    end
  end

  # Integer group parsing: `default` of :mandatory means each key must
  # exist, otherwise the default fills absent keys. Every bound is the
  # inclusive maximum; the floor is always zero. Returns the updated
  # map so the from_json chain keeps threading data through.
  @spec require_ints(map(), [String.t()], :mandatory | integer(), integer()) ::
          {:ok, map()} | {:error, Kiwicaptcha.MalformedRecordError.t()}
  defp require_ints(data, fields, default, max) do
    Enum.reduce_while(fields, {:ok, data}, fn field, {:ok, acc} ->
      cond do
        default == :mandatory and not Map.has_key?(acc, field) ->
          {:halt, malformed("missing record field: #{field}")}

        not Map.has_key?(acc, field) ->
          {:cont, {:ok, Map.put(acc, field, default)}}

        true ->
          value = acc[field]

          if is_integer(value) and value >= 0 and value <= max do
            {:cont, {:ok, acc}}
          else
            {:halt, malformed("#{field} must be an integer within 0..#{max}")}
          end
      end
    end)
  end

  defp fetch_algorithm(data) do
    algorithm = data["algorithm"]

    if algorithm in Kiwicaptcha.Canonical.pow_algorithms() do
      {:ok, algorithm}
    else
      malformed("invalid algorithm: #{inspect(algorithm)}")
    end
  end

  defp check_identifiers(data) do
    Enum.reduce_while([{"region", 64}, {"request_binding", 128}, {"issuer", 128}], {:ok, data}, fn
      {field, max}, {:ok, acc} ->
        value = acc[field]

        if is_nil(value) or Kiwicaptcha.Record.valid_identifier?(value, max) do
          {:cont, {:ok, acc}}
        else
          {:halt, malformed("#{field} must match the identifier alphabet")}
        end
    end)
  end

  defp fetch_decoy(data) do
    decoy = opt(data, "decoy_field")

    if is_nil(decoy) or valid_decoy_field_name?(decoy) do
      {:ok, decoy}
    else
      malformed("decoy_field must match the decoy name alphabet")
    end
  end

  defp fetch_execution(data) do
    program = opt(data, "execution_program")
    has_version = not is_nil(data["execution_version"])
    has_commitment = not is_nil(data["execution_commitment"])

    cond do
      is_nil(program) and not has_version and not has_commitment ->
        {:ok, nil, nil, nil}

      is_nil(program) or not has_version or not has_commitment ->
        malformed("the execution triplet must be present together")

      true ->
        if byte_size(program) > @max_program_base64 do
          malformed("execution_program exceeds the program ceiling")
        else
          if valid_program_shape?(program) do
            version = data["execution_version"]

            with true <-
                   is_integer(version) and version >= 1 and version <= @max_execution_version,
                 {:ok, commitment} <- require_string_field(data, "execution_commitment") do
              cond do
                not Regex.match?(~r/\A[0-9a-f]{64}\z/, commitment) ->
                  malformed("execution_commitment must be 64 lowercase hex characters")

                Kiwicaptcha.Canonical.sha256_hex(program) != commitment ->
                  malformed("execution_commitment does not match the stored program")

                true ->
                  {:ok, program, version, commitment}
              end
            else
              _ ->
                malformed(
                  "execution_version must be an integer within 1..#{@max_execution_version}"
                )
            end
          else
            malformed("execution_program is not a well-formed program blob")
          end
        end
    end
  end

  defp require_string_field(data, field) do
    case data[field] do
      value when is_binary(value) ->
        if byte_size(value) > @max_string_bytes do
          malformed("#{field} exceeds the wire string ceiling")
        else
          {:ok, value}
        end

      _ ->
        malformed("#{field} must be a string")
    end
  end

  defp fetch_rsw_identity(data, algorithm, protocol_version) do
    identity = data["rsw_modulus_sha256"]

    cond do
      is_nil(identity) ->
        {:ok, nil}

      not is_binary(identity) or not Regex.match?(~r/\A[0-9a-f]{64}\z/, identity) ->
        malformed("rsw_modulus_sha256 must be 64 lowercase hex characters")

      algorithm != "rsw" ->
        malformed("rsw_modulus_sha256 may only ride an rsw record")

      protocol_version == 1 ->
        malformed(
          "rsw_modulus_sha256 may not ride the v1 canonical (the v1 signature carries no identity segment)"
        )

      true ->
        {:ok, identity}
    end
  end

  defp grammar_gate(protocol_version, decoy, program, rsw_identity) do
    if protocol_extension_grammar_ok?(
         protocol_version,
         not is_nil(decoy),
         not is_nil(program),
         not is_nil(rsw_identity)
       ) do
      :ok
    else
      malformed("invalid protocol/extension combination for version #{protocol_version}")
    end
  end

  defp fetch_server_mac(data) do
    mac = data["server_mac"]

    cond do
      is_nil(mac) ->
        {:ok, nil}

      not is_binary(mac) or not Regex.match?(Kiwicaptcha.Mac.server_state_mac_pattern(), mac) ->
        malformed("server_mac must be 64 lowercase hex characters")

      true ->
        {:ok, mac}
    end
  end

  defp fetch_hostname(data) do
    hostname = data["hostname"]

    cond do
      is_nil(hostname) ->
        {:ok, nil}

      not is_binary(hostname) ->
        malformed("hostname must be a string")

      byte_size(hostname) > @max_string_bytes ->
        malformed("hostname exceeds the wire string ceiling")

      hostname == "" ->
        malformed("hostname must be a non-empty string or null")

      Regex.match?(~r/[\x00-\x20\x7f]/, hostname) ->
        malformed("hostname must not carry whitespace or control characters")

      true ->
        {:ok, hostname}
    end
  end

  defp opt(data, field) do
    case Map.get(data, field) do
      nil -> nil
      value when is_binary(value) -> value
      _ -> nil
    end
  end

  @doc "Serialize a record to the canonical wire JSON object (v2 key set)."
  @spec to_json_map(t()) :: map()
  def to_json_map(%__MODULE__{} = record) do
    base = %{
      "nonce" => record.nonce,
      "scope" => record.scope,
      "binding_tag" => record.binding_tag,
      "issued_at" => record.issued_at,
      "expires_at" => record.expires_at,
      "algorithm" => record.algorithm,
      "m_kib" => record.m_kib,
      "t" => record.t,
      "p" => record.p,
      "target_bits" => record.target_bits,
      "salt" => record.salt,
      "prefix" => record.prefix,
      "challenge" => record.challenge,
      "min_duration_ms" => record.min_duration_ms,
      "issued_at_ns" => record.issued_at_ns,
      "protocol_version" => record.protocol_version,
      "attempts_used" => 0,
      "region" => record.region,
      "policy_version" => record.policy_version,
      "request_binding" => record.request_binding,
      "issuer" => record.issuer,
      "kid" => record.kid,
      "hostname" => record.hostname
    }

    base
    |> maybe_put("decoy_field", record.decoy_field)
    |> maybe_put("execution_program", record.execution_program)
    |> maybe_put("execution_version", record.execution_version)
    |> maybe_put("execution_commitment", record.execution_commitment)
    |> maybe_put("rsw_modulus_sha256", record.rsw_modulus_sha256)
    |> maybe_put("server_mac", record.server_mac)
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  @doc "Serialize a record to the canonical wire JSON document."
  @spec to_json(t()) :: String.t()
  def to_json(record) do
    Kiwicaptcha.Json.encode!(to_json_map(record))
  end
end
