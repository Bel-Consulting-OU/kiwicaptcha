defmodule Kiwicaptcha.Canonical do
  @moduledoc """
  The canonical signing bytes and the deployment binding tags, shared
  with the PHP Issuer and the Rust issuer byte for byte.

  Canonical payload revision 4:

      v4|protocol_version|nonce|scope|binding_tag|issued_at|expires_at|
        algorithm|m_kib|t|p|target_bits|salt|min_duration_ms|region|
        policy_version|request_binding|issuer|kid

  followed by the tagged extension segments in capability order:

      ...|kid|d=decoy_field|e=version,commitment|r=modulus_sha256|m=1
  """

  @pow_algorithms ["sha256", "argon2id", "rsw"]

  @doc "The three proof-of-work algorithms of the wire protocol."
  @spec pow_algorithms() :: [String.t()]
  def pow_algorithms, do: @pow_algorithms

  defmodule Args do
    @moduledoc false
    defstruct [
      :protocol_version,
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
      :min_duration_ms,
      :region,
      :policy_version,
      :request_binding,
      :issuer,
      :kid,
      :decoy_field,
      :execution_version,
      :execution_commitment,
      :rsw_modulus_sha256,
      :server_mac_committed
    ]
  end

  @doc """
  Assemble the canonical signing payload. The extension segments append
  only when armed, so the unarmed base keeps the plain field set. The
  execution pair and the metadata marker each change the signed bytes,
  so stripping or splicing any armed field breaks the signature.
  """
  @spec canonical_payload(Args.t()) :: String.t()
  def canonical_payload(%Args{} = a) do
    base =
      Enum.join(
        [
          "v4",
          a.protocol_version,
          a.nonce,
          a.scope,
          a.binding_tag,
          a.issued_at,
          a.expires_at,
          a.algorithm,
          a.m_kib,
          a.t,
          a.p,
          a.target_bits,
          a.salt,
          a.min_duration_ms,
          a.region || "",
          a.policy_version || 1,
          a.request_binding || "",
          a.issuer || "",
          a.kid || 1
        ],
        "|"
      )

    out =
      base
      |> maybe_append_decoy(a)
      |> maybe_append_execution(a)
      |> maybe_append_rsw(a)

    if a.server_mac_committed == true, do: out <> "|m=1", else: out
  end

  defp maybe_append_decoy(out, a) do
    if is_binary(a.decoy_field) and a.decoy_field != "",
      do: out <> "|d=#{a.decoy_field}",
      else: out
  end

  defp maybe_append_execution(out, a) do
    has_version = not is_nil(a.execution_version)
    has_commitment = not is_nil(a.execution_commitment)

    cond do
      has_version and has_commitment ->
        out <> "|e=#{a.execution_version},#{a.execution_commitment}"

      has_version or has_commitment ->
        raise ArgumentError, "execution_version and execution_commitment must be passed together"

      true ->
        out
    end
  end

  defp maybe_append_rsw(out, a) do
    if is_binary(a.rsw_modulus_sha256) and a.rsw_modulus_sha256 != "" do
      out <> "|r=#{a.rsw_modulus_sha256}"
    else
      out
    end
  end

  @doc """
  True when the challenge's signed canonical carries the record
  metadata MAC marker (m=1). The marker is parsed from the embedded
  canonical, never inferred from the stored MAC presence.
  """
  @spec signed_canonical_commits_record_meta?(String.t()) :: boolean()
  def signed_canonical_commits_record_meta?(challenge) do
    case String.split(challenge, ".", parts: 2) do
      [encoded, _sig] ->
        case Kiwicaptcha.B64.decode_std(encoded) do
          {:ok, canonical} ->
            String.starts_with?(canonical, "v4|") and String.ends_with?(canonical, "|m=1")

          :error ->
            false
        end

      _ ->
        false
    end
  end

  @doc """
  The authenticated execution commitment of a stored program: the hex
  SHA-256 of the program's base64 wire string.
  """
  @spec execution_commitment(String.t()) :: String.t()
  def execution_commitment(execution_program), do: sha256_hex(execution_program)

  @doc """
  Legacy v1 IP hash: the hex SHA-256 of salt followed by the raw IP
  string. Kept for v1 records inside the migration window.
  """
  @spec hash_ip(String.t(), String.t()) :: String.t()
  def hash_ip(ip, salt), do: sha256_hex(salt <> ip)

  @doc """
  The v1 signature: hex HMAC over the v1 payload keyed by the master
  secret directly. Migration window compatibility only.
  """
  @spec sign_payload_v1(String.t(), binary() | String.t()) :: String.t()
  def sign_payload_v1(canonical, secret_key) do
    Kiwicaptcha.Mac.hmac_hex(IO.iodata_to_binary([secret_key]), canonical)
  end

  @doc """
  The v2+ signature: hex HMAC over the canonical payload keyed by the
  HKDF derived challenge-signing purpose key (tenant scoped when a
  tenant id is configured).
  """
  @spec sign_payload_v2(String.t(), binary() | String.t(), String.t() | nil) :: String.t()
  def sign_payload_v2(canonical, secret_key, tenant_id \\ nil) do
    Kiwicaptcha.Mac.hmac_hex(
      Kiwicaptcha.Keys.derived_keys(secret_key, tenant_id).challenge_key,
      canonical
    )
  end

  @doc "Hex lowercase SHA-256."
  @spec sha256_hex(iodata()) :: String.t()
  def sha256_hex(data),
    do: Base.encode16(:crypto.hash(:sha256, IO.iodata_to_binary(data)), case: :lower)

  @doc "Raw SHA-256 digest."
  @spec sha256(iodata()) :: binary()
  def sha256(data), do: :crypto.hash(:sha256, IO.iodata_to_binary(data))

  @v4_strict ~r/\A(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\z/

  defp parse_ipv4(ip) do
    case Regex.run(@v4_strict, ip) do
      [_all, a, b, c, d] ->
        octets =
          [a, b, c, d]
          |> Enum.map(fn part ->
            if String.length(part) > 1 and String.starts_with?(part, "0") do
              :error
            else
              case Integer.parse(part) do
                {value, ""} when value <= 255 -> {:ok, value}
                _ -> :error
              end
            end
          end)

        if Enum.all?(octets, &match?({:ok, _}, &1)) do
          {:ok, for({:ok, v} <- octets, do: <<v>>) |> IO.iodata_to_binary()}
        else
          :error
        end

      nil ->
        :error
    end
  end

  defp parse_ipv6(ip) do
    if String.contains?(ip, "%") do
      :error
    else
      lower = String.downcase(ip)

      case :binary.matches(lower, "::") do
        [{pos, 2}] ->
          head = if pos == 0, do: [], else: String.split(binary_part(lower, 0, pos), ":")
          rest = binary_part(lower, pos + 2, byte_size(lower) - pos - 2)
          tail = if rest == "", do: [], else: String.split(rest, ":")
          finish_v6(head, tail, true)

        [] ->
          finish_v6(String.split(lower, ":"), [], false)

        _multiple ->
          :error
      end
    end
  end

  defp finish_v6(head, tail, has_dc) do
    {tail_groups, v4_bytes} =
      case List.last(tail) do
        last when is_binary(last) ->
          if String.contains?(last, ".") do
            case parse_ipv4(last) do
              {:ok, v4} -> {Enum.drop(tail, -1), v4}
              :error -> :fail
            end
          else
            {tail, nil}
          end

        _ ->
          {tail, nil}
      end

    if tail_groups == :fail do
      :error
    else
      groups = head ++ tail_groups

      groups_ok =
        Enum.all?(groups, fn g ->
          not String.contains?(g, ".") and Regex.match?(~r/\A[0-9A-Fa-f]{1,4}\z/, g)
        end)

      explicit = length(head) + length(tail_groups) + if v4_bytes, do: 2, else: 0

      cond do
        not groups_ok ->
          :error

        has_dc and explicit >= 8 ->
          :error

        not has_dc and explicit != 8 ->
          :error

        true ->
          # The double-colon expansion sits between the head and tail
          # groups: head, zeros, then the tail and any embedded IPv4.
          head_bytes =
            head
            |> Enum.map(fn g ->
              value = String.to_integer(g, 16)
              <<value::size(16)>>
            end)
            |> IO.iodata_to_binary()

          tail_bytes =
            tail_groups
            |> Enum.map(fn g ->
              value = String.to_integer(g, 16)
              <<value::size(16)>>
            end)
            |> IO.iodata_to_binary()

          missing = if has_dc, do: (8 - explicit) * 2, else: 0

          {:ok,
           IO.iodata_to_binary([
             head_bytes,
             :binary.copy(<<0>>, missing),
             tail_bytes,
             v4_bytes || <<>>
           ])}
      end
    end
  end

  @doc """
  Canonical family byte plus packed address bytes: the inet_pton output
  (4 or 16 bytes) with IPv4-mapped and IPv4-compatible IPv6 spellings
  normalized to the 4-byte IPv4 form. Two textual spellings of one
  address therefore produce the same bytes. Returns `:error` for any
  input outside the strict grammar.
  """
  @spec canonical_ip_family(String.t()) :: {:ok, binary()} | :error
  def canonical_ip_family(ip)

  def canonical_ip_family(""), do: :error

  def canonical_ip_family(ip) do
    if String.contains?(ip, ":") do
      with {:ok, v6} <- parse_ipv6(ip) do
        prefix = binary_part(v6, 0, 12)
        low = binary_part(v6, 12, 4)
        zeros12 = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
        mapped = prefix == <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF>>
        compatible = prefix == zeros12 and low not in [<<0, 0, 0, 0>>, <<0, 0, 0, 1>>]
        {:ok, if(mapped or compatible, do: <<4>> <> low, else: <<6>> <> v6)}
      end
    else
      case parse_ipv4(ip) do
        {:ok, v4} -> {:ok, <<4>> <> v4}
        :error -> :error
      end
    end
  end

  @ip_bind_domain "kiwicaptcha/ip-bind/v2\0"

  @doc """
  The nonce-bound IP binding tag of a v2+ record: hex HMAC over the
  domain string, the nonce and the canonical family bytes, keyed by the
  IP-binding purpose key. Raises Kiwicaptcha.RangeError for an IP outside the
  strict grammar, exactly like the PHP issuer.
  """
  @spec binding_tag(String.t(), String.t(), binary() | String.t(), String.t() | nil) :: String.t()
  def binding_tag(nonce, ip, secret, tenant_id \\ nil) do
    case canonical_ip_family(ip) do
      {:ok, family} ->
        message = IO.iodata_to_binary([@ip_bind_domain, nonce, <<0>>, family])

        Kiwicaptcha.Mac.hmac_hex(
          Kiwicaptcha.Keys.derived_keys(secret, tenant_id).ip_bind_key,
          message
        )

      :error ->
        raise Kiwicaptcha.RangeError, "invalid IP address: #{ip}"
    end
  end
end
