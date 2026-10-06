defmodule Kiwicaptcha.ClientIp do
  @moduledoc """
  The trusted client-IP resolver: the canonical client IP of a request
  is its socket peer unless the peer sits inside the configured
  trusted-proxy CIDR list. An empty list trusts nobody, so a client
  supplied forwarding header can never move the IP binding. With a
  trusted peer, the X-Forwarded-For chain is walked right to left:
  entries inside the trust list are skipped, the first untrusted entry
  wins, and an entry that fails strict IP parsing terminates the walk
  and falls back to the peer. X-Real-IP is honored only when the peer
  is trusted and no forwarded chain exists. The algorithm ports the
  Symfony bundle's ClientIpResolver trusted-chain walk, so every SDK
  binds the same canonical IP for the same request.
  """

  import Bitwise

  @control_bytes ~r/[\x00-\x1F\x7F]/

  @type packed :: binary()
  @type family :: 4 | 6

  @doc """
  The canonical client IP per the shared trusted-proxy contract.

  * `:peer` is the socket peer text.
  * `:xff` is the merged X-Forwarded-For value, a list of header
    lines, or nil.
  * `:real_ip` is the X-Real-IP value (or nil).
  * `:trusted_proxies` is the trusted CIDR list; empty trusts nobody.
  """
  @spec resolve(keyword()) :: String.t()
  def resolve(opts) do
    peer = opts |> Keyword.get(:peer, "") |> to_string() |> String.trim()
    trusted = trusted_list(Keyword.get(opts, :trusted_proxies, []))

    if trusted == [] do
      peer
    else
      lines = forwarded_lines(Keyword.get(opts, :xff))

      cond do
        # A repeated forwarding header is parser ambiguity: one
        # intermediary reads the first line, another the last, so the
        # peer wins.
        length(lines) > 1 -> peer
        lines == [] -> resolve_real_ip(peer, trusted, Keyword.get(opts, :real_ip))
        true -> resolve_chain(peer, trusted, hd(lines))
      end
    end
  end

  @doc """
  The canonical text of one forwarded node, or nil when the node is
  not a genuine address. Handles bare IPv4, IPv4 with a port,
  bracketed IPv6 with an optional port, rejects unknown and obfuscated
  tokens and malformed ports, and normalizes IPv4-mapped IPv6 to its
  IPv4 form.
  """
  @spec canonical_ip(term()) :: String.t() | nil
  def canonical_ip(nil), do: nil

  def canonical_ip(identifier) do
    value = identifier |> to_string() |> String.trim()

    cond do
      value == "" or value == "unknown" or String.starts_with?(value, "_") ->
        nil

      true ->
        value
        |> strip_forwarded_dressing()
        |> parse_and_canonicalize()
    end
  end

  @doc """
  Whether one IP text sits inside any trusted CIDR. Host bits set in a
  CIDR are masked away, and an IPv4-mapped IPv6 address matches in its
  IPv4 form.
  """
  @spec in_trusted?(term(), [String.t()]) :: boolean()
  def in_trusted?(ip_text, trusted) do
    case parse_address(to_string(ip_text)) do
      {:ok, packed, 4} ->
        Enum.any?(trusted, &match_cidr?(&1, packed, 4))

      {:ok, packed, 6} ->
        case ipv4_mapped_of(packed) do
          {:ok, v4} -> Enum.any?(trusted, &match_cidr?(&1, v4, 4))
          :error -> Enum.any?(trusted, &match_cidr?(&1, packed, 6))
        end

      :error ->
        false
    end
  end

  ## The chain walk: right to left, trusted hops are skipped, the
  ## first untrusted entry wins, and an unparsable hop terminates the
  ## walk with the peer (who lies beyond it cannot be established).

  defp resolve_chain(peer, trusted, header) do
    cond do
      Regex.match?(@control_bytes, header) -> peer
      not trusted_peer?(peer, trusted) -> peer
      true -> walk_chain(Enum.reverse(String.split(header, ",")), trusted, peer)
    end
  end

  defp walk_chain([], _trusted, peer), do: peer

  defp walk_chain([hop | rest], trusted, peer) do
    canonical = canonical_ip(hop)

    cond do
      is_nil(canonical) -> peer
      not in_trusted?(canonical, trusted) -> canonical
      true -> walk_chain(rest, trusted, peer)
    end
  end

  defp resolve_real_ip(peer, trusted, real_ip) do
    candidate = real_ip |> to_string() |> String.trim()

    cond do
      not trusted_peer?(peer, trusted) -> peer
      candidate == "" -> peer
      Regex.match?(@control_bytes, candidate) -> peer
      true -> canonical_ip(candidate) || peer
    end
  end

  # Plug merges repeated header lines into one comma-joined value, so
  # a string arrives as the merged chain and a list as raw lines.
  defp forwarded_lines(nil), do: []

  defp forwarded_lines(lines) when is_list(lines) do
    Enum.filter(lines, fn line -> is_binary(line) and String.trim(line) != "" end)
  end

  defp forwarded_lines(value) do
    case value |> to_string() |> String.trim() do
      "" -> []
      merged -> [merged]
    end
  end

  defp trusted_list(list) do
    list |> Enum.map(&to_string/1) |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))
  end

  defp trusted_peer?(peer, trusted) do
    peer != "" and in_trusted?(String.trim(peer, "[]"), trusted)
  end

  ## The forwarded-node grammar: bracket and port dressing first, then
  ## the strict address validation.

  defp strip_forwarded_dressing(value) do
    cond do
      String.starts_with?(value, "[") ->
        strip_bracketed(value)

      count_colons(value) == 1 ->
        ipv4_port_split(value)

      true ->
        ambiguous_v6_port_split(value)
    end
  end

  defp strip_bracketed(value) do
    case String.split(value, "]", parts: 2) do
      [inside, rest] ->
        bare = String.trim_leading(inside, "[")

        cond do
          rest == "" -> bare
          valid_port_suffix?(rest) -> bare
          true -> nil
        end

      _ ->
        nil
    end
  end

  # IPv4 with a port: the port splits only when the left side is a
  # valid IPv4 and the port is a genuine number.
  defp ipv4_port_split(value) do
    case String.split(value, ":") do
      [left, right] ->
        if strict_ipv4?(left) and valid_port_suffix?(":" <> right) do
          left
        else
          ambiguous_v6_port_split(value)
        end

      _ ->
        ambiguous_v6_port_split(value)
    end
  end

  # A bare "v6:v4" remainder collapses only when the right side is a
  # real IPv4; the leftover rejects rather than guesses.
  defp ambiguous_v6_port_split(value) do
    if String.contains?(value, ":") and count_colons(value) < 2 do
      parts = String.split(value, ":")

      case Enum.split(parts, -1) do
        {head, [last]} ->
          if strict_ipv4?(last), do: Enum.join(head, ":"), else: value

        _ ->
          value
      end
    else
      value
    end
  end

  defp parse_and_canonicalize(nil), do: nil

  defp parse_and_canonicalize(candidate) do
    cond do
      String.contains?(candidate, ":") ->
        case parse_address(candidate) do
          # An IPv4-mapped IPv6 address normalizes to its IPv4 form,
          # so equivalent spellings cannot diverge downstream.
          {:ok, packed, 6} ->
            case ipv4_mapped_of(packed) do
              {:ok, v4} -> format_v4(v4)
              :error -> format_v6(packed)
            end

          _ ->
            nil
        end

      strict_ipv4?(candidate) ->
        case parse_address(candidate) do
          {:ok, packed, 4} -> format_v4(packed)
          _ -> nil
        end

      true ->
        nil
    end
  end

  ## Address parsing: {packed, family} or :error, zones refused.

  defp parse_address(text) do
    if String.contains?(text, "%") do
      :error
    else
      case :inet.parse_address(String.to_charlist(text)) do
        {:ok, {a, b, c, d}} ->
          {:ok, <<a::size(8), b::size(8), c::size(8), d::size(8)>>, 4}

        {:ok, {a, b, c, d, e, f, g, h}} ->
          {:ok,
           <<a::size(16), b::size(16), c::size(16), d::size(16), e::size(16), f::size(16), g::size(16),
             h::size(16)>>, 6}

        _ ->
          :error
      end
    end
  end

  # The 12 zero bytes and the ffff prefix of an IPv4-mapped address.
  defp ipv4_mapped_of(<<0::size(80), 0xFFFF::size(16), v4::binary-size(4)>>), do: {:ok, v4}
  defp ipv4_mapped_of(_packed), do: :error

  ## CIDR matching: host bits masked, families exact.

  defp match_cidr?(cidr, packed, family) do
    case parse_cidr(cidr) do
      {:ok, net_packed, net_family, prefix} when net_family == family ->
        prefix_match?(net_packed, packed, prefix)

      _ ->
        false
    end
  end

  defp prefix_match?(net_packed, packed, prefix) do
    full_bytes = div(prefix, 8)
    remainder = rem(prefix, 8)

    cond do
      byte_size(net_packed) != byte_size(packed) ->
        false

      binary_part(net_packed, 0, full_bytes) != binary_part(packed, 0, full_bytes) ->
        false

      remainder > 0 and full_bytes < byte_size(packed) ->
        mask = band(0xFF, 0xFF <<< (8 - remainder))
        band(:binary.at(net_packed, full_bytes), mask) == band(:binary.at(packed, full_bytes), mask)

      true ->
        true
    end
  end

  defp parse_cidr(cidr) do
    case String.split(cidr, "/", parts: 2) do
      [addr] ->
        case parse_address(addr) do
          {:ok, packed, family} -> {:ok, packed, family, byte_size(packed) * 8}
          :error -> :error
        end

      [addr, prefix_text] ->
        parse_cidr_prefix(addr, prefix_text)

      _ ->
        :error
    end
  end

  defp parse_cidr_prefix(addr, prefix_text) do
    case parse_address(addr) do
      {:ok, packed, family} ->
        with {prefix, ""} <- Integer.parse(prefix_text),
             true <- prefix >= 0 and prefix <= byte_size(packed) * 8 do
          {:ok, mask_packed(packed, prefix), family, prefix}
        else
          _ -> :error
        end

      :error ->
        :error
    end
  end

  defp mask_packed(packed, prefix) do
    full_bytes = div(prefix, 8)
    remainder = rem(prefix, 8)
    size = byte_size(packed)

    {masked_head, taken} =
      if remainder > 0 do
        mask = band(0xFF, 0xFF <<< (8 - remainder))
        byte = band(:binary.at(packed, full_bytes), mask)
        {<<binary_part(packed, 0, full_bytes)::binary, byte::size(8)>>, full_bytes + 1}
      else
        {binary_part(packed, 0, full_bytes), full_bytes}
      end

    masked_head <> :binary.copy(<<0>>, size - taken)
  end

  ## Canonical text: dotted IPv4, compressed lowercase IPv6.

  defp format_v4(<<a::size(8), b::size(8), c::size(8), d::size(8)>>) do
    "#{a}.#{b}.#{c}.#{d}"
  end

  defp format_v6(packed) do
    case ipv4_mapped_of(packed) do
      {:ok, v4} ->
        "::ffff:" <> format_v4(v4)

      :error ->
        groups =
          for <<group::size(16) <- packed>> do
            group |> Integer.to_string(16) |> String.downcase()
          end

        compress_zeros(groups)
    end
  end

  # The RFC 5952 compression: one longest zero run becomes "::".
  defp compress_zeros(groups) do
    {best_start, best_length} = longest_zero_run(groups, 0, nil, 0, {-1, 0})

    if best_length >= 2 do
      head = groups |> Enum.take(best_start) |> Enum.join(":")
      foot = groups |> Enum.drop(best_start + best_length) |> Enum.join(":")
      head <> "::" <> foot
    else
      Enum.join(groups, ":")
    end
  end

  defp longest_zero_run([], _index, _start, _length, best), do: best

  defp longest_zero_run([group | rest], index, start, length, {best_start, best_length}) do
    if group == "0" do
      start = start || index
      length = length + 1

      if length > best_length do
        longest_zero_run(rest, index + 1, start, length, {start, length})
      else
        longest_zero_run(rest, index + 1, start, length, {best_start, best_length})
      end
    else
      longest_zero_run(rest, index + 1, nil, 0, {best_start, best_length})
    end
  end

  defp strict_ipv4?(nil), do: false

  defp strict_ipv4?(text) do
    parts = String.split(text, ".")

    length(parts) == 4 and
      Enum.all?(parts, fn part ->
        String.length(part) in 1..3 and String.match?(part, ~r/\A\d+\z/) and
          not (String.length(part) > 1 and String.starts_with?(part, "0")) and
          String.to_integer(part) <= 255
      end)
  end

  # Exactly ":" plus a decimal port in the 1..65535 range.
  defp valid_port_suffix?(":" <> digits) do
    String.match?(digits, ~r/\A\d{1,5}\z/) and String.to_integer(digits) in 1..65_535
  end

  defp valid_port_suffix?(_), do: false

  defp count_colons(value), do: length(String.split(value, ":")) - 1
end
