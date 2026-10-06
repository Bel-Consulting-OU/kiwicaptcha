defmodule Kiwicaptcha.Pow do
  @moduledoc """
  The proof-of-work derivation shared with the Rust and PHP cores. The
  SHA-256 password is prefix plus counter; the hash input is password
  followed by the raw salt bytes.
  """

  import Bitwise, only: [band: 2, bsl: 2]

  @solver_max_hashes 20_000_000

  @doc "The browser and wasm solver search ceiling."
  @spec solver_max_hashes :: pos_integer()
  def solver_max_hashes, do: @solver_max_hashes

  @doc "Count the leading zero bits of a digest (big endian bit order)."
  @spec leading_zero_bits(binary()) :: non_neg_integer()
  def leading_zero_bits(hash) do
    leading_zero_bits(:binary.bin_to_list(hash), 0)
  end

  defp leading_zero_bits([], count), do: count

  defp leading_zero_bits([byte | rest], count) do
    if byte == 0 do
      leading_zero_bits(rest, count + 8)
    else
      count + leading_zero_byte(byte, 0)
    end
  end

  defp leading_zero_byte(byte, n) when band(byte, 0x80) == 0,
    do: leading_zero_byte(band(bsl(byte, 1), 0xFF), n + 1)

  defp leading_zero_byte(_byte, n), do: n

  @doc "Derive the SHA-256 proof hash of a record at one counter value."
  @spec derive_sha256_hash(String.t(), non_neg_integer(), binary()) :: binary()
  def derive_sha256_hash(prefix, counter, salt_bytes) do
    Kiwicaptcha.Canonical.sha256([prefix, Integer.to_string(counter), salt_bytes])
  end

  @doc "Whether a derived hash meets the record's difficulty target."
  @spec meets_target?(binary(), non_neg_integer()) :: boolean()
  def meets_target?(hash, target_bits), do: leading_zero_bits(hash) >= target_bits

  @doc """
  Whether the native Argon2id binding (the argon2_elixir package) is
  loaded. The verify path recomputes argon2id rungs through it when
  present and refuses them loudly when it is not — never silently
  downgraded.
  """
  @spec argon2_available?() :: boolean()
  def argon2_available? do
    case Code.ensure_loaded(Argon2.Base) do
      {:module, _} -> function_exported?(Argon2.Base, :hash_password, 3)
      _ -> false
    end
  end

  @doc """
  Derive the Argon2id proof hash of a record at one counter value
  through the native binding. Returns nil when the binding is absent
  (the caller refuses the rung loudly) or the parameters leave the
  implementable space. The binding's memory cost is a log2 exponent,
  so a non-power-of-two m_kib refuses rather than rounding.
  """
  @spec derive_argon2id_hash(binary(), binary(), pos_integer(), pos_integer(), pos_integer(), pos_integer()) ::
          binary() | nil
  def derive_argon2id_hash(password, salt_bytes, t_cost, m_kib, lanes, out_len \\ 32) do
    if argon2_available?() and t_cost >= 1 and lanes >= 1 and m_kib >= 8 * lanes and
         power_of_two?(m_kib) and out_len >= 4 do
      hex =
        Argon2.Base.hash_password(password, salt_bytes,
          t_cost: t_cost,
          m_cost: log2_exact(m_kib),
          parallelism: lanes,
          hashlen: out_len,
          argon2_type: 2,
          format: :raw_hash
        )

      case Base.decode16(hex, case: :mixed) do
        {:ok, raw} -> raw
        :error -> nil
      end
    else
      nil
    end
  rescue
    _ -> nil
  end

  defp power_of_two?(n) when is_integer(n) and n > 0, do: band(n, n - 1) == 0
  defp power_of_two?(_), do: false

  defp log2_exact(n), do: log2_exact(n, 0)
  defp log2_exact(1, acc), do: acc
  defp log2_exact(n, acc) when n > 1, do: log2_exact(div(n, 2), acc + 1)

  @doc """
  Solve a SHA-256 challenge: the first counter whose hash meets the
  target. Used by the test suite and tooling; the production proof
  comes from the browser or native solver.
  """
  @spec solve_sha256(String.t(), String.t(), pos_integer()) :: non_neg_integer()
  def solve_sha256(prefix, salt_b64, target_bits) do
    {:ok, salt_bytes} = Kiwicaptcha.B64.decode_std(salt_b64)
    solve_from(prefix, salt_bytes, target_bits, 0)
  end

  defp solve_from(_prefix, _salt, _bits, counter) when counter >= @solver_max_hashes do
    raise "no proof found below the solver ceiling"
  end

  defp solve_from(prefix, salt, bits, counter) do
    if meets_target?(derive_sha256_hash(prefix, counter, salt), bits) do
      counter
    else
      solve_from(prefix, salt, bits, counter + 1)
    end
  end
end
