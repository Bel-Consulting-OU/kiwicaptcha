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
