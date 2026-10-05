defmodule Kiwicaptcha.Rsw do
  @moduledoc """
  The RSW time-lock trapdoor and its shared arithmetic on native
  bignums. The client squares a challenge-derived base T times modulo
  a 2048-bit composite n; the server computes base raised to the power
  two-to-the-T modulo lambda, then modulo n, with one modular
  exponentiation. Byte compatible with the PHP Rsw class and the Rust
  rsw module: the expected final value renders as the fixed 512-hex
  wire form.
  """

  @modulus_bytes 256
  @proof_hex_length 512
  @t_min 10_000
  @t_max 300_000
  @selftest_bases [2, 3, 5, 7, 11, 13, 17, 19]
  @miller_rabin_rounds 40

  defstruct [:n, :lambda, :modulus_n]

  @type t :: %__MODULE__{n: non_neg_integer(), lambda: non_neg_integer(), modulus_n: String.t()}

  @doc "The wire byte length of a modulus."
  @spec modulus_bytes :: pos_integer()
  def modulus_bytes, do: @modulus_bytes

  @doc "The fixed proof hex length."
  @spec proof_hex_length :: pos_integer()
  def proof_hex_length, do: @proof_hex_length

  @doc "The issuance range of the sequential cost."
  def t_min, do: @t_min
  def t_max, do: @t_max

  @doc "Binary modular exponentiation on native bignums."
  @spec powm(non_neg_integer(), non_neg_integer(), pos_integer()) :: non_neg_integer()
  def powm(base, exponent, modulus)

  def powm(_base, _exponent, 1), do: 0

  def powm(base, exponent, modulus) do
    do_powm(Integer.mod(base, modulus), exponent, 1, modulus)
  end

  defp do_powm(_b, 0, acc, _modulus), do: acc

  defp do_powm(b, exponent, acc, modulus) do
    acc2 = if Bitwise.band(exponent, 1) == 1, do: Integer.mod(acc * b, modulus), else: acc
    do_powm(Integer.mod(b * b, modulus), Bitwise.bsr(exponent, 1), acc2, modulus)
  end

  @doc """
  Miller-Rabin probabilistic primality with the fixed deterministic
  base ladder shared with the other cores, so accept and reject
  decisions never drift between runtimes.
  """
  @spec probable_prime?(non_neg_integer()) :: boolean()
  def probable_prime?(n) when n < 2, do: false

  def probable_prime?(n) do
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

    if Enum.any?(small, fn p -> Integer.mod(n, p) == 0 end) do
      n in small
    else
      {d, r} = factor_twos(n - 1, 0)
      miller_rounds(n, d, r, 0)
    end
  end

  defp factor_twos(d, r) do
    if Bitwise.band(d, 1) == 0, do: factor_twos(Bitwise.bsr(d, 1), r + 1), else: {d, r}
  end

  defp miller_rounds(_n, _d, _r, i) when i >= @miller_rabin_rounds, do: true

  defp miller_rounds(n, d, r, i) do
    a = 2 + Integer.mod(i * 7919 + 104_729, 1_000_003)
    x = powm(Integer.mod(a, n), d, n)

    if x == 1 or x == n - 1 do
      miller_rounds(n, d, r, i + 1)
    else
      if composite_loop(x, n, r - 1), do: false, else: miller_rounds(n, d, r, i + 1)
    end
  end

  defp composite_loop(_x, _n, j) when j <= 0, do: true

  defp composite_loop(x, n, j) do
    x2 = Integer.mod(x * x, n)

    if x2 == n - 1, do: false, else: composite_loop(x2, n, j - 1)
  end

  @doc "The canonical fingerprint of a modulus: hex SHA-256 of the decoded bytes."
  @spec modulus_fingerprint_hex(String.t()) :: String.t()
  def modulus_fingerprint_hex(modulus_b64) do
    case Kiwicaptcha.B64.decode_std(modulus_b64) do
      {:ok, bytes} -> Kiwicaptcha.Canonical.sha256_hex(bytes)
      :error -> raise Kiwicaptcha.RangeError, "the modulus must be canonical standard base64"
    end
  end

  @doc """
  Whether an identity is the accepted fingerprint form of a modulus:
  the canonical fingerprint always, the legacy base64-text alias only
  while the bounded migration mode is enabled.
  """
  @spec identity_matches?(String.t(), String.t(), boolean()) :: boolean()
  def identity_matches?(identity, modulus_n_base64, allow_legacy_alias) do
    identity == modulus_fingerprint_hex(modulus_n_base64) or
      (allow_legacy_alias and identity == Kiwicaptcha.Canonical.sha256_hex(modulus_n_base64))
  end

  @doc "The challenge-derived base: SHA-256 of prefix plus nonce, reduced modulo n."
  @spec derive_base(String.t(), String.t(), pos_integer()) :: non_neg_integer()
  def derive_base(prefix, nonce, n) do
    digest = Kiwicaptcha.Canonical.sha256([prefix, nonce])

    :crypto.bytes_to_integer(digest)
    |> Integer.mod(n)
  end

  @doc "The fixed 512-hex wire form of a residue."
  @spec proof_hex(non_neg_integer()) :: String.t()
  def proof_hex(value) do
    value
    |> Integer.to_string(16)
    |> String.downcase()
    |> then(fn hex -> if rem(String.length(hex), 2) == 1, do: "0" <> hex, else: hex end)
    |> String.pad_leading(@proof_hex_length, "0")
  end

  @doc """
  Decode and validate a trapdoor pair: the shape, the small-prime
  factors, probable primality and the trapdoor consistency spot-check,
  mirroring the PHP rejections. Raises Kiwicaptcha.RangeError on any violation.
  """
  @spec new_trapdoor(String.t(), String.t()) :: t()
  def new_trapdoor(modulus_b64, lambda_b64) do
    n = decode_modulus(modulus_b64)
    lam = decode_lambda(lambda_b64)
    reject_small_prime_factor(n)

    if probable_prime?(n) do
      raise Kiwicaptcha.RangeError,
            "rsw_modulus_n must not itself be a probable prime (a genuine 2048-bit modulus is the product of two large primes)"
    end

    unless trapdoor_consistent?(n, lam) do
      raise Kiwicaptcha.RangeError,
            "rsw_lambda is not a matching trapdoor for rsw_modulus_n (the lambda shortcut diverges from sequential squaring)"
    end

    %__MODULE__{n: n, lambda: lam, modulus_n: modulus_b64}
  end

  @doc """
  The expected final value of a challenge as the fixed 512-hex wire
  form: base raised to (two to the T modulo lambda) modulo n, base the
  challenge-derived residue.
  """
  @spec expected_proof_hex(t(), String.t(), String.t(), pos_integer()) :: String.t()
  def expected_proof_hex(%__MODULE__{} = trapdoor, prefix, nonce, t) do
    base = derive_base(prefix, nonce, trapdoor.n)
    exponent = powm(2, t, trapdoor.lambda)
    proof_hex(powm(base, exponent, trapdoor.n))
  end

  defp decode_modulus(modulus_b64) do
    bytes =
      case Kiwicaptcha.B64.decode_std(modulus_b64) do
        {:ok, bytes} -> bytes
        :error -> raise Kiwicaptcha.RangeError, "rsw_modulus_n must be canonical standard base64"
      end

    if byte_size(bytes) != @modulus_bytes do
      raise Kiwicaptcha.RangeError,
            "rsw_modulus_n must be the base64 of exactly #{@modulus_bytes} bytes, got #{byte_size(bytes)}"
    end

    first = :binary.at(bytes, 0)
    last = :binary.at(bytes, byte_size(bytes) - 1)

    if Bitwise.band(first, 0x80) == 0 do
      raise Kiwicaptcha.RangeError,
            "rsw_modulus_n must have its top bit set (a genuine 2048-bit composite)"
    end

    if Bitwise.band(last, 1) == 0 do
      raise Kiwicaptcha.RangeError, "rsw_modulus_n must be odd (the product of two odd primes)"
    end

    :crypto.bytes_to_integer(bytes)
  end

  defp decode_lambda(lambda_b64) do
    bytes =
      case Kiwicaptcha.B64.decode_std(lambda_b64) do
        {:ok, bytes} -> bytes
        :error -> raise Kiwicaptcha.RangeError, "rsw_lambda must be canonical standard base64"
      end

    if byte_size(bytes) == 0 or byte_size(bytes) > @modulus_bytes do
      raise Kiwicaptcha.RangeError, "rsw_lambda must be the base64 of 1..#{@modulus_bytes} bytes"
    end

    last = :binary.at(bytes, byte_size(bytes) - 1)

    if Bitwise.band(last, 1) == 1 do
      raise Kiwicaptcha.RangeError, "rsw_lambda must be even (lcm(p-1, q-1) of two odd primes)"
    end

    :crypto.bytes_to_integer(bytes)
  end

  defp small_primes do
    limit = 1000

    sieve =
      Enum.reduce(2..limit, MapSet.new(2..limit), fn p, acc ->
        if MapSet.member?(acc, p) do
          # Step 1 explicitly: p*p can exceed limit, where the bare
          # first..last form would read as a descending range.
          Enum.reduce(Enum.take_every(Range.new(p * p, limit, 1), p), acc, fn m, s ->
            MapSet.delete(s, m)
          end)
        else
          acc
        end
      end)

    Enum.filter(2..limit, fn c -> MapSet.member?(sieve, c) end)
  end

  defp reject_small_prime_factor(n) do
    Enum.each(small_primes(), fn prime ->
      if prime != 2 and Integer.mod(n, prime) == 0 do
        raise Kiwicaptcha.RangeError,
              "rsw_modulus_n must not be divisible by a small prime (found #{prime})"
      end
    end)
  end

  defp trapdoor_consistent?(n, lambda) do
    Enum.all?(@selftest_bases, fn base -> powm(base, lambda, n) == 1 end)
  end
end
