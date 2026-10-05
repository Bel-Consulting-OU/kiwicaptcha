# frozen_string_literal: true

require 'digest'
require 'openssl'

module KiwiCaptcha
  # The RSW time-lock trapdoor and its shared arithmetic on native
  # bignums. The client squares a challenge-derived base T times modulo
  # a 2048-bit composite n; the server computes base raised to the
  # power two-to-the-T modulo lambda, then modulo n, with one modular
  # exponentiation. Byte compatible with the PHP Rsw class and the
  # Rust rsw module: the expected final value renders as the fixed
  # 512-hex wire form.
  module Rsw
    MODULUS_BYTES = 256
    PROOF_HEX_LENGTH = 512
    T_MIN = 10_000
    T_MAX = 300_000

    SMALL_PRIME_LIMIT = 1000
    SELFTEST_BASES = [2, 3, 5, 7, 11, 13, 17, 19].freeze
    MILLER_RABIN_ROUNDS = 40

    module_function

    def small_primes
      @small_primes ||= begin
        limit = SMALL_PRIME_LIMIT
        sieve = Array.new(limit + 1, true)
        sieve[0] = false
        sieve[1] = false
        p = 2
        while p * p <= limit
          if sieve[p]
            (p * p).step(limit, p) { |m| sieve[m] = false }
          end
          p += 1
        end
        (2..limit).select { |c| sieve[c] }
      end
    end

    def powm(base, exponent, modulus)
      base.pow(exponent, modulus)
    end

    # Miller-Rabin probabilistic primality with the fixed deterministic
    # base ladder shared with the other cores, so accept and reject
    # decisions never drift between runtimes.
    def probable_prime?(n)
      return false if n < 2

      [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37].each do |p|
        if (n % p).zero?
          return n == p
        end
      end
      d = n - 1
      r = 0
      while d.even?
        d >>= 1
        r += 1
      end
      MILLER_RABIN_ROUNDS.times do |i|
        a = 2 + ((i * 7919 + 104_729) % 1_000_003)
        x = powm(a % n, d, n)
        next if x == 1 || x == n - 1

        composite = true
        (r - 1).times do
          x = (x * x) % n
          if x == n - 1
            composite = false
            break
          end
        end
        return false if composite
      end
      true
    end

    def decode_modulus(modulus_b64)
      bytes = Base64Utils.decode_std(modulus_b64)
      raise RangeError, 'rsw_modulus_n must be canonical standard base64' if bytes.nil?
      raise RangeError, "rsw_modulus_n must be the base64 of exactly #{MODULUS_BYTES} bytes, got #{bytes.bytesize}" unless bytes.bytesize == MODULUS_BYTES

      first = bytes.getbyte(0)
      last = bytes.getbyte(bytes.bytesize - 1)
      raise RangeError, 'rsw_modulus_n must have its top bit set (a genuine 2048-bit composite)' if (first & 0x80).zero?
      raise RangeError, 'rsw_modulus_n must be odd (the product of two odd primes)' if (last & 1).zero?

      bytes.unpack1('H*').to_i(16)
    end

    def decode_lambda(lambda_b64)
      bytes = Base64Utils.decode_std(lambda_b64)
      raise RangeError, 'rsw_lambda must be canonical standard base64' if bytes.nil?
      if bytes.bytesize.zero? || bytes.bytesize > MODULUS_BYTES
        raise RangeError, "rsw_lambda must be the base64 of 1..#{MODULUS_BYTES} bytes"
      end
      raise RangeError, 'rsw_lambda must be even (lcm(p-1, q-1) of two odd primes)' unless (bytes.getbyte(bytes.bytesize - 1) & 1).zero?

      bytes.unpack1('H*').to_i(16)
    end

    def reject_small_prime_factor(n)
      small_primes.each do |prime|
        next if prime == 2

        if (n % prime).zero?
          raise RangeError, "rsw_modulus_n must not be divisible by a small prime (found #{prime})"
        end
      end
    end

    def trapdoor_consistent?(n, lambda)
      SELFTEST_BASES.all? { |base| powm(base, lambda, n) == 1 }
    end

    def proof_hex(value)
      hex = value.to_s(16)
      hex = "0#{hex}" if hex.length.odd?
      hex.rjust(PROOF_HEX_LENGTH, '0')
    end

    # The decoded and validated trapdoor pair. Construction validates
    # the shape, the small-prime factors, probable primality and the
    # trapdoor consistency spot-check, mirroring the PHP rejections.
    class Trapdoor
      attr_reader :n, :lambda, :modulus_n

      def initialize(modulus_b64, lambda_b64)
        n = Rsw.decode_modulus(modulus_b64)
        lam = Rsw.decode_lambda(lambda_b64)
        Rsw.reject_small_prime_factor(n)
        if Rsw.probable_prime?(n)
          raise RangeError, 'rsw_modulus_n must not itself be a probable prime (a genuine 2048-bit modulus is the product of two large primes)'
        end
        unless Rsw.trapdoor_consistent?(n, lam)
          raise RangeError, 'rsw_lambda is not a matching trapdoor for rsw_modulus_n (the lambda shortcut diverges from sequential squaring)'
        end

        @n = n
        @lambda = lam
        @modulus_n = modulus_b64
      end

      # The expected final value of a challenge as the fixed 512-hex
      # wire form: base raised to (two to the T modulo lambda) modulo
      # n, base the challenge-derived residue.
      def expected_proof_hex(prefix, nonce, t)
        base = Rsw.derive_base(prefix, nonce, @n)
        exponent = Rsw.powm(2, t, @lambda)
        Rsw.proof_hex(base.pow(exponent, @n))
      end
    end

    # The challenge-derived base: SHA-256 of prefix plus nonce bytes,
    # reduced modulo n.
    def derive_base(prefix, nonce, n)
      digest = Digest::SHA256.digest("#{prefix}#{nonce}".b)
      digest.unpack1('H*').to_i(16) % n
    end

    # The fixed 512-hex wire form of a residue.
    def rsw_proof_hex(value)
      proof_hex(value)
    end

    # The canonical fingerprint of a modulus: lowercase-hex SHA-256 of
    # the decoded 256-byte modulus, the identity a v5 record pins.
    def modulus_fingerprint_hex(modulus_b64)
      bytes = Base64Utils.decode_std(modulus_b64)
      raise RangeError, 'the modulus must be canonical standard base64' if bytes.nil?

      Digest::SHA256.hexdigest(bytes)
    end

    # Whether an identity is the accepted fingerprint form of a
    # modulus: the canonical fingerprint always, the legacy base64-text
    # alias only while the bounded migration mode is enabled.
    def identity_matches?(identity, modulus_n_base64, allow_legacy_alias)
      return true if identity == modulus_fingerprint_hex(modulus_n_base64)

      allow_legacy_alias && identity == Digest::SHA256.hexdigest(modulus_n_base64.b)
    end
  end
end
