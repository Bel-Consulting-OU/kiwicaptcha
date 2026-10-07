# frozen_string_literal: true

require 'digest'

module KiwiCaptcha
  # The proof-of-work derivation shared with the Rust and PHP cores.
  # The SHA-256 password is prefix plus counter; the hash input is
  # password followed by the raw salt bytes.
  module Pow
    SOLVER_MAX_HASHES = 20_000_000

    module_function

    # Count the leading zero bits of a 32-byte hash (big endian bit
    # order).
    def leading_zero_bits(hash)
      count = 0
      hash.each_byte do |byte|
        if byte.zero?
          count += 8
          next
        end
        while (byte & 0x80).zero?
          count += 1
          byte = (byte << 1) & 0xff
        end
        break
      end
      count
    end

    # Derive the SHA-256 proof hash of a record at one counter value.
    def derive_sha256_hash(prefix, counter, salt_bytes)
      Digest::SHA256.digest("#{prefix}#{counter}".b + salt_bytes)
    end

    # Whether the native Argon2id binding (the argon2 gem) is loaded
    # and carries the raw derivation entry point. The gem vendors
    # libargon2 behind FFI; nothing else in this SDK requires it. The
    # probe asks for the method, not just the module: a gem build
    # whose Argon2::Ext lacks argon2id_hash_raw can never derive, so
    # it must never report healthy to the doctor or the issuer guard.
    def argon2_available?
      return @argon2_available unless @argon2_available.nil?

      @argon2_available = begin
        require 'argon2'
        defined?(::Argon2::Ext) ? argon2_entry_point?(::Argon2::Ext) : false
      rescue LoadError, StandardError
        false
      end
    end

    # Whether the binding module exposes the raw Argon2id derivation
    # this SDK calls. Split out so the probe is testable without a
    # half-broken gem build.
    def argon2_entry_point?(ext)
      !ext.nil? && ext.respond_to?(:argon2id_hash_raw)
    end

    # Derive the Argon2id proof hash of a record at one counter value
    # through the native binding. Returns nil when the binding is
    # absent (the caller refuses the rung loudly, never downgrades) or
    # the parameters leave the implementable space.
    def derive_argon2id_hash(password, salt_bytes, t_cost, m_kib, lanes, out_len = 32)
      return nil unless argon2_available?
      return nil if t_cost < 1 || lanes < 1 || m_kib < 8 * lanes
      return nil if out_len < 4

      out = ::FFI::MemoryPointer.new(:char, out_len)
      ret = ::Argon2::Ext.argon2id_hash_raw(
        t_cost, m_kib, lanes,
        password.b, password.b.bytesize,
        salt_bytes.b, salt_bytes.b.bytesize,
        out, out_len
      )
      return nil unless ret.zero?

      out.read_string(out_len)
    rescue StandardError, ::FFI::NotFoundError
      nil
    end

    # Whether a derived hash meets the record's difficulty target.
    def meets_target?(hash, target_bits)
      leading_zero_bits(hash) >= target_bits
    end

    # Solve a SHA-256 challenge: the first counter whose hash meets the
    # target. Used by the test suite and tooling; the production proof
    # comes from the browser or native solver.
    def solve_sha256(prefix, salt_b64, target_bits)
      salt_bytes = Base64Utils.decode_std(salt_b64)
      raise ArgumentError, 'salt must be canonical base64' if salt_bytes.nil?

      counter = 0
      while counter < SOLVER_MAX_HASHES
        return counter if meets_target?(derive_sha256_hash(prefix, counter, salt_bytes), target_bits)

        counter += 1
      end
      raise 'no proof found below the solver ceiling'
    end
  end
end
