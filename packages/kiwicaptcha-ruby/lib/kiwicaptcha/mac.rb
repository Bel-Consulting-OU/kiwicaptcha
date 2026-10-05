# frozen_string_literal: true

require 'openssl'

module KiwiCaptcha
  # Authentication of the server written state that the challenge
  # signature does not cover: the record metadata (issued_at_ns and the
  # hostname) and the committed consumed result. The MAC input binds
  # the full challenge string, so a MAC can never be transplanted to
  # another record. Every variable-length field is length-prefixed and
  # every optional field carries a presence tag, mirroring the Rust
  # record_meta_mac and consumed_result_mac byte layout.
  module Mac
    RECORD_META_DOMAIN = 'kiwi/record-meta/v1'
    CONSUMED_RESULT_DOMAIN = 'kiwi/consumed-result/v1'

    # The wire shape of every server-state MAC: 64 lowercase hex.
    SERVER_STATE_MAC_PATTERN = /\A[0-9a-f]{64}\z/.freeze

    module_function

    # The server-state key for a kid secret and the deployment tenant.
    def server_state_key(secret, tenant_id = nil)
      Keys.derived_keys(secret, tenant_id).server_state_key
    end

    def lp(value)
      "#{value.bytesize}:#{value}"
    end

    def opt(value)
      value.nil? ? '0' : "1:#{lp(value)}"
    end

    # The exact record-metadata MAC input bytes, pinned by the shared
    # vectors.
    def record_meta_input(challenge, issued_at_ns, hostname)
      "#{RECORD_META_DOMAIN}\n#{lp(challenge)}\n#{issued_at_ns}\n#{opt(hostname)}"
    end

    # The exact consumed-result MAC input bytes, pinned by the shared
    # vectors.
    def consumed_result_input(challenge, valid, binding, operation_identity)
      "#{CONSUMED_RESULT_DOMAIN}\n#{lp(challenge)}\n#{valid ? '1' : '0'}\n#{opt(binding)}\n#{opt(operation_identity)}"
    end

    def hmac_hex(key, message)
      OpenSSL::HMAC.hexdigest('sha256', key, message.b)
    end

    # The record-metadata MAC over the challenge, issuance clock and
    # hostname.
    def record_meta_mac(key, challenge, issued_at_ns, hostname)
      hmac_hex(key, record_meta_input(challenge, issued_at_ns, hostname))
    end

    # The consumed-result MAC over the challenge, verdict, binding and
    # identity.
    def consumed_result_mac(key, challenge, valid, binding, operation_identity)
      hmac_hex(key, consumed_result_input(challenge, valid, binding, operation_identity))
    end

    # Constant-time comparison over equal-length strings; false on any
    # length mismatch. The fold runs over every byte position
    # regardless of where a difference sits.
    def timing_safe_equals(a, b)
      a = a.to_s.b
      b = b.to_s.b
      return false unless a.bytesize == b.bytesize

      diff = 0
      a.unpack('C*').each_with_index do |byte, i|
        diff |= byte ^ b.getbyte(i)
      end
      diff.zero?
    end
  end
end
