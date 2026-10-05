# frozen_string_literal: true

require 'digest'
require 'openssl'

module KiwiCaptcha
  # Purpose key separation, byte identical to the PHP DerivedKeys and
  # the Rust keys module. Every cryptographic purpose derives its own
  # 32-byte key from the single master secret:
  #
  #   prk          = hkdf extract (salt = deploy salt, ikm = master)
  #   k_challenge  = hkdf expand(prk, "kiwi/v2/challenge-sign")
  #   k_ip_bind    = hkdf expand(prk, "kiwi/v2/ip-bind")
  #   k_result     = hkdf expand(prk, "kiwi/v2/result-token")
  #   k_server     = hkdf expand(prk, "kiwi/v2/server-state")
  #
  # A tenant id derives the purpose keys under the per-tenant root
  # "kiwi/v2/tenant/" plus the tenant id, so tenants of one shared
  # master secret cannot forge each other's material.
  module Keys
    HKDF_DEPLOY_SALT = 'kiwicaptcha/deploy-salt/v1'
    INFO_CHALLENGE_SIGN = 'kiwi/v2/challenge-sign'
    INFO_IP_BIND = 'kiwi/v2/ip-bind'
    INFO_RESULT_TOKEN = 'kiwi/v2/result-token'
    INFO_SERVER_STATE = 'kiwi/v2/server-state'
    INFO_TENANT_ROOT_PREFIX = 'kiwi/v2/tenant/'

    # The minimum master secret length, mirroring the shared limits
    # register.
    MIN_SECRET_BYTES = 32

    DerivedKeys = Struct.new(:challenge_key, :ip_bind_key, :result_key, :server_state_key, keyword_init: true)

    module_function

    # Expand one hkdf output of exactly 32 bytes. The openssl gem moved
    # the digest from a positional argument to a keyword, so both
    # spellings are tried for portability across gem versions.
    def hkdf32(ikm, info, salt)
      ikm = ikm.b
      info_b = info.b
      salt_b = salt.b
      begin
        OpenSSL::KDF.hkdf(ikm, 'sha256', salt: salt_b, info: info_b, length: 32)
      rescue ArgumentError
        OpenSSL::KDF.hkdf(ikm, salt: salt_b, info: info_b, length: 32, hash: 'sha256')
      end
    end

    def derive(master, tenant_id)
      salt = HKDF_DEPLOY_SALT
      ikm = master
      if tenant_id
        ikm = hkdf32(master, INFO_TENANT_ROOT_PREFIX + tenant_id, salt)
        salt = ''
      end
      DerivedKeys.new(
        challenge_key: hkdf32(ikm, INFO_CHALLENGE_SIGN, salt),
        ip_bind_key: hkdf32(ikm, INFO_IP_BIND, salt),
        result_key: hkdf32(ikm, INFO_RESULT_TOKEN, salt),
        server_state_key: hkdf32(ikm, INFO_SERVER_STATE, salt)
      )
    end

    @cache = {}
    @mutex = Mutex.new
    CACHE_LIMIT = 64

    # Derive the purpose keys from the master secret, memoized per
    # secret and tenant for the process lifetime. Raises when the
    # secret is shorter than 32 bytes: a short secret must never derive
    # usable keys.
    def derived_keys(secret, tenant_id = nil)
      master = secret.is_a?(String) ? secret.b : secret.to_s.b
      if master.bytesize < MIN_SECRET_BYTES
        raise RangeError, "the master secret must be at least #{MIN_SECRET_BYTES} bytes (got #{master.bytesize})"
      end

      presence_tag = tenant_id ? [1].pack('C') : [0].pack('C')
      tenant_bytes = tenant_id ? tenant_id.to_s.b : ''.b
      cache_key = Digest::SHA256.digest(
        presence_tag + [tenant_bytes.bytesize].pack('N') + tenant_bytes + [master.bytesize].pack('N') + master
      )
      @mutex.synchronize do
        hit = @cache[cache_key]
        return hit if hit

        derived = derive(master, tenant_id)
        @cache.clear if @cache.size >= CACHE_LIMIT
        @cache[cache_key] = derived
        derived
      end
    end
  end
end
