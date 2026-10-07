# frozen_string_literal: true

require 'digest'

module KiwiCaptcha
  # The doctor: the deployment self-check of the shared server SDK
  # contract. It validates the quickstart surface (the profile is an
  # adoption choice, so the doctor checks the other three): secret
  # strength, store reachability and atomicity, and the optional rsw
  # trapdoor pair. Findings come back typed and ordered so a wrapper
  # can print or assert them.
  module Doctor
    DoctorCheck = Struct.new(:name, :ok, :detail, keyword_init: true)
    DoctorReport = Struct.new(:ok, :checks, keyword_init: true)

    IDENTIFIER_ALPHABET = /\A[A-Za-z0-9._:-]+\z/.freeze

    module_function

    # Run every deployment check. The store probe writes a nonce-shaped
    # probe record, consumes it, and requires the exactly-once
    # semantics: the second consume must answer consumed_before with no
    # fresh win. ``profile`` names the adoption profile whose work
    # ladder the deployment prices (defaults to the quickstart
    # profile): a ladder that prices Argon2id rungs fails the argon2
    # check when the native binding is absent.
    def run(secret:, store:, rsw: nil, region: nil, issuer: nil, profile: nil)
      checks = []

      secret_length = secret.is_a?(String) ? secret.b.bytesize : secret.to_s.bytesize
      checks << DoctorCheck.new(
        name: 'secret',
        ok: secret_length >= Keys::MIN_SECRET_BYTES,
        detail: if secret_length >= Keys::MIN_SECRET_BYTES
                  "#{secret_length} bytes, meets the #{Keys::MIN_SECRET_BYTES}-byte floor"
                else
                  "#{secret_length} bytes, below the #{Keys::MIN_SECRET_BYTES}-byte floor"
                end
      )

      region_ok = region.nil? || IDENTIFIER_ALPHABET.match?(region)
      checks << DoctorCheck.new(
        name: 'region', ok: region_ok,
        detail: region_ok ? 'identifier shape valid or unset' : 'region must match [A-Za-z0-9._:-]'
      )

      issuer_ok = issuer.nil? || IDENTIFIER_ALPHABET.match?(issuer)
      checks << DoctorCheck.new(
        name: 'issuer', ok: issuer_ok,
        detail: issuer_ok ? 'identifier shape valid or unset' : 'issuer must match [A-Za-z0-9._:-]'
      )

      argon_ok = Pow.argon2_available?
      argon_required = Settings::ARGON_RUNG_PROFILES.include?(profile.to_s) || profile.nil?
      rungs_in_space = Settings::ARGON_RUNG_MEMORY_KIB.all? do |m_kib|
        Settings.valid_argon_memory_kib?(m_kib)
      end
      checks << DoctorCheck.new(
        name: 'argon2',
        ok: (argon_ok || !argon_required) && rungs_in_space,
        detail: if !rungs_in_space
                  'an argon2id rung budget is outside the protocol profile space ' \
                  '(powers of two within 8..=65536 KiB); refused at configuration ' \
                  'time, never per request'
                elsif argon_ok
                  'native Argon2id binding present (argon2 gem); argon rungs verify ' \
                  '(protocol profile space: powers of two within 8..=65536 KiB)'
                elsif argon_required
                  'native Argon2id binding missing: the priced ladder issues argon2id ' \
                  'rungs that refuse with unsupported_argon2_params (install the argon2 ' \
                  'gem or choose a sha-only profile); never silently downgraded'
                else
                  'native Argon2id binding missing (this profile prices no argon rungs)'
                end
      )

      checks << probe_store(store)

      unless rsw.nil?
        checks << probe_rsw(rsw)
      end

      DoctorReport.new(ok: checks.all? { |check| check.ok }, checks: checks)
    end

    def probe_store(store)
      probe = Digest::SHA256.digest(Time.now.to_f.to_s)
      nonce = Base64Utils.encode_std(probe)
      now = Time.now.to_i
      record = Record::ChallengeRecord.new(
        nonce: nonce,
        scope: 'doctor',
        binding_tag: '',
        issued_at: now,
        expires_at: now + 120,
        algorithm: 'sha256',
        m_kib: 0,
        t: 1,
        p: 1,
        target_bits: 1,
        salt: Base64Utils.encode_std(probe[0, 16]),
        prefix: "#{nonce}.",
        challenge: "#{nonce}.sig",
        min_duration_ms: 0,
        issued_at_ns: 0,
        protocol_version: 2,
        region: nil,
        policy_version: 1,
        request_binding: nil,
        issuer: nil,
        kid: 1,
        hostname: nil,
        decoy_field: nil,
        execution_program: nil,
        execution_version: nil,
        execution_commitment: nil,
        rsw_modulus_sha256: nil,
        server_mac: nil
      )
      store.store(record)
      found = store.find(nonce)
      return DoctorCheck.new(name: 'store', ok: false, detail: 'the probe record did not read back') if found.nil?

      first = store.consume(nonce)
      if first.nil? || !first.consumed_now
        return DoctorCheck.new(name: 'store', ok: false, detail: 'the first probe consume did not win')
      end

      second = store.consume(nonce)
      if second.nil? || !second.consumed_before
        return DoctorCheck.new(name: 'store', ok: false, detail: 'the second probe consume won again: the store is not single-use')
      end

      DoctorCheck.new(name: 'store', ok: true, detail: 'reachable and single-use under the probe')
    rescue StandardError => e
      DoctorCheck.new(name: 'store', ok: false, detail: "store probe failed: #{e.message}")
    end

    def probe_rsw(config)
      modulus_n = config.respond_to?(:modulus_n) ? config.modulus_n : config[:modulus_n]
      lambda = config.respond_to?(:lambda) ? config.lambda : config[:lambda]
      trapdoor = Rsw::Trapdoor.new(modulus_n, lambda)
      DoctorCheck.new(name: 'rsw', ok: true, detail: "trapdoor valid for modulus #{trapdoor.n.to_s(16)[0, 16]}...")
    rescue StandardError => e
      DoctorCheck.new(name: 'rsw', ok: false, detail: e.message)
    end
  end
end
