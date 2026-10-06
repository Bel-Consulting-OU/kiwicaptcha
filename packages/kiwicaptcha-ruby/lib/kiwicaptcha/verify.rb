# frozen_string_literal: true

require 'openssl'
require 'set'

module KiwiCaptcha
  # The verifier: the exact cheap-gate order and the consumed
  # resolution of the PHP Verifier, over the storage seam.
  #
  # The gate order is normative and mirrors Verifier::verify(): nonce
  # match, structure, protocol gate, kid revocation, kid resolution,
  # signature, Argon2id ceilings, rsw bounds, TTL, scope, request
  # binding, IP binding, region, policy epoch (with the rollout floor
  # window), issuer, execution binding and minimum duration. Then comes
  # the opt-in telemetry gate, the terminal-state resolution, the
  # one-shot consume, the proof re-derivation, the post-derive final
  # revalidation and the result commit.
  #
  # Verify is pure local: it never calls out to any network service.
  # The only side effects are the storage transitions the one-shot
  # model requires. Execution-armed records (the signed e= commitment)
  # are refused deterministically with execution_mismatch: the
  # browser-trace walker is a browser-behavior oracle this SDK does not
  # carry, and an armed record must never pass without it. Argon2id
  # records are authentic but unrepresentable without a native Argon2id
  # runtime, and fail closed with the cores' unsupported mapping.
  module Verify
    # Hard ceiling for a stored record's lifetime (expires_at minus
    # issued_at).
    MAX_TTL_SECS = 300

    # Maximum tolerated future skew for a record's issuance timestamp.
    MAX_CLOCK_SKEW = 60

    # Host clock skew tolerance for the minimum-duration check, in
    # microseconds.
    SKEW_TOLERANCE_US = 5_000_000

    MIN_ARGON_MEMORY_KIB = 8
    MAX_ARGON_MEMORY_KIB = 65_536
    MIN_ARGON_TIME = 3
    MAX_ARGON_TIME = 16
    MIN_PARALLELISM = 1
    MAX_PARALLELISM = 4

    MIN_DIFFICULTY = 1
    MAX_DIFFICULTY = 20

    # The verification result of the shared server SDK contract: ok,
    # disposition, decision_handle and price, with the additive
    # evidence fields the cores expose.
    VerifyResult = Struct.new(
      :ok, :disposition, :decision_handle, :price, :code, :detail,
      :request_binding, :from_stored_result, :solve_duration_ms, :decoy_field,
      keyword_init: true
    )

    # The rsw trapdoor configuration of one deployment.
    RswVerifierConfig = Struct.new(
      :modulus_n, :lambda, :verification_keys, :allow_legacy_identity,
      keyword_init: true
    )

    # The verify options of one call. Every field except storage and
    # secret_key carries the documented default.
    VerifyOptions = Struct.new(
      :storage, :secret_key, :expected_scope, :client_ip, :now_ns, :now,
      :enforce_telemetry, :operation_identity, :expected_request_binding,
      :binding_expectation, :expected_policy_version, :policy_version_floor,
      :region, :expected_issuer, :secrets_by_kid, :revoked_kids,
      :tenant_id, :accept_legacy_v1, :rsw, :execution_policy,
      keyword_init: true
    ) do
      # The scope option is REQUIRED: the keyword has no default, so a
      # call without it raises at construction (the ruby spelling of
      # the required_scope contract) instead of defaulting to the lax
      # any-scope acceptance.
      def initialize(expected_scope:, **kwargs)
        opts = {
          client_ip: nil, now_ns: nil, now: nil,
          enforce_telemetry: false, operation_identity: nil,
          expected_request_binding: nil, binding_expectation: :exact,
          expected_policy_version: nil, policy_version_floor: nil,
          region: nil, expected_issuer: nil, secrets_by_kid: {},
          revoked_kids: [].freeze, tenant_id: nil, accept_legacy_v1: false,
          rsw: nil, execution_policy: nil
        }.merge(kwargs)
        super(expected_scope: expected_scope, **opts)
      end
    end

    class << self
      def invalid(code)
        VerifyResult.new(
          ok: false, disposition: 'deny', decision_handle: nil, price: nil,
          code: code, detail: VerifyError.describe(code),
          request_binding: nil, from_stored_result: false,
          solve_duration_ms: nil, decoy_field: nil
        )
      end

      def valid(nonce, price, request_binding, from_stored_result, solve_duration_ms, decoy_field)
        VerifyResult.new(
          ok: true, disposition: 'allow', decision_handle: nonce, price: price,
          code: '', detail: nil, request_binding: request_binding,
          from_stored_result: from_stored_result,
          solve_duration_ms: solve_duration_ms, decoy_field: decoy_field
        )
      end

      # The work-ladder rung name of a verified record's signed
      # parameters.
      def ladder_rung(record)
        if record.algorithm == 'rsw'
          return 'rsw'
        end
        if record.algorithm == 'argon2id'
          mib = record.m_kib / 1024
          return [16, 32, 64].include?(mib) ? "argon#{mib}" : "argon#{record.m_kib}kib"
        end
        [16, 18, 20].include?(record.target_bits) ? "sha#{record.target_bits}" : "sha#{record.target_bits}bit"
      end

      def resolved_secrets(options)
        by_kid = {}
        (options.secrets_by_kid || {}).each do |kid, secret|
          by_kid[Integer(kid)] = secret.is_a?(String) ? secret.b : secret.to_s.b
        end
        {
          by_kid: by_kid,
          revoked: Set.new(options.revoked_kids || []),
          newest: nil
        }
      end

      # Select the signature secret for a record (kid set or legacy
      # secret).
      def secret_for_key(secrets, record, legacy_secret)
        return legacy_secret if secrets[:by_kid].empty?

        secrets[:newest] ||= secrets[:by_kid].keys.max
        return nil if record.kid > secrets[:newest]

        secrets[:by_kid][record.kid]
      end

      def normalize_secret(secret)
        secret.is_a?(String) ? secret.b : secret.to_s.b
      end

      def now_secs(options)
        options.now ? options.now.call : Time.now.to_i
      end

      # Verify a client-submitted solution token against the store: the
      # pure local operation of the shared server SDK contract. The
      # cheap-gate order mirrors the PHP and Rust verifiers exactly.
      def call(raw_token, options)
        secrets = resolved_secrets(options)
        legacy_secret = normalize_secret(options.secret_key)

        token = begin
          Token.decode(raw_token)
        rescue DecodeError, StandardError
          return invalid(VerifyError::MALFORMED_TOKEN)
        end
        receipt_ns = options.now_ns || (Time.now.to_f * 1_000_000).to_i
        storage = options.storage

        runtime = begin
          storage.runtime_state(token.nonce)
        rescue StandardError
          return invalid(VerifyError::STORAGE_UNAVAILABLE)
        end
        return invalid(VerifyError::RECORD_NOT_FOUND) if runtime.kind == 'missing'

        peek = runtime.record
        if peek.nil?
          begin
            peek = storage.find(token.nonce)
          rescue StandardError
            return invalid(VerifyError::STORAGE_UNAVAILABLE)
          end
          return invalid(VerifyError::RECORD_NOT_FOUND) if peek.nil?
        end

        # The execution delegation plane: an armed record under a
        # sidecar policy delegates the execution dimension after the
        # cheap phase proved everything the SDK checks locally.
        policy = options.execution_policy
        delegate_execution = !policy.nil? && policy.enabled? && peek.execution_program.to_s != ''
        failure = cheap_phase_check(options, secrets, legacy_secret, peek, token, true, receipt_ns, delegate_execution)
        if failure.nil? && delegate_execution
          ok, code = policy.delegate(raw_token, options.expected_scope, options.client_ip)
          if ok
            return valid(peek.nonce, ladder_rung(peek), peek.request_binding, true, nil, peek.decoy_field)
          end
          return invalid(code)
        end
        if failure
          if failure != VerifyError::MISSING_CLIENT_IP
            cleanup = begin
              storage.delete_if_pending(token.nonce)
            rescue StandardError
              return invalid(VerifyError::STORAGE_UNAVAILABLE)
            end
            if cleanup.kind != 'consumed'
              # Missing, deleted pending, cancelled or corrupt: the
              # one-shot verdict stands.
              return invalid(failure)
            end
            unless VerifyError.replay_exempt?(failure)
              # A hard security verdict on a consumed record: the
              # failure stands and the evidence stays preserved.
              return invalid(failure)
            end
            # Consumed plus an exempt circumstance: the exempt failure
            # may not mask a hard verdict on the same request.
            hard = replay_security_check(options, secrets, legacy_secret, peek, token, receipt_ns)
            return invalid(hard) if hard

            return resolve_consumed_record(options, secrets, legacy_secret, cleanup.consumed, token.nonce, options.operation_identity)
          end

          # MissingClientIp never deletes: the caller can retry with
          # the IP. A consumed record resolves through the
          # compositional replay gate, exactly like the fused path.
          if runtime.kind == 'consumed' && runtime.consumed
            hard = replay_security_check(options, secrets, legacy_secret, peek, token, receipt_ns)
            return invalid(hard) if hard

            return resolve_consumed_record(options, secrets, legacy_secret, runtime.consumed, token.nonce, options.operation_identity)
          end
          return invalid(failure)
        end

        # The opt-in telemetry gate: client-controlled evidence about
        # the original solve, replay-exempt, deletion only for a
        # pending record.
        if options.enforce_telemetry &&
           (token.telemetry.empty? || Telemetry.bot_signal?(token.telemetry, token.duration_ms)) &&
           runtime.kind != 'consumed'
          cleanup = begin
            storage.delete_if_pending(token.nonce)
          rescue StandardError
            return invalid(VerifyError::STORAGE_UNAVAILABLE)
          end
          if cleanup.kind != 'consumed'
            return invalid(VerifyError::TELEMETRY_REJECTED)
          end
          hard = replay_security_check(options, secrets, legacy_secret, peek, token, receipt_ns)
          return invalid(hard) if hard

          return resolve_consumed_record(options, secrets, legacy_secret, cleanup.consumed, token.nonce, options.operation_identity)
        end

        # Terminal-state resolution before the consume: a cancelled or
        # already-consumed record never burns the proof phase.
        return invalid(VerifyError::RECORD_NOT_FOUND) if runtime.kind == 'cancelled'
        if runtime.kind == 'consumed' && runtime.consumed
          return resolve_consumed_record(options, secrets, legacy_secret, runtime.consumed, token.nonce, options.operation_identity)
        end

        # The one-shot consume and the proof re-derivation.
        consumed = begin
          Store.validated_operation_identity(options.operation_identity)
          storage.consume(token.nonce, options.operation_identity)
        rescue StandardError
          # A lost transition response is ambiguous: the challenge may
          # or may not have been consumed.
          return invalid(VerifyError::CONSUME_INDETERMINATE)
        end
        return invalid(VerifyError::RECORD_NOT_FOUND) if consumed.nil?
        if consumed.consumed_before
          return resolve_consumed_record(options, secrets, legacy_secret, consumed, token.nonce, options.operation_identity)
        end
        record = consumed.record

        # The consumed instance must be the challenge that was
        # validated and signed-checked via the peek: a swapped record
        # fails closed.
        consumed_secret = secret_for_key(secrets, record, legacy_secret)
        if record.nonce != token.nonce ||
           peek.challenge != record.challenge ||
           secrets[:revoked].include?(record.kid) ||
           consumed_secret.nil? ||
           !validate_record(record) ||
           !verify_record_signature(options, record, consumed_secret)
          return invalid(VerifyError::MALFORMED_RECORD)
        end
        return invalid(VerifyError::UNSUPPORTED_ARGON2_PARAMS) unless argon2_ceilings_ok?(record)
        return invalid(VerifyError::UNSUPPORTED_RSW_PARAMS) unless rsw_params_ok?(record)
        return invalid(VerifyError::WRONG_POLICY_VERSION) unless policy_version_accepted?(options, record.policy_version)
        if !options.expected_issuer.nil? && record.issuer != options.expected_issuer
          return invalid(VerifyError::WRONG_ISSUER)
        end

        valid_proof = recompute_valid_proof(options, record, token)
        if valid_proof.nil?
          # Authentic but unrepresentable by this verifier: the
          # per-algorithm mapping of the cores.
          mapped = if record.algorithm == 'rsw'
                     VerifyError::UNSUPPORTED_RSW_PARAMS
                   elsif record.algorithm == 'argon2id'
                     VerifyError::UNSUPPORTED_ARGON2_PARAMS
                   else
                     VerifyError::MALFORMED_RECORD
                   end
          return invalid(mapped)
        end

        # Post-derive final revalidation against the current clock and
        # the current expectations, for both valid and invalid
        # derivations.
        now = now_secs(options)
        return invalid(VerifyError::EXPIRED) if now >= record.expires_at
        return invalid(VerifyError::WRONG_POLICY_VERSION) unless policy_version_accepted?(options, record.policy_version)
        return invalid(VerifyError::WRONG_REGION) if !options.region.nil? && record.region != options.region
        if !options.expected_issuer.nil? && record.issuer != options.expected_issuer
          return invalid(VerifyError::WRONG_ISSUER)
        end

        unless valid_proof
          best_effort_commit(options, secrets, legacy_secret, storage, consumed, false)
          return invalid(VerifyError::INSUFFICIENT_WORK)
        end
        best_effort_commit(options, secrets, legacy_secret, storage, consumed, true)
        valid(
          record.nonce,
          ladder_rung(record),
          record.request_binding,
          false,
          measurable_solve_duration_ms(record, receipt_ns),
          record.decoy_field
        )
      end

      def cheap_phase_check(options, secrets, legacy_secret, record, token, check_timing, now_ns, delegate_execution = false)
        # 0. The record must carry the nonce it was loaded under.
        return VerifyError::MALFORMED_RECORD if record.nonce != token.nonce

        # 1 to 2b. Structure, protocol gate, kid gate, signature,
        # ceilings.
        shape = check_authenticated_shape(options, secrets, legacy_secret, record)
        return shape unless shape.nil?

        signing_secret = secret_for_key(secrets, record, legacy_secret)
        # 3. TTL.
        if check_timing
          ttl = check_ttl(options, record)
          return ttl unless ttl.nil?
        end
        # 4 and 4b. Scope and the expected request binding.
        scope_or_binding = check_scope_and_binding(options, record)
        return scope_or_binding unless scope_or_binding.nil?
        # 5. IP binding.
        ip_binding = check_ip_binding(options, record, signing_secret)
        return ip_binding unless ip_binding.nil?
        # 5b to 5d. Region, policy epoch, issuer.
        deployment = check_deployment_expectations(options, record)
        return deployment unless deployment.nil?
        # 5e. The execution binding. The delegation path leaves this
        # gate to the sidecar's full-core pass; every other gate stays
        # local.
        unless delegate_execution
          execution = check_execution_binding(record, token)
          return execution unless execution.nil?
        end
        # 6. Server-measured minimum duration.
        return nil unless check_timing

        check_min_duration(record, now_ns)
      end

      def replay_security_check(options, secrets, legacy_secret, record, token, receipt_ns)
        shape = check_authenticated_shape(options, secrets, legacy_secret, record)
        return shape unless shape.nil?
        scope_or_binding = check_scope_and_binding(options, record)
        return scope_or_binding unless scope_or_binding.nil?
        deployment = check_deployment_expectations(options, record)
        return deployment unless deployment.nil?
        execution = check_execution_binding(record, token)
        return execution unless execution.nil?

        check_min_duration(record, receipt_ns)
      end

      def check_authenticated_shape(options, secrets, legacy_secret, record)
        return VerifyError::MALFORMED_RECORD unless validate_record(record)
        if record.protocol_version == 1 && !options.accept_legacy_v1
          return VerifyError::MALFORMED_RECORD
        end
        return VerifyError::UNKNOWN_KID if secrets[:revoked].include?(record.kid)

        signing_secret = secret_for_key(secrets, record, legacy_secret)
        return VerifyError::UNKNOWN_KID if signing_secret.nil?
        return VerifyError::BAD_SIGNATURE unless verify_record_signature(options, record, signing_secret)
        return VerifyError::UNSUPPORTED_ARGON2_PARAMS unless argon2_ceilings_ok?(record)

        rsw_params_ok?(record) ? nil : VerifyError::UNSUPPORTED_RSW_PARAMS
      end

      def check_ttl(options, record)
        now = now_secs(options)
        return VerifyError::EXPIRED if now >= record.expires_at
        return VerifyError::EXPIRED if record.issued_at > now + MAX_CLOCK_SKEW

        nil
      end

      def check_scope_and_binding(options, record)
        # The scope option is required: an empty option refuses with
        # the typed code instead of accepting any scope.
        return VerifyError::REQUIRED_SCOPE if options.expected_scope.nil? || options.expected_scope.empty?

        return VerifyError::WRONG_SCOPE if record.scope != options.expected_scope

        # Exact option equality by default: a bound record must present
        # its binding, an unbound record under a presented expectation
        # is refused; the legacy mode permits an unbound record
        # regardless of the expectation.
        if record.request_binding.nil? || options.expected_request_binding.nil?
          return nil if record.request_binding.nil? && options.binding_expectation == :legacy

          return record.request_binding == options.expected_request_binding ? nil : VerifyError::REQUEST_BINDING_MISMATCH
        end
        Mac.timing_safe_equals(record.request_binding, options.expected_request_binding) ? nil : VerifyError::REQUEST_BINDING_MISMATCH
      end

      def check_ip_binding(options, record, signing_secret)
        return nil if record.binding_tag.empty?
        return VerifyError::MISSING_CLIENT_IP if options.client_ip.nil?

        expected_tag = begin
          if record.protocol_version == 1
            Canonical.hash_ip(options.client_ip, signing_secret)
          else
            Canonical.binding_tag(record.nonce, options.client_ip, signing_secret, options.tenant_id)
          end
        rescue RangeError, StandardError
          return VerifyError::IP_MISMATCH
        end
        Mac.timing_safe_equals(expected_tag, record.binding_tag) ? nil : VerifyError::IP_MISMATCH
      end

      # Whether the record's policy epoch satisfies the configured
      # window: strict equality by default, or the declared rollout
      # floor through the expected epoch, inclusive on both ends. A
      # floor above the expected epoch accepts nothing (fail closed).
      def policy_version_accepted?(options, record_version)
        return true if options.expected_policy_version.nil?
        return record_version == options.expected_policy_version if options.policy_version_floor.nil?

        options.policy_version_floor <= record_version && record_version <= options.expected_policy_version
      end

      def check_deployment_expectations(options, record)
        if !options.region.nil? && record.region != options.region
          return VerifyError::WRONG_REGION
        end
        unless policy_version_accepted?(options, record.policy_version || 1)
          return VerifyError::WRONG_POLICY_VERSION
        end
        if !options.expected_issuer.nil? && record.issuer != options.expected_issuer
          return VerifyError::WRONG_ISSUER
        end

        nil
      end

      def check_execution_binding(record, token)
        digest = token.execution_digest
        if record.execution_program.nil?
          # Stray execution evidence on an unarmed record is never
          # ignored.
          return digest.nil? && token.execution_trace.nil? ? nil : VerifyError::EXECUTION_MISMATCH
        end
        # An armed record demands the browser-trace walker, a
        # browser-behavior oracle this SDK does not carry. The armed
        # dimension fails closed: the record's own authenticated
        # program and commitment still verify, but no submission can
        # satisfy the armed binding, so a missing capability never
        # widens acceptance.
        VerifyError::EXECUTION_MISMATCH
      end

      def check_min_duration(record, now_ns)
        return VerifyError::MALFORMED_RECORD if record.issued_at_ns <= 0

        floor = [0, record.min_duration_ms].max
        if floor.positive?
          # An unauthenticated issuance clock cannot drive the floor.
          return VerifyError::MALFORMED_RECORD if record.server_mac.nil?

          receipt = now_ns || (Time.now.to_f * 1_000_000).to_i
          if receipt >= record.issued_at_ns
            return VerifyError::TOO_FAST if receipt - record.issued_at_ns < floor * 1000
          elsif record.issued_at_ns - receipt > SKEW_TOLERANCE_US
            return VerifyError::TOO_FAST
          end
        end
        nil
      end

      # Structural validation of the stored record, in the canonical
      # order.
      def validate_record(record)
        return false if record.protocol_version < 1 || record.protocol_version > Record::MAX_PROTOCOL_VERSION
        unless Record.protocol_extension_grammar_ok?(
          record.protocol_version,
          !record.decoy_field.nil?,
          !record.execution_program.nil?,
          !record.rsw_modulus_sha256.nil?
        )
          return false
        end

        scope_len = record.scope.b.bytesize
        return false if scope_len < 1 || scope_len > 128 || record.scope !~ /\A[A-Za-z0-9._:-]+\z/
        return false if record.decoy_field && !Record.valid_decoy_field_name?(record.decoy_field)

        if record.execution_program
          return false if record.execution_version.nil? ||
                          record.execution_version < 1 ||
                          record.execution_version > Record::MAX_EXECUTION_VERSION ||
                          record.execution_commitment.nil?
          return false unless record.execution_commitment =~ /\A[0-9a-f]{64}\z/

          expected = Canonical.execution_commitment(record.execution_program)
          return false unless Mac.timing_safe_equals(expected, record.execution_commitment)
        elsif !record.execution_version.nil? || !record.execution_commitment.nil?
          return false
        end
        if record.rsw_modulus_sha256
          return false if record.algorithm != 'rsw' || record.rsw_modulus_sha256 !~ /\A[0-9a-f]{64}\z/
        end

        nonce_bytes = Base64Utils.decode_std(record.nonce)
        return false if nonce_bytes.nil? || nonce_bytes.bytesize != 32

        salt_bytes = Base64Utils.decode_std(record.salt)
        return false if salt_bytes.nil? || salt_bytes.bytesize != 16

        return false if record.expires_at <= record.issued_at || record.expires_at - record.issued_at > MAX_TTL_SECS

        prefix_bytes = "#{record.challenge}|#{record.salt}|".b
        return false unless Mac.timing_safe_equals(prefix_bytes, record.prefix.b)

        return false if record.target_bits < MIN_DIFFICULTY || record.target_bits > MAX_DIFFICULTY

        true
      end

      def argon2_ceilings_ok?(record)
        return true unless record.algorithm == 'argon2id'

        record.m_kib >= MIN_ARGON_MEMORY_KIB && record.m_kib <= MAX_ARGON_MEMORY_KIB &&
          record.t >= MIN_ARGON_TIME && record.t <= MAX_ARGON_TIME &&
          record.p >= MIN_PARALLELISM && record.p <= MAX_PARALLELISM
      end

      def rsw_params_ok?(record)
        return true unless record.algorithm == 'rsw'

        record.t >= Rsw::T_MIN && record.t <= Rsw::T_MAX
      end

      # Recompute the expected HMAC signature for a record per its
      # protocol version and compare constant time against the
      # challenge's embedded tag. The v2+ canonical covers every
      # immutable parameter and the tagged armed-extension segments; a
      # signed m=1 marker requires a valid record-metadata MAC.
      def verify_record_signature(options, record, secret_key)
        commits_mac = Canonical.signed_canonical_commits_record_meta(record.challenge)
        expected =
          if record.protocol_version == 1
            Canonical.sign_payload_v1(
              "#{record.nonce}|#{record.scope}|#{record.binding_tag}|#{record.issued_at}",
              secret_key
            )
          else
            Canonical.sign_payload_v2(
              Canonical.canonical_payload(
                Canonical::CanonicalArgs.new(
                  protocol_version: record.protocol_version,
                  nonce: record.nonce,
                  scope: record.scope,
                  binding_tag: record.binding_tag,
                  issued_at: record.issued_at,
                  expires_at: record.expires_at,
                  algorithm: record.algorithm,
                  m_kib: record.m_kib,
                  t: record.t,
                  p: record.p,
                  target_bits: record.target_bits,
                  salt: record.salt,
                  min_duration_ms: record.min_duration_ms,
                  region: record.region,
                  policy_version: record.policy_version || 1,
                  request_binding: record.request_binding,
                  issuer: record.issuer,
                  kid: record.kid || 1,
                  decoy_field: record.decoy_field,
                  execution_version: record.execution_version,
                  execution_commitment: record.execution_commitment,
                  rsw_modulus_sha256: record.rsw_modulus_sha256,
                  server_mac_committed: commits_mac
                )
              ),
              secret_key,
              options.tenant_id
            )
          end
        return false unless Mac.timing_safe_equals(expected, signature_from_challenge(record.challenge))

        key = Mac.server_state_key(secret_key, options.tenant_id)
        if commits_mac
          return false if record.server_mac.nil?

          Mac.timing_safe_equals(Mac.record_meta_mac(key, record.challenge, record.issued_at_ns, record.hostname), record.server_mac)
        elsif record.server_mac.nil?
          true
        else
          Mac.timing_safe_equals(Mac.record_meta_mac(key, record.challenge, record.issued_at_ns, record.hostname), record.server_mac)
        end
      end

      def signature_from_challenge(challenge)
        pos = challenge.rindex('.')
        pos.nil? ? '' : challenge[(pos + 1)..].to_s
      end

      # The deterministic proof verdict of a presented token against a
      # record. SHA-256 re-derives the hash and compares leading zero
      # bits; rsw compares the trapdoor expectation; an argon2id record
      # is authentic but unrepresentable by this runtime and fails
      # closed with the cores' unsupported mapping (nil).
      def recompute_valid_proof(options, record, token)
        if record.algorithm == 'rsw'
          trapdoor = resolve_trapdoor(options.rsw, record)
          return nil if trapdoor.nil?
          return false if token.counter != 0 || token.rsw_proof.nil?

          expected = trapdoor.expected_proof_hex(record.prefix, record.nonce, record.t)
          return Mac.timing_safe_equals(expected, token.rsw_proof)
        end
        if token.rsw_proof
          # An rsw final value is rsw evidence only; the hash is never
          # derived for a record it does not belong to.
          return false
        end
        return nil if record.algorithm == 'argon2id'

        salt_bytes = Base64Utils.decode_std(record.salt)
        return nil if salt_bytes.nil?

        hash = Pow.derive_sha256_hash(record.prefix, token.counter, salt_bytes)
        Pow.meets_target?(hash, record.target_bits)
      end

      # Normalize the rsw configuration surface: a RswVerifierConfig or
      # a plain hash with symbol or string keys.
      def normalized_rsw(config)
        return nil if config.nil?
        return config if config.is_a?(RswVerifierConfig)

        fetch = ->(key) { config[key.to_sym] || config[key.to_s] }
        RswVerifierConfig.new(
          modulus_n: fetch.call(:modulus_n),
          lambda: fetch.call(:lambda),
          verification_keys: fetch.call(:verification_keys) || {},
          allow_legacy_identity: fetch.call(:allow_legacy_identity) == true
        )
      end

      def resolve_trapdoor(rsw_config, record)
        config = normalized_rsw(rsw_config)
        active = nil
        if config && !config.modulus_n.to_s.empty? && !config.lambda.to_s.empty?
          begin
            active = Rsw::Trapdoor.new(config.modulus_n, config.lambda)
          rescue RangeError
            active = nil
          end
        end
        keyring = {}
        modulus_by_hash = {}
        allow_legacy = config && config.allow_legacy_identity == true
        if config
          (config.verification_keys || {}).each do |hash, pair|
            next unless hash.to_s =~ /\A[0-9a-f]{64}\z/

            pair_modulus = pair.is_a?(Hash) ? (pair[:modulus_n] || pair['modulus_n']) : nil
            pair_lambda = pair.is_a?(Hash) ? (pair[:lambda] || pair['lambda']) : nil
            begin
              trapdoor = Rsw::Trapdoor.new(pair_modulus, pair_lambda)
            rescue RangeError
              next
            end
            next unless Rsw.identity_matches?(hash.to_s, pair_modulus, allow_legacy)

            keyring[hash.to_s] = trapdoor
            modulus_by_hash[hash.to_s] = pair_modulus
          end
          if active && !config.modulus_n.to_s.empty?
            fingerprint_of(config.modulus_n, allow_legacy).each do |identity|
              keyring[identity] = active
              modulus_by_hash[identity] = config.modulus_n
            end
          end
        end
        if record.rsw_modulus_sha256
          identity = record.rsw_modulus_sha256
          keyring_modulus = modulus_by_hash[identity]
          if keyring_modulus && Rsw.identity_matches?(identity, keyring_modulus, allow_legacy)
            return keyring[identity]
          end
          if active && Rsw.identity_matches?(identity, config ? config.modulus_n.to_s : '', allow_legacy)
            return active
          end
          return nil
        end
        active
      end

      def fingerprint_of(modulus_n, allow_legacy)
        bytes = Base64Utils.decode_std(modulus_n)
        return [] if bytes.nil?

        forms = [Digest::SHA256.hexdigest(bytes)]
        forms << Digest::SHA256.hexdigest(modulus_n.b) if allow_legacy
        forms
      end

      # The server-measured solve duration of a fresh valid outcome.
      def measurable_solve_duration_ms(record, receipt_ns)
        if record.server_mac.nil? || record.issued_at_ns <= 0 || receipt_ns.nil? || receipt_ns < record.issued_at_ns
          return nil
        end

        (receipt_ns - record.issued_at_ns) / 1000
      end

      def best_effort_commit(options, secrets, legacy_secret, storage, consumed, outcome_valid)
        secret = secret_for_key(secrets, consumed.record, legacy_secret)
        return if secret.nil?

        mac = Mac.consumed_result_mac(
          Mac.server_state_key(secret, options.tenant_id),
          consumed.record.challenge,
          outcome_valid,
          consumed.record.request_binding,
          consumed.operation_identity
        )
        storage.commit_result(consumed.record.nonce, outcome_valid, consumed.record.request_binding, mac)
      rescue StandardError
        # Best-effort: a storage failure must not change the outcome.
        nil
      end

      # Resolve an already-consumed record's retained state. A stored
      # invalid outcome replays to any caller; a stored success replays
      # only under the exact logical operation identity with an
      # authentic MAC; a resultless consumed record is
      # consume_indeterminate.
      def resolve_consumed_record(options, secrets, legacy_secret, consumed, token_nonce, operation_identity)
        return invalid(VerifyError::MALFORMED_RECORD) if consumed.record.nonce != token_nonce
        return invalid(VerifyError::CONSUME_INDETERMINATE) if consumed.consumed_result.nil?
        return invalid(VerifyError::INSUFFICIENT_WORK) unless consumed.consumed_result.valid

        if !operation_identity.nil? && !consumed.operation_identity.nil? &&
           Mac.timing_safe_equals(consumed.operation_identity, operation_identity)
          unless stored_success_authentic?(options, secrets, legacy_secret, consumed)
            return invalid(VerifyError::MALFORMED_RECORD)
          end

          return valid(
            consumed.record.nonce,
            ladder_rung(consumed.record),
            consumed.consumed_result.binding,
            true,
            nil,
            consumed.record.decoy_field
          )
        end
        invalid(VerifyError::ALREADY_CONSUMED)
      end

      def stored_success_authentic?(options, secrets, legacy_secret, consumed)
        result = consumed.consumed_result
        return false if result.nil? || !result.valid

        if result.mac.nil?
          commits = options.storage.respond_to?(:authenticated_result_commit) &&
                    options.storage.authenticated_result_commit
          return !commits
        end
        secret = secret_for_key(secrets, consumed.record, legacy_secret)
        return false if secret.nil?

        expected = Mac.consumed_result_mac(
          Mac.server_state_key(secret, options.tenant_id),
          consumed.record.challenge,
          result.valid,
          result.binding,
          consumed.operation_identity
        )
        Mac.timing_safe_equals(expected, result.mac)
      end
    end
  end

  # The module-level one-call entry: KiwiCaptcha.verify(token, options).
  def self.verify(raw_token, options)
    Verify.call(raw_token, options)
  end
end
