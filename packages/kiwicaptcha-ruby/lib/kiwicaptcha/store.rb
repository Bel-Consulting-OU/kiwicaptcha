# frozen_string_literal: true

require 'json'

module KiwiCaptcha
  # The store adapter contract of the verifier: the atomic one-shot
  # surface verify needs, implementable over any backend whose
  # transitions are atomic. The three shipped adapters (memory, Redis,
  # SQLite) each hold the exactly-once guarantee: two racing consumers
  # of one nonce cannot both win the pending-to-consumed transition.
  module Store
    # The committed deterministic result of a consumed record.
    ConsumedResultRecord = Struct.new(:valid, :binding, :mac, keyword_init: true)

    # The consume transition result plus the retained record.
    ConsumedRecordSnapshot = Struct.new(
      :record, :consumed_now, :consumed_before, :consumed_result, :operation_identity,
      keyword_init: true
    )

    RUNTIME_KINDS = %w[missing pending consumed cancelled].freeze

    # The single-snapshot terminal-state classification of one nonce.
    RuntimeStateSnapshot = Struct.new(:kind, :record, :consumed, keyword_init: true)

    # The fused cleanup outcome kinds: missing, deleted_pending,
    # cancelled, corrupt, or consumed carrying the snapshot.
    DeleteIfPendingOutcome = Struct.new(:kind, :consumed, keyword_init: true)

    # The default retention margin past the signed expiry (the Redis
    # mirror).
    DEFAULT_TTL_MARGIN_SECS = 60

    OPERATION_IDENTITY_PATTERN = /\A[A-Za-z0-9_-]{1,128}\z/.freeze

    module_function

    # Validate a logical-operation identity: 1 to 128 bytes of
    # [A-Za-z0-9_-], or nil. The validation runs before any transition
    # so a malformed identity never lands in storage.
    def validated_operation_identity(operation_identity)
      return nil if operation_identity.nil?

      unless OPERATION_IDENTITY_PATTERN.match?(operation_identity)
        raise RangeError, 'operation identity must be 1..128 bytes of [A-Za-z0-9_-]'
      end

      operation_identity
    end

    # Decode the flat storage envelope the core writes: the record's
    # wire fields plus the top-level state, consumed_result and
    # operation_identity runtime fields. The record parse is strict; a
    # corrupt committed result degrades to absent. Nil on any
    # structural failure (fail closed, never partially trusted).
    def decode_envelope(raw)
      parsed = begin
        JSON.parse(raw)
      rescue JSON::ParserError
        return nil
      end
      return nil unless parsed.is_a?(Hash)

      state = parsed['state']
      return nil unless state.is_a?(String)

      record_fields = {}
      parsed.each do |key, value|
        record_fields[key] = value unless %w[state consumed_result operation_identity].include?(key)
      end
      begin
        record = Record.from_json(record_fields)
      rescue MalformedRecordError
        return nil
      end
      result = nil
      raw_result = parsed['consumed_result']
      unless raw_result.nil?
        if raw_result.is_a?(Hash)
          candidate = raw_result
          unknown_keys = candidate.keys - %w[valid binding mac]
          valid_bool = candidate['valid'].is_a?(TrueClass) || candidate['valid'].is_a?(FalseClass)
          if unknown_keys.empty? && valid_bool
            binding = candidate['binding'].is_a?(String) ? candidate['binding'] : nil
            mac = candidate['mac'].is_a?(String) ? candidate['mac'] : nil
            result = ConsumedResultRecord.new(valid: candidate['valid'], binding: binding, mac: mac)
          end
        end
        # A non-object committed result degrades to absent, never to a
        # partially trusted one.
      end
      EnvelopeDecoded.new(state: state, record: record, result: result, identity: envelope_identity(parsed))
    end

    def envelope_identity(envelope)
      identity = envelope['operation_identity']
      identity.is_a?(String) && !identity.empty? ? identity : nil
    end

    # The decoded envelope payload.
    EnvelopeDecoded = Struct.new(:state, :record, :result, :identity, keyword_init: true)
  end
end
