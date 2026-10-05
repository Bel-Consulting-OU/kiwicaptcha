# frozen_string_literal: true

require 'openssl'

module KiwiCaptcha
  # The typed outcomes client: the eight application outcomes resolved
  # through the one versioned mapping table, mirroring the PHP
  # OutcomeMap. The table is the polarity authority: only the
  # server-confirmed trust outcomes may subtract risk, and exactly the
  # abuse outcomes write long-memory marks. The client carries the
  # mapping, the handle acceptance rules, the mark keys and the
  # idempotency keys; a host binds its own sink through the sink
  # interface.
  module Outcomes
    MAP_VERSION = 1

    OUTCOMES = %w[
      confirmedLegitimate stepUpCompleted authenticationSuccess
      authenticationFailure spamReported chargeback accountBanned
      fraudConfirmed
    ].freeze

    HANDLE_DIMENSIONS = %w[nonce decisionId principal target session agent].freeze

    LEDGER_DIMENSIONS = %w[nonce decisionId].freeze
    IDENTITY_DIMENSIONS = %w[principal target session agent].freeze
    EVERY_DIMENSION = (LEDGER_DIMENSIONS + IDENTITY_DIMENSIONS).freeze

    PSEUDONYM_PATTERN = /\A[0-9a-f]{32}\z/.freeze
    UNSAFE_HANDLE_CHARS = /[\u0000-\u001f\u007f:}]/.freeze

    # The risk-v1 feedback channel each outcome books.
    RISK_EVENT_KINDS = {
      'ProtectedActionSuccess' => 8,
      'ProtectedActionFailure' => 9,
      'AuthenticationSuccess' => 10,
      'AuthenticationFailure' => 11,
      'ConfirmedLegitimate' => 12,
      'ConfirmedAbuse' => 13
    }.freeze

    OutcomeHandle = Struct.new(:dimension, :id, keyword_init: true)

    OutcomeMapping = Struct.new(
      :outcome, :channel, :ledger_legitimate, :writes_abuse_mark,
      :server_confirmed, :may_subtract_risk, :accepted_handles,
      keyword_init: true
    )

    OutcomeReceipt = Struct.new(:outcome, :mapping, :ledger_status, :marks_written, keyword_init: true)

    TABLE = {
      'confirmedLegitimate' => OutcomeMapping.new(
        outcome: 'confirmedLegitimate', channel: RISK_EVENT_KINDS['ConfirmedLegitimate'],
        ledger_legitimate: true, writes_abuse_mark: false, server_confirmed: true,
        may_subtract_risk: true, accepted_handles: EVERY_DIMENSION
      ),
      'stepUpCompleted' => OutcomeMapping.new(
        outcome: 'stepUpCompleted', channel: RISK_EVENT_KINDS['ProtectedActionSuccess'],
        ledger_legitimate: nil, writes_abuse_mark: false, server_confirmed: true,
        may_subtract_risk: true, accepted_handles: IDENTITY_DIMENSIONS
      ),
      'authenticationSuccess' => OutcomeMapping.new(
        outcome: 'authenticationSuccess', channel: RISK_EVENT_KINDS['AuthenticationSuccess'],
        ledger_legitimate: nil, writes_abuse_mark: false, server_confirmed: true,
        may_subtract_risk: true, accepted_handles: IDENTITY_DIMENSIONS
      ),
      'authenticationFailure' => OutcomeMapping.new(
        outcome: 'authenticationFailure', channel: RISK_EVENT_KINDS['AuthenticationFailure'],
        ledger_legitimate: nil, writes_abuse_mark: false, server_confirmed: false,
        may_subtract_risk: false, accepted_handles: IDENTITY_DIMENSIONS
      ),
      'spamReported' => OutcomeMapping.new(
        outcome: 'spamReported', channel: RISK_EVENT_KINDS['ProtectedActionFailure'],
        ledger_legitimate: nil, writes_abuse_mark: true, server_confirmed: true,
        may_subtract_risk: false, accepted_handles: IDENTITY_DIMENSIONS
      ),
      'chargeback' => OutcomeMapping.new(
        outcome: 'chargeback', channel: RISK_EVENT_KINDS['ConfirmedAbuse'],
        ledger_legitimate: false, writes_abuse_mark: true, server_confirmed: true,
        may_subtract_risk: false, accepted_handles: EVERY_DIMENSION
      ),
      'accountBanned' => OutcomeMapping.new(
        outcome: 'accountBanned', channel: RISK_EVENT_KINDS['ConfirmedAbuse'],
        ledger_legitimate: false, writes_abuse_mark: true, server_confirmed: true,
        may_subtract_risk: false, accepted_handles: EVERY_DIMENSION
      ),
      'fraudConfirmed' => OutcomeMapping.new(
        outcome: 'fraudConfirmed', channel: RISK_EVENT_KINDS['ConfirmedAbuse'],
        ledger_legitimate: false, writes_abuse_mark: true, server_confirmed: true,
        may_subtract_risk: false, accepted_handles: EVERY_DIMENSION
      )
    }.freeze

    module_function

    def validate_outcome_handle(handle)
      id = handle.id
      if %w[principal target session].include?(handle.dimension)
        unless PSEUDONYM_PATTERN.match?(id)
          raise RangeError, "#{handle.dimension} handle must carry the 32-char lowercase hex pseudonym, never a raw identifier"
        end

        return
      end
      return if PSEUDONYM_PATTERN.match?(id)
      return unless id.empty? || UNSAFE_HANDLE_CHARS.match?(id)

      raise RangeError, "#{handle.dimension} handle id must be a 32-char lowercase hex id or a non-empty key-safe string"
    end

    def accepts?(mapping, dimension)
      mapping.accepted_handles.include?(dimension)
    end

    # The mark kind an outcome writes on identity handles, nil when
    # none.
    def mark_kind(mapping)
      mapping.writes_abuse_mark ? mapping.outcome : nil
    end

    def ledger_action?(mapping)
      !mapping.ledger_legitimate.nil?
    end

    # The mapping row of one outcome. The table is total over the
    # vocabulary.
    def outcome_mapping(outcome)
      TABLE.fetch(outcome)
    end

    # Every row, in vocabulary order (the completeness oracle).
    def all_outcome_mappings
      OUTCOMES.map { |outcome| TABLE[outcome] }
    end

    # The ledger dimensions in table order (nonce before decision id).
    def ledger_dimensions
      LEDGER_DIMENSIONS
    end

    # The identity dimensions in table order.
    def identity_dimensions
      IDENTITY_DIMENSIONS
    end

    # The long-memory mark key of one identity handle: the Redis
    # hash-tagged key the cores write, namespaced per deployment.
    def mark_key(namespace, dimension, id)
      "mark:{kiwi:#{namespace}}:#{dimension}:#{id}"
    end

    # The idempotency key of a handle report: a bounded HMAC of the
    # request id.
    def default_idempotency_key(handle, secret = nil)
      value = "#{handle.dimension}:#{handle.id}"
      key = secret || 'kiwicaptcha/outcomes-idem/v1'
      OpenSSL::HMAC.hexdigest('sha256', key.to_s.b, value.b)[0, 32]
    end

    # The sink a host implements to land outcomes in its risk store:
    # the always-on outcome ledger, the reputation feedback channel and
    # the long-memory marks. The client maps and validates; the sink
    # persists. Implement confirm_ledger, record_feedback, write_mark
    # and forget_mark.
    class MemorySink
      attr_reader :ledger, :marks, :feedback

      def initialize
        @ledger = {}
        @marks = {}
        @feedback = []
        @next_id = 1
      end

      def confirm_ledger(id, legitimate)
        status = legitimate ? 1 : 0
        @ledger[id] = status
        status
      end

      def record_feedback(channel, idempotency_key, handle)
        @feedback << { channel: channel, key: idempotency_key, handle: handle }
        nil
      end

      def write_mark(key, kind)
        existed = @marks.key?(key)
        @marks[key] = kind
        existed ? 0 : 1
      end

      def forget_mark(key)
        deleted = @marks.delete(key)
        deleted ? 1 : 0
      end
    end

    # The outcomes client over one sink.
    class Client
      def initialize(sink, namespace = 'd')
        @sink = sink
        @namespace = namespace
      end

      # Report one typed outcome for one handle. Raises RangeError when
      # the mapping accepts no such handle dimension for the outcome.
      def report(outcome, handle, idempotency_key = nil)
        mapping = Outcomes.outcome_mapping(outcome)
        Outcomes.validate_outcome_handle(handle)
        unless Outcomes.accepts?(mapping, handle.dimension)
          raise RangeError,
                "outcome #{outcome} cannot be reported on a #{handle.dimension} handle (accepted: #{mapping.accepted_handles.join(', ')})"
        end

        ledger_status = nil
        marks_written = 0
        if Outcomes::LEDGER_DIMENSIONS.include?(handle.dimension)
          ledger_status = @sink.confirm_ledger(handle.id, mapping.ledger_legitimate == true)
          key = idempotency_key || Outcomes.default_idempotency_key(handle)
          @sink.record_feedback(mapping.channel, key, handle)
          return OutcomeReceipt.new(outcome: outcome, mapping: mapping, ledger_status: ledger_status, marks_written: marks_written)
        end

        kind = Outcomes.mark_kind(mapping)
        unless kind.nil?
          marks_written = @sink.write_mark(Outcomes.mark_key(@namespace, handle.dimension, handle.id), kind)
        end
        key = idempotency_key || Outcomes.default_idempotency_key(handle)
        @sink.record_feedback(mapping.channel, key, handle)
        OutcomeReceipt.new(outcome: outcome, mapping: mapping, ledger_status: ledger_status, marks_written: marks_written)
      end

      # Remove the long-memory marks of the handle's dimension (the
      # erasure path).
      def forget(handle)
        return 0 if Outcomes::LEDGER_DIMENSIONS.include?(handle.dimension)

        @sink.forget_mark(Outcomes.mark_key(@namespace, handle.dimension, handle.id))
      end
    end
  end
end
