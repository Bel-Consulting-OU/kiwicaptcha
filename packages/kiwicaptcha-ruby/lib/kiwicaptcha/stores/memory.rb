# frozen_string_literal: true

require 'json'

module KiwiCaptcha
  # The in-memory adapter: single-process evaluations, tests and tools.
  # The record map is synchronous under the GVL, so the read-decide-
  # write of the consume transition has no interleaving point and
  # exactly-once holds naturally.
  class MemoryStore
    attr_reader :authenticated_result_commit

    MemoryRow = Struct.new(:envelope_json, :state, :retained_until)

    def initialize(ttl_margin_secs: Store::DEFAULT_TTL_MARGIN_SECS, now: nil)
      raise RangeError, 'ttl_margin_secs must be >= 0' if ttl_margin_secs.negative?

      @authenticated_result_commit = true
      @rows = {}
      @mutex = Mutex.new
      @ttl_margin_secs = ttl_margin_secs
      @now = now || -> { Time.now.to_i }
    end

    # Store a pending record, replacing any record with the same nonce.
    def store(record)
      sweep
      envelope = Record.to_json_record(record).merge(
        'state' => 'pending', 'consumed_result' => nil, 'operation_identity' => nil
      )
      @mutex.synchronize do
        @rows[record.nonce] = MemoryRow.new(
          JSON.generate(envelope),
          'pending',
          record.expires_at + @ttl_margin_secs
        )
      end
      nil
    end

    # Peek a record, or nil when the nonce is unknown or expired.
    def find(nonce)
      row = live(nonce)
      return nil if row.nil?

      decoded = Store.decode_envelope(row.envelope_json)
      decoded&.record
    end

    # The terminal-state snapshot: one read, never two.
    def runtime_state(nonce)
      row = live(nonce)
      return Store::RuntimeStateSnapshot.new(kind: 'missing', record: nil, consumed: nil) if row.nil?

      decoded = Store.decode_envelope(row.envelope_json)
      if decoded.nil?
        return Store::RuntimeStateSnapshot.new(kind: 'missing', record: nil, consumed: nil)
      end

      case decoded.state
      when 'cancelled'
        Store::RuntimeStateSnapshot.new(kind: 'cancelled', record: decoded.record, consumed: nil)
      when 'consumed'
        Store::RuntimeStateSnapshot.new(kind: 'consumed', record: decoded.record, consumed: retained_snapshot(decoded))
      when 'pending'
        Store::RuntimeStateSnapshot.new(kind: 'pending', record: decoded.record, consumed: nil)
      else
        Store::RuntimeStateSnapshot.new(kind: 'missing', record: nil, consumed: nil)
      end
    end

    # The one-shot consume transition. Nil answers missing, cancelled
    # or corrupt; a nil identity records none. Raises StoreWriteError
    # when a non-nil identity could not be recorded on a fresh flip.
    def consume(nonce, operation_identity = nil)
      identity = Store.validated_operation_identity(operation_identity)
      row = live(nonce)
      return nil if row.nil?

      decoded = Store.decode_envelope(row.envelope_json)
      return nil if decoded.nil?

      if decoded.state == 'consumed'
        return retained_snapshot(decoded)
      end
      return nil if decoded.state != 'pending'

      # The pending-envelope guard mirrors the Redis script: a pending
      # envelope carrying a result or identity marker is a forged
      # rewrite.
      envelope = JSON.parse(row.envelope_json)
      return nil if !envelope['consumed_result'].nil? || !envelope['operation_identity'].nil?

      envelope['state'] = 'consumed'
      envelope['operation_identity'] = identity
      row.envelope_json = JSON.generate(envelope)
      row.state = 'consumed'
      Store::ConsumedRecordSnapshot.new(
        record: decoded.record, consumed_now: true, consumed_before: false,
        consumed_result: nil, operation_identity: identity
      )
    end

    # Commit the deterministic result of a consumed record, exactly
    # once. False answers missing, not consumed, or already committed.
    def commit_result(nonce, valid, binding, mac)
      row = live(nonce)
      return false if row.nil? || row.state != 'consumed'

      envelope = JSON.parse(row.envelope_json)
      return false unless envelope['consumed_result'].nil?

      result = { 'valid' => valid, 'binding' => binding }
      result['mac'] = mac unless mac.nil?
      envelope['consumed_result'] = result
      row.envelope_json = JSON.generate(envelope)
      true
    end

    # The fused cleanup: only the exact pending record is deleted.
    def delete_if_pending(nonce)
      row = live(nonce)
      return Store::DeleteIfPendingOutcome.new(kind: 'missing', consumed: nil) if row.nil?

      decoded = Store.decode_envelope(row.envelope_json)
      if decoded.nil?
        return Store::DeleteIfPendingOutcome.new(kind: 'corrupt', consumed: nil)
      end

      case decoded.state
      when 'consumed'
        Store::DeleteIfPendingOutcome.new(kind: 'consumed', consumed: retained_snapshot(decoded))
      when 'cancelled'
        Store::DeleteIfPendingOutcome.new(kind: 'cancelled', consumed: nil)
      when 'pending'
        @mutex.synchronize { @rows.delete(nonce) }
        Store::DeleteIfPendingOutcome.new(kind: 'deleted_pending', consumed: nil)
      else
        Store::DeleteIfPendingOutcome.new(kind: 'corrupt', consumed: nil)
      end
    end

    private

    def live(nonce)
      row = @mutex.synchronize { @rows[nonce] }
      return nil if row.nil?
      return nil if @now.call >= row.retained_until

      row
    end

    def retained_snapshot(decoded)
      Store::ConsumedRecordSnapshot.new(
        record: decoded.record, consumed_now: false, consumed_before: true,
        consumed_result: decoded.result, operation_identity: decoded.identity
      )
    end

    def sweep
      now = @now.call
      @mutex.synchronize do
        @rows.delete_if { |_nonce, row| now >= row.retained_until }
      end
    end
  end
end
