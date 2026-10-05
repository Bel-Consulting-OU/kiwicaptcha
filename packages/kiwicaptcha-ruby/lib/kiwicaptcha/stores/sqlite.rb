# frozen_string_literal: true

require 'json'

module KiwiCaptcha
  # The SQLite adapter: the zero-infrastructure single-node backend.
  # Every durable transition runs inside one begin-immediate
  # transaction (the lock taken before the row is read, the commit as
  # the durability point). SQLite serializes writers, so two racing
  # consumers of one nonce cannot both observe the pending row: exactly
  # one caller wins the consume and the loser reads the winner's
  # retained state. The column set matches the PHP SqliteStorage table
  # row for row, so one database file serves every SDK.
  #
  # The database handle is duck typed: an SQLite3::Database from the
  # optional sqlite3 gem, or any object answering execute(sql, params).
  class SqliteStore
    attr_reader :authenticated_result_commit

    SCHEMA_VERSION = 1

    SELECT_ROW = 'SELECT nonce, record_json, state, consumed_result_json, operation_identity, retained_until ' \
                 'FROM kiwicaptcha_challenge_records WHERE nonce = ?'

    Row = Struct.new(:nonce, :record_json, :state, :consumed_result_json, :operation_identity, :retained_until,
                     keyword_init: true)

    def initialize(db, ttl_margin_secs: Store::DEFAULT_TTL_MARGIN_SECS, now: nil)
      raise RangeError, 'ttl_margin_secs must be >= 0' if ttl_margin_secs.negative?

      @authenticated_result_commit = true
      @db = db
      @ttl_margin_secs = ttl_margin_secs
      @now = now || -> { Time.now.to_i }
      begin
        initialize_schema
      rescue StoreUnavailableError
        raise
      rescue StandardError => e
        raise StoreUnavailableError, "sqlite schema initialization failed: #{e.message}"
      end
    end

    def store(record)
      json = JSON.generate(Record.to_json_record(record))
      retained_until = record.expires_at + @ttl_margin_secs
      write_transition('challenge issuance') do
        @db.execute('DELETE FROM kiwicaptcha_challenge_records WHERE retained_until <= ?', [@now.call])
        @db.execute(
          'INSERT INTO kiwicaptcha_challenge_records ' \
          '(nonce, record_json, state, consumed_result_json, operation_identity, retained_until) ' \
          'VALUES (?, ?, ?, NULL, NULL, ?) ' \
          'ON CONFLICT(nonce) DO UPDATE SET ' \
          'record_json = excluded.record_json, state = excluded.state, ' \
          'consumed_result_json = excluded.consumed_result_json, ' \
          'operation_identity = excluded.operation_identity, ' \
          'retained_until = excluded.retained_until',
          [db_text(record.nonce), json, 'pending', retained_until]
        )
      end
      nil
    end

    def find(nonce)
      row = live_row(nonce)
      return nil if row.nil?

      decoded = decode_row(row)
      decoded&.record
    rescue StoreUnavailableError
      raise
    rescue StandardError => e
      raise StoreUnavailableError, "sqlite storage failure while reading the record: #{e.message}"
    end

    def runtime_state(nonce)
      row = live_row(nonce)
      if row.nil?
        return Store::RuntimeStateSnapshot.new(kind: 'missing', record: nil, consumed: nil)
      end

      decoded = decode_row(row)
      if decoded.nil?
        # A corrupt row fails closed as missing, never pending.
        return Store::RuntimeStateSnapshot.new(kind: 'missing', record: nil, consumed: nil)
      end

      case row.state
      when 'cancelled'
        Store::RuntimeStateSnapshot.new(kind: 'cancelled', record: decoded.record, consumed: nil)
      when 'consumed'
        Store::RuntimeStateSnapshot.new(kind: 'consumed', record: decoded.record, consumed: retained_snapshot(decoded))
      when 'pending'
        Store::RuntimeStateSnapshot.new(kind: 'pending', record: decoded.record, consumed: nil)
      else
        Store::RuntimeStateSnapshot.new(kind: 'missing', record: nil, consumed: nil)
      end
    rescue StoreUnavailableError
      raise
    rescue StandardError => e
      raise StoreUnavailableError, "sqlite storage failure while reading the runtime state: #{e.message}"
    end

    def consume(nonce, operation_identity = nil)
      identity = Store.validated_operation_identity(operation_identity)
      write_transition('the pending-to-consumed transition') do
        row = live_row(nonce)
        decoded = row.nil? ? nil : decode_row(row)
        if row.nil? || decoded.nil?
          nil
        elsif row.state == 'consumed'
          retained_snapshot(decoded)
        elsif row.state != 'pending'
          nil
        elsif !row.consumed_result_json.nil? || !row.operation_identity.nil?
          # The pending-envelope guard mirrors the Redis script marker
          # check: a pending row carrying a result or identity is a
          # forged rewrite and reports missing.
          nil
        else
          @db.execute(
            'UPDATE kiwicaptcha_challenge_records SET state = ?, operation_identity = ? WHERE nonce = ?',
            ['consumed', identity ? db_text(identity) : identity, db_text(nonce)]
          )
          after = row_by_nonce(nonce)
          if after.nil? || after.state != 'consumed' || (!identity.nil? && after.operation_identity != identity)
            raise StoreWriteError, 'the consume transition could not record the operation identity on the flipped row'
          end
          Store::ConsumedRecordSnapshot.new(
            record: decoded.record, consumed_now: true, consumed_before: false,
            consumed_result: nil, operation_identity: identity
          )
        end
      end
    end

    def commit_result(nonce, valid, binding, mac)
      result_json = mac.nil? ? JSON.generate('valid' => valid, 'binding' => binding) : JSON.generate('valid' => valid, 'binding' => binding, 'mac' => mac)
      write_transition('the result commit') do
        row = live_row(nonce)
        if row.nil? || decode_row(row).nil? || row.state != 'consumed' || !row.consumed_result_json.nil?
          false
        else
          @db.execute(
            'UPDATE kiwicaptcha_challenge_records SET consumed_result_json = ? WHERE nonce = ?',
            [result_json, db_text(nonce)]
          )
          true
        end
      end
    end

    def delete_if_pending(nonce)
      write_transition('the delete-if-pending transition') do
        row = live_row(nonce)
        decoded = row.nil? ? nil : decode_row(row)
        if row.nil?
          Store::DeleteIfPendingOutcome.new(kind: 'missing', consumed: nil)
        elsif decoded.nil?
          Store::DeleteIfPendingOutcome.new(kind: 'corrupt', consumed: nil)
        else
          case row.state
          when 'consumed'
            Store::DeleteIfPendingOutcome.new(kind: 'consumed', consumed: retained_snapshot(decoded))
          when 'cancelled'
            Store::DeleteIfPendingOutcome.new(kind: 'cancelled', consumed: nil)
          when 'pending'
            @db.execute('DELETE FROM kiwicaptcha_challenge_records WHERE nonce = ?', [db_text(nonce)])
            Store::DeleteIfPendingOutcome.new(kind: 'deleted_pending', consumed: nil)
          else
            Store::DeleteIfPendingOutcome.new(kind: 'corrupt', consumed: nil)
          end
        end
      end
    end

    # The sqlite3 gem binds a binary-encoded Ruby string as a blob,
    # which never matches a TEXT column. Every wire string here is
    # ASCII-7bit, so rebasing the encoding is lossless and keeps the
    # lookups textual.
    def db_text(value)
      value.is_a?(String) ? value.dup.force_encoding(Encoding::UTF_8) : value
    end

    private


    def initialize_schema
      # Contending writers must wait on the begin-immediate lock, never
      # fail it: a bounded busy timeout makes a losing racer observe the
      # winner's consumed state instead of raising.
      @db.busy_timeout = 5000 if @db.respond_to?(:busy_timeout=)
      @db.execute('PRAGMA journal_mode = WAL')
      @db.execute('BEGIN IMMEDIATE')
      version_row = @db.execute('PRAGMA user_version').first
      version = version_row.is_a?(Hash) ? version_row.values.first.to_i : Array(version_row).first.to_i
      raise "the database carries schema version #{version}, newer than the #{SCHEMA_VERSION} this adapter supports" if version > SCHEMA_VERSION

      if version < SCHEMA_VERSION
        @db.execute(
          'CREATE TABLE IF NOT EXISTS kiwicaptcha_challenge_records (' \
          'nonce TEXT PRIMARY KEY, ' \
          'record_json TEXT NOT NULL, ' \
          "state TEXT NOT NULL CHECK (state IN ('pending', 'consumed', 'cancelled')), " \
          'consumed_result_json TEXT, ' \
          'operation_identity TEXT, ' \
          'resume_owner TEXT, ' \
          'resume_until INTEGER, ' \
          'retained_until INTEGER NOT NULL)'
        )
        @db.execute(
          'CREATE INDEX IF NOT EXISTS kiwicaptcha_challenge_records_retained_until_idx ' \
          'ON kiwicaptcha_challenge_records (retained_until)'
        )
        @db.execute("PRAGMA user_version = #{SCHEMA_VERSION}")
      end
      @db.execute('COMMIT')
    rescue StandardError
      safe_rollback
      raise
    end

    def safe_rollback
      @db.execute('ROLLBACK')
    rescue StandardError
      # The rollback of a broken connection is best-effort.
      nil
    end

    # One durable transition: the lock precedes the body's reads.
    def write_transition(what)
      begin
        @db.execute('BEGIN IMMEDIATE')
      rescue StandardError => e
        raise StoreUnavailableError, "sqlite storage failure during #{what}: #{e.message}"
      end
      begin
        result = yield
        @db.execute('COMMIT')
        result
      rescue StoreWriteError => e
        safe_rollback
        raise e
      rescue StandardError => e
        safe_rollback
        raise StoreUnavailableError, "sqlite storage failure during #{what}: #{e.message}"
      end
    end

    def row_by_nonce(nonce)
      raw = @db.execute(SELECT_ROW, [db_text(nonce)]).first
      return nil if raw.nil?

      Row.new(
        nonce: raw.is_a?(Hash) ? raw['nonce'] : raw[0],
        record_json: raw.is_a?(Hash) ? raw['record_json'] : raw[1],
        state: raw.is_a?(Hash) ? raw['state'] : raw[2],
        consumed_result_json: raw.is_a?(Hash) ? raw['consumed_result_json'] : raw[3],
        operation_identity: raw.is_a?(Hash) ? raw['operation_identity'] : raw[4],
        retained_until: (raw.is_a?(Hash) ? raw['retained_until'] : raw[5]).to_i
      )
    end

    def live_row(nonce)
      row = row_by_nonce(nonce)
      return nil if row.nil?
      return nil if @now.call >= row.retained_until

      row
    end

    # Decode a row into the record, its committed result and its
    # recorded identity: the record JSON passes the strict authority
    # first, a malformed committed result degrades to absent, and any
    # structural failure answers nil (an unusable row, never a
    # partially trusted one).
    def decode_row(row)
      parsed = begin
        JSON.parse(row.record_json)
      rescue JSON::ParserError
        return nil
      end
      begin
        record = Record.from_json(parsed)
      rescue MalformedRecordError
        return nil
      end
      result = nil
      if row.consumed_result_json.is_a?(String)
        begin
          candidate = JSON.parse(row.consumed_result_json)
          if candidate.is_a?(Hash)
            unknown_keys = candidate.keys - %w[valid binding mac]
            valid_bool = candidate['valid'].is_a?(TrueClass) || candidate['valid'].is_a?(FalseClass)
            if unknown_keys.empty? && valid_bool
              result = Store::ConsumedResultRecord.new(
                valid: candidate['valid'],
                binding: candidate['binding'].is_a?(String) ? candidate['binding'] : nil,
                mac: candidate['mac'].is_a?(String) ? candidate['mac'] : nil
              )
            end
          end
        rescue JSON::ParserError
          result = nil
        end
      end
      identity = row.operation_identity.is_a?(String) && !row.operation_identity.empty? ? row.operation_identity : nil
      Store::EnvelopeDecoded.new(state: row.state, record: record, result: result, identity: identity)
    end

    def retained_snapshot(decoded)
      Store::ConsumedRecordSnapshot.new(
        record: decoded.record, consumed_now: false, consumed_before: true,
        consumed_result: decoded.result, operation_identity: decoded.identity
      )
    end
  end
end
