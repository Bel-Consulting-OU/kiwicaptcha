# frozen_string_literal: true

module KiwiCaptcha
  # Verify error codes: the machine readable snake_case vocabulary
  # shared with the PHP and Rust cores. Values are stable wire tokens;
  # logs, metrics and cross-service consumers switch on them without
  # parsing prose.
  module VerifyError
    BAD_SIGNATURE = 'bad_signature'
    EXPIRED = 'expired'
    WRONG_SCOPE = 'wrong_scope'
    IP_MISMATCH = 'ip_mismatch'
    MISSING_CLIENT_IP = 'missing_client_ip'
    WRONG_REGION = 'wrong_region'
    WRONG_ISSUER = 'wrong_issuer'
    WRONG_POLICY_VERSION = 'wrong_policy_version'
    UNKNOWN_KID = 'unknown_kid'
    TOO_FAST = 'too_fast'
    INSUFFICIENT_WORK = 'insufficient_work'
    MALFORMED_RECORD = 'malformed_record'
    RECORD_NOT_FOUND = 'record_not_found'
    MALFORMED_TOKEN = 'malformed_token'
    UNSUPPORTED_ARGON2_PARAMS = 'unsupported_argon2_params'
    TOO_MANY_ATTEMPTS = 'too_many_attempts'
    TELEMETRY_REJECTED = 'telemetry_rejected'
    CAPACITY_EXCEEDED = 'capacity_exceeded'
    ADMISSION_UNAVAILABLE = 'admission_unavailable'
    STORAGE_UNAVAILABLE = 'storage_unavailable'
    CONSUME_INDETERMINATE = 'consume_indeterminate'
    ALREADY_CONSUMED = 'already_consumed'
    REQUEST_BINDING_MISMATCH = 'request_binding_mismatch'
    EXECUTION_MISMATCH = 'execution_mismatch'
    UNSUPPORTED_RSW_PARAMS = 'unsupported_rsw_params'

    ALL = [
      BAD_SIGNATURE, EXPIRED, WRONG_SCOPE, IP_MISMATCH, MISSING_CLIENT_IP,
      WRONG_REGION, WRONG_ISSUER, WRONG_POLICY_VERSION, UNKNOWN_KID, TOO_FAST,
      INSUFFICIENT_WORK, MALFORMED_RECORD, RECORD_NOT_FOUND, MALFORMED_TOKEN,
      UNSUPPORTED_ARGON2_PARAMS, TOO_MANY_ATTEMPTS, TELEMETRY_REJECTED,
      CAPACITY_EXCEEDED, ADMISSION_UNAVAILABLE, STORAGE_UNAVAILABLE,
      CONSUME_INDETERMINATE, ALREADY_CONSUMED, REQUEST_BINDING_MISMATCH,
      EXECUTION_MISMATCH, UNSUPPORTED_RSW_PARAMS
    ].freeze

    DESCRIPTIONS = {
      BAD_SIGNATURE => 'challenge signature is invalid',
      EXPIRED => 'challenge has expired',
      WRONG_SCOPE => 'challenge was issued for a different scope',
      IP_MISMATCH => 'challenge was issued to a different client IP',
      MISSING_CLIENT_IP => 'challenge is IP-bound but no client IP was supplied',
      WRONG_REGION => 'challenge was issued for a different region',
      WRONG_ISSUER => 'challenge was issued by a different deployment',
      WRONG_POLICY_VERSION => 'challenge was issued under a different security-policy epoch',
      UNKNOWN_KID => 'unknown signing key id',
      TOO_FAST => 'solution arrived faster than the theoretical minimum (server-measured)',
      INSUFFICIENT_WORK => 'solution does not meet the difficulty target',
      MALFORMED_RECORD => 'stored challenge record is malformed',
      RECORD_NOT_FOUND => 'challenge record not found (unknown or already deleted)',
      MALFORMED_TOKEN => 'solution token is malformed',
      UNSUPPORTED_ARGON2_PARAMS => 'Argon2id parameters exceed the supported process ceilings',
      TOO_MANY_ATTEMPTS => 'too many verification attempts',
      TELEMETRY_REJECTED => 'bot-signal telemetry rejected the solution',
      CAPACITY_EXCEEDED => 'verification capacity exceeded, try again shortly',
      ADMISSION_UNAVAILABLE => 'verification admission backend unavailable, try again shortly',
      STORAGE_UNAVAILABLE => 'verification storage backend unavailable, try again shortly',
      CONSUME_INDETERMINATE => 'verification storage response indeterminate, the challenge may or may not have been consumed',
      ALREADY_CONSUMED => 'the challenge was already consumed by a different logical operation',
      REQUEST_BINDING_MISMATCH => 'the challenge is not bound to the expected application transaction',
      EXECUTION_MISMATCH => 'the execution digest does not match the expected program trace of the challenge',
      UNSUPPORTED_RSW_PARAMS => 'the rsw challenge cannot be verified: this verifier lacks the matching trapdoor, or the signed sequential cost is out of bounds'
    }.freeze

    module_function

    # Whether a failure is exempt from the one-shot policy on a consumed
    # record. The failure describes the original redemption's
    # circumstances rather than this request's authorization. Every
    # other verdict is a security verdict: it stands even when the
    # operation identity matches a consumed record's stored success.
    def replay_exempt?(code)
      [EXPIRED, IP_MISMATCH, MISSING_CLIENT_IP, TELEMETRY_REJECTED].include?(code)
    end

    # Operator facing description of one failure code.
    def describe(code)
      DESCRIPTIONS[code]
    end
  end

  # Raised by the strict record parser on any structural violation.
  class MalformedRecordError < StandardError; end

  # Raised by the strict token decoder; carries the stable wire reason.
  class DecodeError < StandardError
    attr_reader :code

    def initialize(code)
      super(code.to_s)
      @code = code
    end
  end

  # Raised when a store write could not be recorded atomically.
  class StoreWriteError < StandardError; end

  # Raised on backend failure: the verifier answers storage_unavailable.
  class StoreUnavailableError < StandardError; end
end
