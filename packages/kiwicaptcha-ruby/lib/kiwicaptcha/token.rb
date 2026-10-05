# frozen_string_literal: true

require 'json'

module KiwiCaptcha
  # The client-submitted solution, decoded from the kiwi__token hidden
  # input. Wire format: base64(nonce "." counter "." duration_ms "."
  # telemetry_json ["." execution_digest[":" execution_trace]] ["."
  # rsw_proof]). The telemetry segment may contain dots, so decoding
  # splits on all dots and peels the optional suffix segments right to
  # left, independently.
  module Token
    # Hard ceiling for the client-reported duration (telemetry only).
    MAX_DURATION_MS = 3_600_000

    DECODE_CODES = %i[
      invalid_base64 invalid_utf8 malformed invalid_counter
      counter_exceeds_solver_maximum invalid_duration
    ].freeze

    SolutionToken = Struct.new(
      :nonce, :counter, :duration_ms, :telemetry,
      :execution_digest, :execution_trace, :rsw_proof,
      keyword_init: true
    ) do
      # Encode the token back to its canonical base64 wire form. The
      # trace rides in its wire spelling, so a decode and encode round
      # trip is byte identical.
      def encode
        Token.encode(self)
      end
    end

    CANONICAL_DECIMAL = /\A\d+\z/.freeze
    NONCE_SHAPE = /\A[A-Za-z0-9+\/]{43}=\z/.freeze
    RSW_PROOF_SHAPE = /\A[0-9a-f]{512}\z/.freeze
    EXECUTION_DIGEST_SHAPE = /\A[0-9a-f]{64}\z/.freeze

    module_function

    def canonical_decimal?(segment)
      return false if segment.empty? || !CANONICAL_DECIMAL.match?(segment)

      segment.length == 1 || !segment.start_with?('0')
    end

    def encode(token)
      plain = +"#{token.nonce}.#{token.counter}.#{token.duration_ms}.#{JSON.generate(token.telemetry)}"
      if token.execution_digest
        trace = token.execution_trace ? ":#{token.execution_trace}" : ''
        plain << ".#{token.execution_digest}#{trace}"
      end
      plain << ".#{token.rsw_proof}" if token.rsw_proof
      Base64Utils.encode_std(plain.b)
    end

    # Decode a raw token string with the exact acceptance split of the
    # PHP and Rust decoders: canonical base64, UTF-8 plaintext, at
    # least four segments, the canonical decimal rules, the solver
    # counter ceiling, the duration ceiling and a JSON-object telemetry
    # segment.
    def decode(raw)
      raise DecodeError, :malformed if raw.bytesize > 32_768

      plain_bytes = Base64Utils.decode_std(raw)
      raise DecodeError, :invalid_base64 if plain_bytes.nil?

      begin
        plain = plain_bytes.dup.force_encoding(Encoding::UTF_8)
        raise DecodeError, :invalid_utf8 unless plain.valid_encoding?

        plain = plain.b
      rescue DecodeError
        raise
      end

      parts = plain.split('.', -1)
      raise DecodeError, :malformed if parts.length < 4

      end_index = parts.length
      rsw_proof = nil
      execution_digest = nil
      execution_trace = nil
      if end_index >= 5 && RSW_PROOF_SHAPE.match?(parts[end_index - 1])
        rsw_proof = parts[end_index - 1]
        end_index -= 1
      end
      if end_index >= 5
        segment = parts[end_index - 1]
        colon = segment.index(':')
        digest_part = colon.nil? ? segment : segment[0...colon]
        if EXECUTION_DIGEST_SHAPE.match?(digest_part)
          execution_digest = digest_part
          unless colon.nil?
            execution_trace = segment[(colon + 1)..]
            raise DecodeError, :malformed if Base64Utils.decode_url(execution_trace).nil?
          end
          end_index -= 1
        end
      end

      telemetry_str = parts[3...end_index].join('.')
      nonce = parts[0]
      counter_str = parts[1]
      duration_str = parts[2]

      # The nonce is base64 of exactly 32 bytes: 43 alphabet chars plus
      # one padding sign. The strict re-encode check refuses shape
      # valid spellings whose final sextet carries non-zero unused
      # bits.
      unless nonce.length == 44 && NONCE_SHAPE.match?(nonce)
        raise DecodeError, :malformed
      end

      nonce_bytes = Base64Utils.decode_std(nonce)
      raise DecodeError, :malformed if nonce_bytes.nil? || nonce_bytes.bytesize != 32

      raise DecodeError, :invalid_counter unless canonical_decimal?(counter_str)

      counter_value = Integer(counter_str, 10)
      raise DecodeError, :counter_exceeds_solver_maximum if counter_str.length > 8 || counter_value >= Pow::SOLVER_MAX_HASHES

      raise DecodeError, :invalid_duration unless canonical_decimal?(duration_str)

      duration_ms = Integer(duration_str, 10)
      raise DecodeError, :invalid_duration if duration_ms > MAX_DURATION_MS

      begin
        parsed = JSON.parse(telemetry_str)
      rescue JSON::ParserError
        raise DecodeError, :malformed
      end
      raise DecodeError, :malformed unless parsed.is_a?(Hash)

      if execution_digest && !EXECUTION_DIGEST_SHAPE.match?(execution_digest)
        raise DecodeError, :malformed
      end

      SolutionToken.new(
        nonce: nonce,
        counter: counter_value,
        duration_ms: duration_ms,
        telemetry: parsed,
        execution_digest: execution_digest,
        execution_trace: execution_trace,
        rsw_proof: rsw_proof
      )
    end
  end
end
