# frozen_string_literal: true

require 'digest'
require 'json'

module KiwiCaptcha
  # The server-side challenge record and its strict serde mirror
  # parser, mirroring the Rust ChallengeRecord field names one to one
  # so PHP, Rust, Node, Ruby and Elixir share the same Redis and
  # SQLite records.
  module Record
    MAX_PROTOCOL_VERSION = 5
    BASE_PROTOCOL_VERSION = 2
    DECOY_PROTOCOL_VERSION = 3
    EXECUTION_PROTOCOL_VERSION = 4
    RSW_IDENTITY_PROTOCOL_VERSION = 5

    # Maximum byte length of any wire string (the serde parse ceiling).
    MAX_STRING_BYTES = 4096

    MAX_EXECUTION_VERSION = 5
    MAX_PROGRAM_BASE64 = 4096

    U32_MAX = 4_294_967_295

    WIRE_KEYS = %w[
      nonce scope binding_tag issued_at expires_at
      algorithm m_kib t p target_bits salt prefix
      challenge min_duration_ms issued_at_ns protocol_version
      attempts_used region policy_version request_binding
      issuer kid hostname decoy_field execution_program
      execution_version execution_commitment rsw_modulus_sha256
      server_mac
    ].freeze

    REQUIRED_KEYS = %w[
      nonce scope binding_tag issued_at expires_at
      algorithm m_kib t p target_bits salt prefix
      challenge min_duration_ms
    ].freeze

    IDENTIFIER_ALPHABET = /\A[A-Za-z0-9._:-]+\z/.freeze
    DECOY_ALPHABET = /\A[A-Za-z0-9_-]+\z/.freeze
    HEX64 = /\A[0-9a-f]{64}\z/.freeze
    HOSTNAME_FORBIDDEN = /[\x00-\x20\x7f]/.freeze

    # The narrow security-identifier alphabet: deployment-bound
    # identifiers can never smuggle canonical separators, whitespace or
    # multi-byte text into a signed payload segment.
    def self.valid_identifier?(value, max_bytes)
      !value.empty? && value.bytesize <= max_bytes && IDENTIFIER_ALPHABET.match?(value)
    end

    # The decoy (honeypot) field-name grammar.
    def self.valid_decoy_field_name?(value)
      value.length >= 1 && value.length <= 64 && DECOY_ALPHABET.match?(value)
    end

    # The protocol versus extension grammar, the one shared matrix
    # every boundary applies: v1 and v2 carry neither extension, v3
    # requires the decoy, v4 requires the execution triplet, v5
    # requires the rsw identity.
    def self.protocol_extension_grammar_ok?(protocol_version, decoy_present, execution_present, rsw_identity_present)
      case protocol_version
      when 1 then !decoy_present && !execution_present && !rsw_identity_present
      when BASE_PROTOCOL_VERSION then !decoy_present && !execution_present
      when DECOY_PROTOCOL_VERSION then decoy_present && !execution_present
      when EXECUTION_PROTOCOL_VERSION then execution_present
      when RSW_IDENTITY_PROTOCOL_VERSION then rsw_identity_present
      else false
      end
    end

    # The stored challenge record. Field names mirror the node surface
    # so the port map reads one to one across SDKs.
    ChallengeRecord = Struct.new(
      :nonce, :scope, :binding_tag, :issued_at, :expires_at,
      :algorithm, :m_kib, :t, :p, :target_bits, :salt, :prefix, :challenge,
      :min_duration_ms, :issued_at_ns, :protocol_version,
      :region, :policy_version, :request_binding, :issuer, :kid, :hostname,
      :decoy_field, :execution_program, :execution_version, :execution_commitment,
      :rsw_modulus_sha256, :server_mac,
      keyword_init: true
    )

    module_function

    def require_string(data, field)
      value = data[field]
      raise MalformedRecordError, "#{field} must be a string" unless value.is_a?(String)
      raise MalformedRecordError, "#{field} exceeds the wire string ceiling" if value.bytesize > MAX_STRING_BYTES

      value
    end

    def require_int(data, field, min, max, fallback = :absent)
      raw = data.key?(field) ? data[field] : fallback
      raise MalformedRecordError, "#{field} must be an integer within #{min}..#{max}" if raw == :absent
      raise MalformedRecordError, "#{field} must be an integer within #{min}..#{max}" unless raw.is_a?(Integer) && raw >= min && raw <= max

      raw
    end

    def optional_string(data, field)
      value = data[field]
      return nil if value.nil?

      require_string(data, field)
    end

    def validate_hostname(data)
      value = data['hostname']
      return nil if value.nil?

      text = require_string(data, 'hostname')
      raise MalformedRecordError, 'hostname must be a non-empty string or null' if text.empty?
      raise MalformedRecordError, 'hostname must not carry whitespace or control characters' if HOSTNAME_FORBIDDEN.match?(text)

      text
    end

    def parse_rsw_modulus_sha256(data)
      value = data['rsw_modulus_sha256']
      return nil if value.nil?

      unless value.is_a?(String) && HEX64.match?(value)
        raise MalformedRecordError, 'rsw_modulus_sha256 must be 64 lowercase hex characters'
      end
      raise MalformedRecordError, 'rsw_modulus_sha256 may only ride an rsw record' unless data['algorithm'] == 'rsw'
      if (data['protocol_version'] || 1).to_i == 1
        raise MalformedRecordError,
              'rsw_modulus_sha256 may not ride the v1 canonical (the v1 signature carries no identity segment)'
      end

      value
    end

    # The base64 wire shape of an execution program: a structural check
    # only (canonical base64 within the ceiling). The full grammar runs
    # in the issuing interpreter; this boundary keeps persisted reads
    # independent of any interpreter.
    def valid_program_shape?(program_b64)
      !Base64Utils.decode_std(program_b64).nil?
    end

    # Rebuild a record from persisted JSON data with the strict serde
    # semantics: whitelisted keys only, exact algorithm values, strict
    # integer ranges, the legacy ip_hash alias, the total protocol
    # grammar and the exact execution triplet equivalence.
    def from_json(json)
      raise MalformedRecordError, 'the record must be a JSON object' unless json.is_a?(Hash)

      data = {}
      json.each { |k, v| data[k.to_s] = v }

      data.each_key do |key|
        next if key == 'ip_hash' || WIRE_KEYS.include?(key)

        raise MalformedRecordError, "unknown record key: #{key}"
      end
      if data.key?('ip_hash')
        raise MalformedRecordError, 'binding_tag and ip_hash may not appear together' if data.key?('binding_tag')

        data['binding_tag'] = data['ip_hash']
      end
      REQUIRED_KEYS.each do |field|
        raise MalformedRecordError, "missing record field: #{field}" unless data.key?(field)
      end
      %w[nonce scope binding_tag salt prefix challenge].each do |field|
        require_string(data, field)
      end
      %w[issued_at expires_at min_duration_ms].each do |field|
        require_int(data, field, 0, (1 << 62))
      end
      require_int(data, 'issued_at_ns', 0, (1 << 62), 0)
      %w[m_kib t p target_bits attempts_used].each do |field|
        require_int(data, field, 0, U32_MAX, 0)
      end
      %w[policy_version kid].each do |field|
        require_int(data, field, 0, U32_MAX, 1)
      end
      protocol_version = require_int(data, 'protocol_version', 1, MAX_PROTOCOL_VERSION, 1)
      algorithm = data['algorithm']
      unless Canonical::POW_ALGORITHMS.include?(algorithm)
        raise MalformedRecordError, "invalid algorithm: #{algorithm.inspect}"
      end
      { 'region' => 64, 'request_binding' => 128, 'issuer' => 128 }.each do |field, max|
        value = optional_string(data, field)
        if value && !valid_identifier?(value, max)
          raise MalformedRecordError, "#{field} must match the identifier alphabet"
        end
      end
      decoy = optional_string(data, 'decoy_field')
      if decoy && !valid_decoy_field_name?(decoy)
        raise MalformedRecordError, 'decoy_field must match the decoy name alphabet'
      end

      execution_program = nil
      raw_program = optional_string(data, 'execution_program')
      if raw_program
        raise MalformedRecordError, 'execution_program exceeds the program ceiling' if raw_program.bytesize > MAX_PROGRAM_BASE64
        unless valid_program_shape?(raw_program)
          raise MalformedRecordError, 'execution_program is not a well-formed program blob'
        end

        execution_program = raw_program
      end
      has_version = !data['execution_version'].nil?
      has_commitment = !data['execution_commitment'].nil?
      execution_version = nil
      execution_commitment = nil
      if execution_program || has_version || has_commitment
        if execution_program.nil? || !has_version || !has_commitment
          raise MalformedRecordError, 'the execution triplet must be present together'
        end

        execution_version = require_int(data, 'execution_version', 1, MAX_EXECUTION_VERSION)
        execution_commitment = require_string(data, 'execution_commitment')
        unless HEX64.match?(execution_commitment)
          raise MalformedRecordError, 'execution_commitment must be 64 lowercase hex characters'
        end
        expected = Digest::SHA256.hexdigest(execution_program.b)
        if expected != execution_commitment
          raise MalformedRecordError, 'execution_commitment does not match the stored program'
        end
      end
      rsw_modulus_sha256 = parse_rsw_modulus_sha256(data)
      unless protocol_extension_grammar_ok?(protocol_version, !decoy.nil?, !execution_program.nil?, !rsw_modulus_sha256.nil?)
        raise MalformedRecordError, "invalid protocol/extension combination for version #{protocol_version}"
      end

      server_mac = nil
      if !data['server_mac'].nil?
        mac = require_string(data, 'server_mac')
        raise MalformedRecordError, 'server_mac must be 64 lowercase hex characters' unless Mac::SERVER_STATE_MAC_PATTERN.match?(mac)

        server_mac = mac
      end
      ChallengeRecord.new(
        nonce: data['nonce'],
        scope: data['scope'],
        binding_tag: data['binding_tag'],
        issued_at: data['issued_at'],
        expires_at: data['expires_at'],
        algorithm: algorithm,
        m_kib: data.fetch('m_kib', 0),
        t: data.fetch('t', 0),
        p: data.fetch('p', 0),
        target_bits: data.fetch('target_bits', 0),
        salt: data['salt'],
        prefix: data['prefix'],
        challenge: data['challenge'],
        min_duration_ms: data['min_duration_ms'],
        issued_at_ns: data.fetch('issued_at_ns', 0),
        protocol_version: protocol_version,
        region: data.fetch('region', nil),
        policy_version: data.fetch('policy_version', 1),
        request_binding: data.fetch('request_binding', nil),
        issuer: data.fetch('issuer', nil),
        kid: data.fetch('kid', 1),
        hostname: validate_hostname(data),
        decoy_field: decoy,
        execution_program: execution_program,
        execution_version: execution_version,
        execution_commitment: execution_commitment,
        rsw_modulus_sha256: rsw_modulus_sha256,
        server_mac: server_mac
      )
    end

    # Serialize a record to the canonical wire JSON (v2 key set).
    def to_json_record(record)
      data = {
        'nonce' => record.nonce,
        'scope' => record.scope,
        'binding_tag' => record.binding_tag,
        'issued_at' => record.issued_at,
        'expires_at' => record.expires_at,
        'algorithm' => record.algorithm,
        'm_kib' => record.m_kib,
        't' => record.t,
        'p' => record.p,
        'target_bits' => record.target_bits,
        'salt' => record.salt,
        'prefix' => record.prefix,
        'challenge' => record.challenge,
        'min_duration_ms' => record.min_duration_ms,
        'issued_at_ns' => record.issued_at_ns,
        'protocol_version' => record.protocol_version,
        'attempts_used' => 0,
        'region' => record.region,
        'policy_version' => record.policy_version,
        'request_binding' => record.request_binding,
        'issuer' => record.issuer,
        'kid' => record.kid,
        'hostname' => record.hostname
      }
      data['decoy_field'] = record.decoy_field if record.decoy_field
      data['execution_program'] = record.execution_program if record.execution_program
      data['execution_version'] = record.execution_version if record.execution_version
      data['execution_commitment'] = record.execution_commitment if record.execution_commitment
      data['rsw_modulus_sha256'] = record.rsw_modulus_sha256 if record.rsw_modulus_sha256
      data['server_mac'] = record.server_mac if record.server_mac
      data
    end
  end
end
