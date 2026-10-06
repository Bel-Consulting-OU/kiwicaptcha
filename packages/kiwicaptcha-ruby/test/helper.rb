# frozen_string_literal: true

require 'json'
require 'minitest/autorun'
require_relative '../lib/kiwicaptcha'

# Shared test support: the protocol corpus paths, the PHP-issued golden
# vectors and the record and token builders every suite composes.
module TestSupport
  PACKAGE_ROOT = File.expand_path('..', __dir__)
  REPO_ROOT = File.expand_path('../..', PACKAGE_ROOT)
  PROTOCOL_DIR = File.join(REPO_ROOT, 'protocol')

  SECRET = '0123456789abcdef0123456789abcdef'
  CLIENT_IP = '203.0.113.7'
  ISSUED_AT = 1_800_000_000
  NOW = 1_800_000_100

  def self.protocol(relpath)
    JSON.parse(File.read(File.join(PROTOCOL_DIR, relpath)))
  end

  def self.fixture(relpath)
    JSON.parse(File.read(File.join(PACKAGE_ROOT, 'test', 'fixtures', relpath)))
  end

  def self.golden
    @golden ||= fixture('golden-php-vectors.json')
  end

  def self.golden_record(name)
    row = golden['records'].find { |entry| entry['name'] == name }
    raise KeyError, "golden record #{name} missing" if row.nil?

    row
  end

  # The frozen test clock: the golden records were issued once by the
  # PHP core, so every test that redeems them travels back to the
  # issuance era on both clocks.
  def self.frozen_clock(record)
    { now: -> { record.issued_at + 10 }, now_ns: record.issued_at_ns + 2_000_000 }
  end

  def self.record_from_row(row)
    KiwiCaptcha::Record.from_json(row['record'])
  end

  def self.token_for(nonce, counter, duration_ms, telemetry = {},
                     execution_digest: nil, execution_trace: nil)
    KiwiCaptcha::Token::SolutionToken.new(
      nonce: nonce, counter: counter, duration_ms: duration_ms, telemetry: telemetry,
      execution_digest: execution_digest, execution_trace: execution_trace, rsw_proof: nil
    ).encode
  end

  def self.solve_sha(prefix, salt_b64, target_bits)
    KiwiCaptcha::Pow.solve_sha256(prefix, salt_b64, target_bits)
  end

  def self.verify_options(over = {})
    defaults = {
      storage: nil, secret_key: SECRET, expected_scope: 'login', client_ip: nil,
      now_ns: nil, now: nil, enforce_telemetry: false, operation_identity: nil,
      expected_request_binding: nil, binding_expectation: :exact,
      expected_policy_version: nil, policy_version_floor: nil,
      region: nil, expected_issuer: nil, secrets_by_kid: {},
      revoked_kids: [], tenant_id: nil, accept_legacy_v1: false, rsw: nil
    }
    KiwiCaptcha::Verify::VerifyOptions.new(**defaults.merge(over))
  end

  # The Rust-issued canonical v1 vectors, mirrored from the PHP test
  # fixtures and asserted byte-exact by every core suite.
  SHA_VECTOR = {
    'nonce' => '2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=',
    'challenge' => 'MmwwSVZoMXh1S05qemNDRHlWK1gwbHJjZU1IbEh2bXFDczVNZER3OHR3MD18bG9naW58' \
                   'OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1' \
                   'ZDY0ODUwMDM0YnwxODAwMDAwMDAw.' \
                   'dee1893de8e9f57e974af43ec5b6e7523f7d09cee038a8edd5df59ad2f9248ba',
    'salt' => 'phUfA189G9A5KMv3r+wzLA==',
    'prefix' => 'MmwwSVZoMXh1S05qemNDRHlWK1gwbHJjZU1IbEh2bXFDczVNZER3OHR3MD18bG9naW58' \
                'OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1' \
                'ZDY0ODUwMDM0YnwxODAwMDAwMDAw.' \
                'dee1893de8e9f57e974af43ec5b6e7523f7d09cee038a8edd5df59ad2f9248ba' \
                '|phUfA189G9A5KMv3r+wzLA==|',
    'algorithm' => 'sha256',
    'm_kib' => 0, 't' => 1, 'p' => 1, 'target_bits' => 8,
    'counter' => 158, 'outcome' => 'Valid'
  }.freeze

  IP_HASH = '9c50b8d493de847656a168d0408bd4455994df2fc0b1e94bab5a85d64850034b'
end
