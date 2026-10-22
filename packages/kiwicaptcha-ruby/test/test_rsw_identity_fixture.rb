# frozen_string_literal: true

require_relative 'helper'

# The one canonical rsw modulus identity fixture against the Ruby
# binding. protocol/rsw-identity-v1/fixtures.json pins the shared
# 2048-bit test modulus and the identity values every language binding
# must agree on: the canonical fingerprint (SHA-256 of the decoded
# 256-byte modulus), the legacy base64-text alias accepted only in the
# bounded migration mode, and the secondary pair used solely for
# cross-identity negative tests.
class RswIdentityFixtureTest < Minitest::Test
  include TestSupport

  FIXTURE = TestSupport.protocol('rsw-identity-v1/fixtures.json')

  def test_the_fixture_parses_and_pins_the_expected_fields
    assert_equal 1, FIXTURE['format_version']
    refute_nil FIXTURE['modulus_n_b64']
    refute_nil FIXTURE['lambda_b64']
    assert_match(/\A[0-9a-f]{64}\z/, FIXTURE['rsw_modulus_n_sha256'])
    assert_match(/\A[0-9a-f]{64}\z/, FIXTURE['legacy_base64_text_sha256'])
    refute_nil FIXTURE.dig('secondary', 'modulus_n_b64')
    assert_match(/\A[0-9a-f]{64}\z/, FIXTURE.dig('secondary', 'rsw_modulus_n_sha256'))
  end

  def test_the_canonical_and_legacy_identities_match_the_fixture
    modulus = FIXTURE['modulus_n_b64']
    assert_equal FIXTURE['rsw_modulus_n_sha256'],
                 KiwiCaptcha::Rsw.modulus_fingerprint_hex(modulus)
    assert KiwiCaptcha::Rsw.identity_matches?(FIXTURE['rsw_modulus_n_sha256'], modulus, false)
    # The legacy base64-text alias matches only while the bounded
    # migration mode is enabled; the binding derives it internally.
    assert KiwiCaptcha::Rsw.identity_matches?(FIXTURE['legacy_base64_text_sha256'], modulus, true)
    refute KiwiCaptcha::Rsw.identity_matches?(FIXTURE['legacy_base64_text_sha256'], modulus, false)
    # A foreign identity never matches.
    refute KiwiCaptcha::Rsw.identity_matches?('f' * 64, modulus, true)
  end

  def test_the_secondary_pair_fingerprints_and_never_matches_the_primary
    secondary = FIXTURE['secondary']
    assert_equal secondary['rsw_modulus_n_sha256'],
                 KiwiCaptcha::Rsw.modulus_fingerprint_hex(secondary['modulus_n_b64'])
    refute KiwiCaptcha::Rsw.identity_matches?(secondary['rsw_modulus_n_sha256'],
                                              FIXTURE['modulus_n_b64'], true)
  end

  def test_the_fixture_trapdoor_pair_validates
    trapdoor = KiwiCaptcha::Rsw::Trapdoor.new(FIXTURE['modulus_n_b64'], FIXTURE['lambda_b64'])
    assert_equal 2048, trapdoor.n.to_s(2).length
  end
end
