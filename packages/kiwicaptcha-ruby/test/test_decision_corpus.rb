# frozen_string_literal: true

require_relative 'helper'

# The shared decision and authority register:
# protocol/decision-v1/corpus.json. The Ruby side asserts every wire
# code, the retry table, the middleware status rows and every token
# source matrix row.
class DecisionCorpusTest < Minitest::Test
  include TestSupport

  def corpus
    TestSupport.protocol('decision-v1/corpus.json')
  end

  def test_every_wire_code_maps_to_its_registered_disposition
    register = corpus
    assert_equal register['codes'].keys.sort, KiwiCaptcha::VerifyError::ALL.sort
    register['codes'].each do |code, disposition|
      result = KiwiCaptcha::Verify.invalid(code)
      refute result.ok
      assert_equal disposition, result.disposition, code
      assert_equal code, result.code
    end
  end

  def test_the_retry_table_is_exactly_the_four_transient_codes
    register = corpus
    assert_equal register['retry_codes'].sort, KiwiCaptcha::Verify::RETRY_CODES.sort
    register['retry_codes'].each do |code|
      assert_equal 'retry', KiwiCaptcha::Verify.disposition_for(code)
    end
  end

  def test_the_middleware_status_rows_agree
    register = corpus
    assert_equal 200, register['http']['allow_status']
    assert_equal 503, register['http']['retry_status']
    assert_equal 422, register['http']['deny_status']['ruby']
  end

  def test_every_authority_row_resolves_under_reject_on_conflict
    authority = corpus['authority']
    assert_equal 'token_source_conflict', authority['conflict_code']
    assert_equal 'malformed_token', authority['missing_code']
    authority['matrix'].each do |row|
      token, failure = KiwiCaptcha::TokenSource.resolve_values(
        header_values: row['header'],
        form_values: row['form'],
        query_values: row['query']
      )
      case row['verdict']
      when 'verify'
        assert_nil failure, row['case']
        assert_equal row['token'], token, row['case']
      when 'conflict'
        assert_equal 'token_source_conflict', failure, row['case']
        assert_nil token, row['case']
      else
        assert_equal 'malformed_token', failure, row['case']
      end
    end
  end
end
