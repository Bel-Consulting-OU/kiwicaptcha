# frozen_string_literal: true

require_relative 'helper'

# The shared hostile wire corpus against the Ruby decoder. The fixture
# is expanded by the PHP generator and read byte-for-byte by every
# hosted SDK suite; the expected verdicts are the reference decoder's.
class WireHostileCorpusTest < Minitest::Test
  include TestSupport

  CORPUS = TestSupport.fixture('wire-hostile-corpus.json')

  def self.classify(code)
    case code.to_s
    when 'invalid_base64' then 'base64'
    when 'invalid_utf8' then 'utf8'
    when 'invalid_counter', 'counter_exceeds_solver_maximum' then 'counter'
    when 'invalid_duration' then 'duration'
    else 'malformed'
    end
  end

  def test_the_corpus_is_broad
    assert_operator CORPUS['counts']['total'], :>=, 100
  end

  def assert_value(expected, actual, message)
    expected.nil? ? assert_nil(actual, message) : assert_equal(expected, actual, message)
  end

  CORPUS['vectors'].each do |row|
    define_method("test_#{row['id'].gsub(/[^A-Za-z0-9_]/, '_')}") do
      expected = row['expect']
      if expected['verdict'] == 'accept'
        token = KiwiCaptcha::Token.decode(row['raw'])
        assert_equal expected['counter'], token.counter, row['id']
        assert_equal expected['duration_ms'], token.duration_ms, row['id']
        assert_value expected['execution_digest'], token.execution_digest, row['id']
        assert_value expected['execution_trace'], token.execution_trace, row['id']
        assert_value expected['rsw_proof'], token.rsw_proof, row['id']
        if expected.key?('telemetry')
          assert_equal expected['telemetry'], JSON.parse(JSON.generate(token.telemetry)),
                       "#{row['id']}: telemetry value"
        end
        if expected.key?('telemetry_score')
          assert_equal expected['telemetry_score'],
                       KiwiCaptcha::Telemetry.bot_signal?(token.telemetry, token.duration_ms),
                       "#{row['id']}: telemetry score"
        end
        next
      end

      error = assert_raises(KiwiCaptcha::DecodeError, row['id']) do
        KiwiCaptcha::Token.decode(row['raw'])
      end
      next if expected['class'] == 'any'

      assert_equal expected['class'], self.class.classify(error.code), row['id']
    end
  end
end
