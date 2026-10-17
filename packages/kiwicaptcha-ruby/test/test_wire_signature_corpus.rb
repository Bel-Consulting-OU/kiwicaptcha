# frozen_string_literal: true

require_relative 'helper'

# The shared challenge-signature corpus against the Ruby verifier. The
# fixture is expanded by the PHP generator and read byte-for-byte by
# every hosted SDK suite.
class WireSignatureCorpusTest < Minitest::Test
  include TestSupport

  CORPUS = TestSupport.fixture('wire-signature-corpus.json')
  VerifyOptions = Struct.new(:tenant_id)

  def test_the_corpus_is_broad
    assert_operator CORPUS['counts']['total'], :>=, 40
  end

  CORPUS['vectors'].each do |row|
    define_method("test_#{row['id'].gsub(/[^A-Za-z0-9_]/, '_')}") do
      record = KiwiCaptcha::Record.from_json(row['record'])
      assert_equal row['challenge'], record.challenge, row['id']
      options = VerifyOptions.new(row['verify_tenant'])
      verified = KiwiCaptcha::Verify.verify_record_signature(
        options, record, row['verify_secret']
      )
      assert_equal row['expect'] == 'accept', verified, row['id']
    end
  end
end
