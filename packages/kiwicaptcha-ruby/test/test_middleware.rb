# frozen_string_literal: true

require_relative 'helper'
require 'rack'
require 'stringio'

# The Rack middleware over a mock request: token extraction, the 422
# JSON failure, the redirect mode, the fail-closed storage outage and
# the downstream env exposure.
class RackMiddlewareTest < Minitest::Test
  include TestSupport

  def golden
    @golden ||= begin
      row = TestSupport.golden_record('sha_plain')
      record = TestSupport.record_from_row(row)
      { row: row, record: record }
    end
  end

  # One fresh store per request: every call of the factory redeems its
  # own copy of the golden record, like a real deployment.
  def fresh_options
    storage = KiwiCaptcha::MemoryStore.new(now: -> { golden[:record].issued_at + 10 })
    storage.store(golden[:record])
    TestSupport.verify_options(
      { storage: storage, secret_key: SECRET }.merge(TestSupport.frozen_clock(golden[:record]))
    )
  end

  def downstream
    lambda { |env|
      result = env['kiwi.verify']
      [200, { 'Content-Type' => 'text/plain' }, ["ok:#{!result.nil? && result.decision_handle == golden[:record].nonce}"]]
    }
  end

  def env_for(params: {}, header: nil)
    env = {
      'REQUEST_METHOD' => 'POST',
      'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
      'rack.input' => StringIO.new(::Rack::Utils.build_query(params)),
      'rack.errors' => StringIO.new
    }
    env['HTTP_X_KIWI_TOKEN'] = header if header
    env
  end

  def test_a_valid_token_passes_and_exposes_the_result_downstream
    app = KiwiCaptcha::Rack::Verifier.new(downstream, verify: ->(_env) { fresh_options })
    status, _headers, body = app.call(env_for(params: { 'kiwi__token' => golden[:row]['token_b64'] }))
    assert_equal 200, status
    assert_equal 'ok:true', body.first
  end

  def test_a_missing_token_answers_the_typed_malformed_body
    app = KiwiCaptcha::Rack::Verifier.new(downstream, verify: ->(_env) { fresh_options })
    status, headers, body = app.call(env_for)
    assert_equal 422, status
    assert_equal 'application/json', headers['Content-Type']
    error = JSON.parse(body.first).fetch('error')
    assert_equal 'malformed_token', error.fetch('code')
  end

  def test_a_failed_verification_answers_422_with_the_typed_code
    app = KiwiCaptcha::Rack::Verifier.new(downstream, verify: ->(_env) { fresh_options })
    status, _headers, body = app.call(env_for(params: { 'kiwi__token' => 'not-a-token' }))
    assert_equal 422, status
    assert_equal 'malformed_token', JSON.parse(body.first).fetch('error').fetch('code')
  end

  def test_the_header_carries_the_token
    app = KiwiCaptcha::Rack::Verifier.new(downstream, verify: ->(_env) { fresh_options })
    status, = app.call(env_for(header: golden[:row]['token_b64']))
    assert_equal 200, status
  end

  def test_the_redirect_mode_answers_303
    redirect_downstream = ->(_env) { [200, {}, ['never']] }
    app = KiwiCaptcha::Rack::Verifier.new(
      redirect_downstream, verify: ->(_env) { fresh_options }, failure_redirect: '/try-again'
    )
    status, headers, = app.call(env_for)
    assert_equal 303, status
    assert_equal '/try-again', headers['Location']
  end

  def test_a_storage_outage_is_fail_closed_422
    failing = Object.new
    failing.define_singleton_method(:runtime_state) { raise 'down' }
    app = KiwiCaptcha::Rack::Verifier.new(
      downstream, verify: ->(_env) { TestSupport.verify_options(storage: failing, secret_key: SECRET) }
    )
    status, _headers, body = app.call(env_for(params: { 'kiwi__token' => golden[:row]['token_b64'] }))
    assert_equal 422, status
    assert_equal 'storage_unavailable', JSON.parse(body.first).fetch('error').fetch('code')
  end

  def test_the_factory_accepts_a_plain_hash
    factory = lambda { |_env|
      storage = KiwiCaptcha::MemoryStore.new(now: -> { golden[:record].issued_at + 10 })
      storage.store(golden[:record])
      { storage: storage, secret_key: SECRET }.merge(TestSupport.frozen_clock(golden[:record]))
    }
    app = KiwiCaptcha::Rack::Verifier.new(downstream, verify: factory)
    status, = app.call(env_for(params: { 'kiwi__token' => golden[:row]['token_b64'] }))
    assert_equal 200, status
  end
end

# The Rails concern and the form helper, driven on framework-pure
# doubles: no Rails installation is required to verify the behavior.
class RailsIntegrationTest < Minitest::Test
  include TestSupport

  class FakeResponse
    attr_accessor :status, :body, :headers

    def initialize
      @headers = {}
    end
  end

  class FakeController
    include KiwiCaptcha::Rails::ControllerConcern
    extend KiwiCaptcha::Rails::FormHelper

    attr_reader :params, :response

    # One fresh storage per verification: the hook factory a real
    # controller would wire to its configured store.
    kiwi_verify do
      golden = TestSupport.golden_record('sha_plain')
      record = TestSupport.record_from_row(golden)
      storage = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
      storage.store(record)
      TestSupport.verify_options(
        { storage: storage, secret_key: TestSupport::SECRET }.merge(TestSupport.frozen_clock(record))
      )
    end

    def initialize(params)
      @params = params
      @response = FakeResponse.new
    end

    def run_hook
      kiwi_verify!
    end
  end

  def test_the_concern_verifies_and_exposes_the_result
    row = TestSupport.golden_record('sha_plain')
    controller = FakeController.new('kiwi__token' => row['token_b64'])
    result = controller.run_hook
    assert result.ok
    assert_equal controller.kiwi_verify_result, result
    refute controller.kiwi_verify_failed?
  end

  def test_the_concern_renders_the_json_failure
    controller = FakeController.new({})
    controller.run_hook
    assert_equal 422, controller.response.status
    assert_equal 'application/json', controller.response.headers['Content-Type']
    assert_equal 'malformed_token', JSON.parse(controller.response.body).fetch('error').fetch('code')
    assert controller.kiwi_verify_failed?
  end

  def test_the_form_helper_renders_the_drop_in_markup
    html = FakeController.kiwi_form_field('login')
    assert_includes html, '<script src="/kiwi.js" defer></script>'
    assert_includes html, 'name="kiwi__token"'
    assert_includes html, 'data-kiwi="login"'
    attrs = FakeController.kiwi_form_attributes('signup')
    assert_equal 'data-kiwi="signup"', attrs
    # Scope sanitization keeps hostile values out of the markup.
    hostile = FakeController.kiwi_form_field('login"><script>')
    refute_includes hostile, '";'
  end
end

# The Sinatra helper, mixed into a plain context that ducks the Sinatra
# surface (params, status, content_type, redirect).
class SinatraHelperTest < Minitest::Test
  include TestSupport

  class FakeRouteContext
    include KiwiCaptcha::Sinatra::Helper

    attr_reader :params, :response_status, :redirected_to

    def initialize(params)
      @params = params
      @redirected_to = nil
    end

    def status(value)
      @response_status = value
    end

    def content_type(value)
      @content_type = value
    end

    def redirect(uri, status = 302)
      @redirected_to = [status, uri]
    end

    def call_hook(&options_block)
      kiwi_verify!(&options_block)
    end
  end

  def options_block
    lambda {
      golden = TestSupport.golden_record('sha_plain')
      record = TestSupport.record_from_row(golden)
      storage = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
      storage.store(record)
      TestSupport.verify_options(
        { storage: storage, secret_key: SECRET }.merge(TestSupport.frozen_clock(record))
      )
    }
  end

  def test_a_valid_token_returns_the_result
    row = TestSupport.golden_record('sha_plain')
    context = FakeRouteContext.new('kiwi__token' => row['token_b64'])
    result = context.call_hook(&options_block)
    refute_nil result
    assert result.ok
  end

  def test_a_missing_token_renders_the_422_body
    context = FakeRouteContext.new({})
    result = context.call_hook(&options_block)
    assert_nil result
    assert_equal 422, context.response_status
  end

  def test_a_failed_token_renders_the_typed_code
    context = FakeRouteContext.new('kiwi__token' => 'garbage')
    result = context.call_hook(&options_block)
    assert_nil result
    assert_equal 422, context.response_status
  end
end
