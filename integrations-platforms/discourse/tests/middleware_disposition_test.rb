# frozen_string_literal: true

# The plain-ruby test of the signup gate's disposition mapping: a
# transport outage must answer 503 (retry), never a definitive 403, and
# a failed challenge must answer 403. Run:
#   ruby tests/middleware_disposition_test.rb

require "json"

begin
  require "rack"
rescue LoadError
  # The test only uses Rack::Request#cookies and the Rack::Runtime
  # constant; the fallback keeps this a plain-ruby test on a box
  # without the gem.
  module Rack
    class Runtime; end

    class Request
      def initialize(env)
        @env = env
      end

      def cookies
        (@env["HTTP_COOKIE"] || "").split(/;\s*/).each_with_object({}) do |pair, out|
          name, value = pair.split("=", 2)
          out[name] = value if name && value
        end
      end
    end
  end
end

$failures = 0
$checks = 0

def check(name, condition)
  $checks += 1
  return if condition

  $failures += 1
  warn "FAIL: #{name}"
end

# Minimal SiteSetting double so plugin.rb can load outside Discourse.
module SiteSetting
  class << self
    attr_accessor :kiwi_captcha_enabled, :kiwi_signup_scope, :kiwi_signup_paths,
                  :kiwi_verify_url, :kiwi_bearer, :kiwi_trusted_proxies
  end
  self.kiwi_captcha_enabled = true
  self.kiwi_signup_scope = "signup"
  self.kiwi_signup_paths = "/u"
  self.kiwi_verify_url = "http://127.0.0.1:1/verify" # never dialed: transport is stubbed
  self.kiwi_bearer = ""
  self.kiwi_trusted_proxies = ""
end

module Discourse
  module Application
    def self.config
      @config ||= Class.new do
        def middleware
          @middleware ||= Class.new do
            def self.insert_before(*); end
          end
        end
      end.new
    end
  end
end

def register_asset(*); end

require_relative "../plugin"

APP_OK = ->(_env) { [200, { "Content-Type" => "text/plain" }, ["app"]] }

def request_env
  {
    "REQUEST_METHOD" => "POST",
    "PATH_INFO" => "/u",
    "HTTP_X_KIWI_TOKEN" => "tok",
    "REMOTE_ADDR" => "203.0.113.9",
  }
end

def run_gate(transport)
  gate = KiwiSignupGate.new(APP_OK)
  gate.define_singleton_method(:transport) { |request| transport.call(request) }
  gate.call(request_env)
end

# run_gate with request overrides: the token-ambiguity cases post
# different header/cookie shapes than the default request.
def run_gate_conflict(env_overrides)
  gate = KiwiSignupGate.new(APP_OK)
  gate.define_singleton_method(:transport) { |_request| { status: 200, body: '{"success":true}' } }
  gate.call(request_env.merge(env_overrides.compact))
end

# A failed challenge is a definitive 403.
status, _headers, body = run_gate(->(_r) { { status: 200, body: '{"success":false}' } })
check("failed challenge denies 403", status == 403)
check("failed challenge body", body.first.include?("invalid-input-response"))

# A transport outage is the retry disposition (503), never a 403 deny:
# the client must be told to retry later, not to re-solve.
status, _headers, body = run_gate(->(_r) { { status: 0, body: "" } })
check("transport outage answers 503", status == 503)
check("transport outage body", body.first.include?("verify-unavailable"))

# A 5xx upstream is also the retry disposition.
status, = run_gate(->(_r) { { status: 502, body: "" } })
check("upstream 5xx answers 503", status == 503)

# A successful verdict passes to the app.
status, = run_gate(->(_r) { { status: 200, body: '{"success":true}' } })
check("verified passes to the app", status == 200)

# The token authority rule: a request carrying two distinct token
# values refuses with the typed code before any verification.
status, _headers, body = run_gate_conflict(
  "HTTP_X_KIWI_TOKEN" => "tok\nother",
  "HTTP_COOKIE" => nil,
)
check("repeated header lines conflict answers 403", status == 403)
check("repeated header lines conflict body", body.first.include?("token_source_conflict"))

status, _headers, body = run_gate_conflict(
  "HTTP_X_KIWI_TOKEN" => "tok",
  "HTTP_COOKIE" => "kiwi_token=other",
)
check("header vs cookie conflict answers 403", status == 403)
check("header vs cookie conflict body", body.first.include?("token_source_conflict"))

# The same value carried by both sources is one distinct value and
# verifies through to the app.
status, = run_gate_conflict(
  "HTTP_X_KIWI_TOKEN" => "tok",
  "HTTP_COOKIE" => "kiwi_token=tok",
)
check("same token in header and cookie passes to the app", status == 200)

puts "middleware_disposition_test: #{$checks - $failures}/#{$checks} passed"
exit($failures.zero? ? 0 : 1)
