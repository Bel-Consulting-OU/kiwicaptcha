# frozen_string_literal: true

# The plain-ruby test of the signup gate's disposition mapping: a
# transport outage must answer 503 (retry), never a definitive 403, and
# a failed challenge must answer 403. Run:
#   ruby tests/middleware_disposition_test.rb

require "json"
require "rack"

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

puts "middleware_disposition_test: #{$checks - $failures}/#{$checks} passed"
exit($failures.zero? ? 0 : 1)
