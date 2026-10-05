# frozen_string_literal: true

# name: kiwi-captcha
# about: KiwiCaptcha sign-up protection: a middleware gates the sign-up
#   endpoints on a kiwi proof-of-work token verified server-to-server
#   against your self-hosted kiwi deployment. No third-party captcha
#   host, no tracking.
# version: 1.0.0
# authors: KiwiCaptcha contributors
# url: https://kiwicaptcha.example

enabled = false
begin
  enabled = SiteSetting.kiwi_captcha_enabled
rescue StandardError
  # During early boot the site settings table may not exist yet; the
  # middleware below checks the setting per request anyway.
end

require_relative "lib/kiwi_captcha/verifier"

# The sign-up gate middleware: one Rack middleware ahead of the app,
# exactly the mechanism official plugins (discourse-prometheus) use.
# It guards the sign-up POSTs (the paths in kiwi_signup_paths) and
# answers 403 with a provider-shaped JSON body when the challenge did
# not pass, 503 when the kiwi deployment is unreachable (fail closed).
class KiwiSignupGate
  def initialize(app)
    @app = app
  end

  def call(env)
    return @app.call(env) unless gate?(env)

    request = Rack::Request.new(env)
    token = KiwiCaptcha::Verifier.extract_token(
      headers: env,
      cookies: request.cookies,
    )
    return denied("missing-input-response") if token.nil?

    result = KiwiCaptcha::Verifier.decide(
      token: token,
      scope: SiteSetting.kiwi_signup_scope,
      settings: gate_settings,
      server: env,
      transport: method(:transport),
    )
    return denied("invalid-input-response") unless result[:ok]
    return unavailable if result[:code] == :unavailable || result[:code] == :unreadable

    @app.call(env)
  end

  private

  def gate?(env)
    return false unless SiteSetting.kiwi_captcha_enabled

    method = env["REQUEST_METHOD"].to_s.upcase
    return false unless method == "POST"

    path = env["PATH_INFO"].to_s
    SiteSetting.kiwi_signup_paths
      .split("|")
      .map(&:strip)
      .reject(&:empty?)
      .any? { |candidate| path == candidate || path == "#{candidate}.json" }
  end

  def gate_settings
    {
      verify_url: SiteSetting.kiwi_verify_url,
      bearer: SiteSetting.kiwi_bearer.to_s,
      trust_proxy: SiteSetting.kiwi_trust_proxy,
    }
  end

  # The Net::HTTP transport: one blocking POST, five second timeout.
  def transport(request)
    uri = URI(request[:url])
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == "https"
    http.open_timeout = 5
    http.read_timeout = 5
    response = http.post(
      uri.request_uri.empty? ? "/" : uri.request_uri,
      request[:body],
      request[:headers],
    )
    { status: response.code.to_i, body: response.body.to_s }
  rescue StandardError
    { status: 0, body: "" }
  end

  def denied(error_code)
    [
      403,
      { "Content-Type" => "application/json" },
      [{ success: false, "error-codes" => [error_code] }.to_json],
    ]
  end

  def unavailable
    [
      503,
      { "Content-Type" => "application/json" },
      [{ success: false, "error-codes" => ["verify-unavailable"] }.to_json],
    ]
  end
end

require "net/http"
require "json"

register_asset "assets/javascripts/kiwi-signup-header.js"

Discourse::Application.config.middleware.insert_before(
  Rack::Runtime,
  KiwiSignupGate,
)
