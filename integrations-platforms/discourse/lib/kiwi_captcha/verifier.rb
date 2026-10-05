# frozen_string_literal: true

module KiwiCaptcha
  # The framework-free kiwi verify client: one module, one call, the
  # provider siteverify answer. The transport is an injected callable,
  # so the whole module unit-tests with plain ruby.
  module Verifier
    # The request for the transport: the sidecar json contract
    # (token/scope/remoteip with the bearer header).
    #
    # Returns { url:, headers:, body: }.
    def self.build_request(verify_url:, token:, scope:, ip:, bearer: "")
      {
        url: verify_url,
        headers: {
          "Content-Type" => "application/json",
          "Authorization" => bearer.to_s.empty? ? nil : "Bearer #{bearer}",
        }.compact,
        body: { token: token, scope: scope, remoteip: ip }.to_json,
      }
    end

    # The decision table over a transport answer { status:, body: }.
    # A transport failure, a 5xx or a 401/404 is a gate fault
    # (:unavailable); everything else answers the challenge verdict.
    #
    # Returns { ok:, code: } with code in verified / challenge_failed /
    # unavailable / unreadable.
    def self.decide(token:, scope:, settings:, server:, transport:)
      ip = client_ip(server, settings[:trust_proxy])
      request = build_request(
        verify_url: settings[:verify_url],
        token: token,
        scope: scope,
        ip: ip,
        bearer: settings[:bearer],
      )
      answer = transport.call(request)
      status = answer[:status].to_i
      return { ok: false, code: :unavailable } if status.zero? || status >= 500 || status == 401 || status == 404

      parsed = begin
        JSON.parse(answer[:body].to_s)
      rescue JSON::ParserError
        nil
      end
      return { ok: false, code: :unreadable } unless parsed.is_a?(Hash)

      return { ok: true, code: :verified } if parsed["success"] == true

      { ok: false, code: :challenge_failed }
    end

    # The first present token: header, then the kiwi_token cookie.
    # returns nil when the request carries none.
    def self.extract_token(headers:, cookies:)
      header = headers["HTTP_X_KIWI_TOKEN"] || headers["X-Kiwi-Token"]
      return header.strip if header.is_a?(String) && !header.strip.empty?

      cookie = cookies["kiwi_token"]
      return cookie.strip if cookie.is_a?(String) && !cookie.strip.empty?

      nil
    end

    # The client ip bound into the verify call.
    def self.client_ip(server, trust_proxy)
      if trust_proxy
        forwarded = server["HTTP_X_FORWARDED_FOR"] || server["X-Forwarded-For"]
        if forwarded.is_a?(String) && !forwarded.empty?
          first = forwarded.split(",").first.to_s.strip
          return first unless first.empty?
        end
      end
      server["REMOTE_ADDR"] || "127.0.0.1"
    end
  end
end
