# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

module KiwiCaptcha
  # The execution delegation plane of the ruby SDK: an execution-armed
  # record demands the browser-trace walker, an oracle this SDK does
  # not carry. The default policy fails every armed record closed
  # (execution_mismatch, documented). The sidecar policy delegates that
  # single verification to a co-located kiwicaptcha-verifier sidecar
  # over HTTP: the sidecar carries the full Rust core with the real
  # execution verifier, consumes the record (single-use semantics
  # preserved: the sidecar consumes, this SDK never double-consumes)
  # and answers the provider-shaped verdict mapped back into this
  # SDK's vocabulary.
  #
  # Trust boundary: the sidecar decides acceptances, so it must be
  # co-located and trusted to the same standard as the verifier itself.
  # The bearer credential is sent per request, and a refused credential
  # denies instead of retrying into an untrusted verifier.
  class ExecutionPolicy
    # The kiwicaptcha-verifier base URL. Nil keeps the fail-closed
    # default.
    attr_reader :sidecar_url

    # The sidecar's own credential, sent as the Authorization bearer.
    attr_reader :bearer_token

    # The bounded budget of one delegation call in milliseconds.
    attr_reader :timeout_ms

    def initialize(sidecar_url: nil, bearer_token: nil, timeout_ms: 5000)
      @sidecar_url = sidecar_url
      @bearer_token = bearer_token
      @timeout_ms = timeout_ms
    end

    def enabled?
      !@sidecar_url.nil? && !@sidecar_url.strip.empty?
    end

    # Hands one execution-armed verification to the sidecar. Answers
    # [ok, code]: ok means the sidecar's full-core pass accepted; a
    # failure maps the sidecar's kiwi-code (the shared wire vocabulary)
    # through verbatim, with the transport failures fail-closed
    # (storage_unavailable keeps the retry disposition, the record
    # intact).
    def delegate(raw_token, scope, client_ip)
      uri = URI.parse(sidecar_url.strip.sub(%r{/+\z}, '') + '/verify')
      request = Net::HTTP::Post.new(uri)
      request['content-type'] = 'application/json'
      request['authorization'] = "Bearer #{bearer_token}" if bearer_token && !bearer_token.empty?
      request.body = JSON.generate(token: raw_token, scope: scope, remoteip: client_ip)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.instance_of?(URI::HTTPS)
      http.open_timeout = timeout_ms / 1000.0
      http.read_timeout = timeout_ms / 1000.0
      response = begin
        http.request(request)
      rescue StandardError
        return [false, 'storage_unavailable']
      end
      case response.code.to_i
      when 401, 403
        # The sidecar refused the credential: never retry into an
        # untrusted verifier, fail closed with a deny.
        return [false, 'execution_mismatch']
      when 500..599
        return [false, 'storage_unavailable']
      when 200
        payload = begin
          JSON.parse(response.body)
        rescue StandardError
          return [false, 'execution_mismatch']
        end
        return [true, 'ok'] if payload['success'] == true

        [false, payload['kiwi-code'] || 'execution_mismatch']
      else
        [false, 'execution_mismatch']
      end
    end
  end
end
