# frozen_string_literal: true

require 'json'

module KiwiCaptcha
  module Rack
    # The Rack middleware: reads the configured token field, verifies
    # the token locally, and answers 422 with a JSON error body on
    # failure (or a redirect when one is configured). A verified
    # request exposes env['kiwi.verify'] for downstream apps, so the
    # decision handle, the price rung and the binding ride along.
    #
    # The middleware never raises: a storage outage is a 422 with the
    # typed storage_unavailable code, fail closed.
    class Verifier
      DEFAULT_TOKEN_FIELD = 'kiwi__token'
      DEFAULT_FAILURE_STATUS = 422

      HeaderToken = Struct.new(:value)

      # Options:
      #   verify:      a per-request options factory. Receives the Rack
      #                 env and returns a VerifyOptions (or a hash of
      #                 its fields with the storage bound by the host).
      #   token_field: the body or query field carrying the token.
      #   failure_status: the JSON failure status (default 422).
      #   failure_redirect: render the failure as a 303 redirect.
      #   trusted_proxies: the trusted-proxy CIDR list. The default
      #                 (option absent) leaves the client-IP choice to
      #                 the host factory; when configured (an empty
      #                 list included) a factory result without an
      #                 explicit client_ip gains the resolved IP: the
      #                 socket peer, or a forwarded entry when a
      #                 trusted hop justifies one. Rack::Request#ip
      #                 carries different forwarding semantics, so the
      #                 resolver in KiwiCaptcha::ClientIp is used
      #                 directly and the framework helper is never
      #                 consulted.
      def initialize(app, verify:, token_field: DEFAULT_TOKEN_FIELD, failure_status: DEFAULT_FAILURE_STATUS, failure_redirect: nil, trusted_proxies: nil)
        @app = app
        @verify = verify
        @token_field = token_field
        @failure_status = failure_status
        @failure_redirect = failure_redirect
        @trusted_proxies = trusted_proxies
      end

      def call(env)
        request = ::Rack::Request.new(env)
        raw_token = read_token(request)
        if raw_token.nil?
          return fail_with(env, 'malformed_token', "the #{@token_field} field is missing")
        end

        options = @verify.call(env)
        options = VerifyOptionsFactory.coerce(options)
        apply_resolved_client_ip(options, request)
        result = KiwiCaptcha.verify(raw_token, options)
        unless result.ok
          return fail_with(env, result.code.empty? ? 'invalid' : result.code, result.detail || 'verification failed')
        end

        env['kiwi.verify'] = result
        @app.call(env)
      end

      private

      def apply_resolved_client_ip(options, request)
        return if @trusted_proxies.nil?
        return unless options.respond_to?(:client_ip=)

        current = options.respond_to?(:client_ip) ? options.client_ip : nil
        return unless current.nil?

        options.client_ip = KiwiCaptcha::ClientIp.resolve(
          peer: peer_text(request),
          xff: env_forwarded_lines(request),
          real_ip: request.get_header('HTTP_X_REAL_IP'),
          trusted_proxies: @trusted_proxies
        )
      end

      # Rack merges repeated header lines into one comma-joined value,
      # so the merged chain is what the resolver walks.
      def env_forwarded_lines(request)
        value = request.get_header('HTTP_X_FORWARDED_FOR')
        value.is_a?(String) && !value.strip.empty? ? [value] : []
      end

      # The socket peer comes straight from the CGI variable:
      # Rack::Request#ip applies its own forwarding model, which must
      # not leak into this boundary.
      def peer_text(request)
        request.get_header('REMOTE_ADDR').to_s
      end

      def read_token(request)
        value = request.params[@token_field]
        return value if value.is_a?(String) && !value.empty?

        header = request.get_header('HTTP_X_KIWI_TOKEN')
        return header if header.is_a?(String) && !header.empty?

        nil
      end

      def fail_with(_env, code, detail)
        return [303, { 'Location' => @failure_redirect }, []] unless @failure_redirect.nil?

        body = JSON.generate('error' => { 'code' => code, 'detail' => detail })
        [@failure_status,
         { 'Content-Type' => 'application/json', 'Content-Length' => body.bytesize.to_s },
         [body]]
      end
    end

    # Coerce a host factory result into VerifyOptions: the host may
    # return a VerifyOptions or a plain hash.
    module VerifyOptionsFactory
      module_function

      def coerce(value)
        return value if value.is_a?(Verify::VerifyOptions)

        Verify::VerifyOptions.new(**value.transform_keys(&:to_sym))
      end
    end
  end
end
