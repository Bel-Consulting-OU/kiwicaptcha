# frozen_string_literal: true

require 'json'

module KiwiCaptcha
  module Sinatra
    # The Sinatra helper: mix it into an application class (or any
    # route context) for one-call verification. On failure the helper
    # answers the framework-idiomatic 422 JSON body, or performs the
    # redirect when the host configured one; the route body never runs.
    #
    #   helpers KiwiCaptcha::Sinatra::Helper
    #   post '/login' do
    #     kiwi_verify! { VerifyOptions.new(storage: store, secret_key: secret) }
    #     "signed in"
    #   end
    module Helper
      DEFAULT_TOKEN_FIELD = 'kiwi__token'

      def kiwi_verify_result
        instance_variable_get(:@kiwi_verify_result)
      end

      # Verify the request token. Calls into the host context for
      # params, headers and response; pass a block returning the
      # VerifyOptions (or hash). Returns the result on success; on
      # failure it writes the error response and returns nil, so the
      # route body is skipped by an explicit return in the caller.
      def kiwi_verify!(token_field: DEFAULT_TOKEN_FIELD, failure_status: 422, failure_redirect: nil, &options_block)
        raw_token = kiwi_read_token(token_field)
        if raw_token.nil?
          kiwi_render_failure('malformed_token', "the #{token_field} field is missing", failure_status, failure_redirect)
          return nil
        end

        options = KiwiCaptcha::Rack::VerifyOptionsFactory.coerce(options_block.call)
        result = KiwiCaptcha.verify(raw_token, options)
        if result.ok
          instance_variable_set(:@kiwi_verify_result, result)
          return result
        end

        kiwi_render_failure(
          result.code.empty? ? 'invalid' : result.code,
          result.detail || 'verification failed',
          failure_status,
          failure_redirect
        )
        nil
      end

      private

      def kiwi_read_token(token_field)
        value = params[token_field]
        return value if value.is_a?(String) && !value.empty?

        header = if respond_to?(:request) && request.respond_to?(:env)
                   request.env['HTTP_X_KIWI_TOKEN']
                 else
                   nil
                 end
        return header if header.is_a?(String) && !header.empty?

        nil
      rescue StandardError
        nil
      end

      def kiwi_render_failure(code, detail, failure_status, failure_redirect)
        unless failure_redirect.nil?
          redirect failure_redirect, 303 if respond_to?(:redirect)
          return
        end
        body = JSON.generate('error' => { 'code' => code, 'detail' => detail })
        if respond_to?(:content_type)
          content_type 'application/json'
        end
        status failure_status if respond_to?(:status)
        body
      end
    end
  end
end
