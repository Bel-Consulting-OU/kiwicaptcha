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
        raw_token, failure = kiwi_read_token(token_field)
        unless failure.nil?
          detail = failure == 'token_source_conflict' ?
            'the request carries conflicting token sources' :
            "the #{token_field} field is missing"
          kiwi_render_failure(failure, detail, failure_status, failure_redirect)
          return nil
        end

        options = KiwiCaptcha::Rack::VerifyOptionsFactory.coerce(options_block.call)
        result = KiwiCaptcha.verify(raw_token, options)
        if result.ok
          instance_variable_set(:@kiwi_verify_result, result)
          return result
        end

        if result.disposition == 'retry'
          kiwi_render_failure(
            result.code.empty? ? 'invalid' : result.code,
            result.detail || 'verification failed',
            503,
            nil
          )
          return nil
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
        env = respond_to?(:request) && request.respond_to?(:env) ? request.env : {}
        header_values = KiwiCaptcha::TokenSource.split_header(env['HTTP_X_KIWI_TOKEN'])
        query_values = KiwiCaptcha::TokenSource.values_for(
          KiwiCaptcha::TokenSource.form_pairs(env['QUERY_STRING']), token_field
        )
        form_values = []
        content_type = env['CONTENT_TYPE'].to_s
        if content_type.include?('application/x-www-form-urlencoded')
          body = env['rack.input']
          if body.respond_to?(:read)
            encoded = body.read
            body.rewind if body.respond_to?(:rewind)
            form_values = KiwiCaptcha::TokenSource.values_for(
              KiwiCaptcha::TokenSource.form_pairs(encoded), token_field
            )
          end
        end
        token, failure = KiwiCaptcha::TokenSource.resolve_values(
          header_values: header_values, form_values: form_values, query_values: query_values
        )
        return [token, failure] unless token.nil? && failure == 'malformed_token'

        value = begin
          params[token_field]
        rescue StandardError
          nil
        end
        values = value.is_a?(Array) ? value : [value]
        KiwiCaptcha::TokenSource.resolve_values(
          header_values: header_values,
          form_values: values.compact,
          query_values: []
        )
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
