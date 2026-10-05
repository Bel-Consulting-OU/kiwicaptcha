# frozen_string_literal: true

require 'json'

module KiwiCaptcha
  module Rails
    # The controller concern: one before_action style hook plus the
    # result accessor. Include it in an ApplicationController and wrap
    # the actions that need a verified human, mirroring the drop-in
    # model: the middleware verifies on submit and the integrator
    # writes nothing.
    #
    # The concern is framework pure: it depends on no Rails constant,
    # so it loads in any controller object that answers params and
    # response, and tests can drive it with plain doubles.
    module ControllerConcern
      DEFAULT_TOKEN_FIELD = 'kiwi__token'

      def self.included(base)
        base.extend(ClassMethods)
      end

      # The verification result of the current request, set by
      # kiwi_verify!.
      def kiwi_verify_result
        instance_variable_get(:@kiwi_verify_result)
      end

      def kiwi_verify_failed?
        !kiwi_verify_result.nil? && !kiwi_verify_result.ok
      end

      module ClassMethods
        attr_reader :kiwi_options

        # Declare the verification hook. The block returns the
        # VerifyOptions (or hash) for the request; failure renders a
        # 422 JSON body unless a failure view is configured.
        def kiwi_verify(token_field: DEFAULT_TOKEN_FIELD, failure_status: 422, &options_block)
          @kiwi_options = {
            token_field: token_field,
            failure_status: failure_status,
            options_block: options_block
          }
        end

        def kiwi_verify_options
          @kiwi_options || {}
        end
      end

      # The hook body. Returns the verification result on success; on
      # failure it renders the typed JSON error and records the denied
      # result, so kiwi_verify_failed? answers true downstream.
      def kiwi_verify!
        options = self.class.kiwi_verify_options
        token_field = options.fetch(:token_field, DEFAULT_TOKEN_FIELD)
        raw_token = kiwi_request_token(token_field)
        if raw_token.nil?
          return kiwi_fail('malformed_token', "the #{token_field} field is missing", options)
        end

        verify_options = KiwiCaptcha::Rack::VerifyOptionsFactory.coerce(options.fetch(:options_block).call)
        result = KiwiCaptcha.verify(raw_token, verify_options)
        return result if instance_variable_set(:@kiwi_verify_result, result).ok

        kiwi_fail(result.code.empty? ? 'invalid' : result.code, result.detail || 'verification failed', options, result)
        result
      end

      private

      def kiwi_fail(code, detail, options, result = nil)
        body = kiwi_render_failure(code, detail, options)
        instance_variable_set(:@kiwi_verify_result, result || KiwiCaptcha::Verify::VerifyResult.new(
          ok: false, disposition: 'deny', decision_handle: nil, price: nil,
          code: code, detail: detail, request_binding: nil,
          from_stored_result: false, solve_duration_ms: nil, decoy_field: nil
        ))
        body
      end

      def kiwi_request_token(token_field)
        value = kiwi_param(token_field)
        return value if value.is_a?(String) && !value.empty?

        header = respond_to?(:request) ? request.headers['X-Kiwi-Token'] : nil
        return header if header.is_a?(String) && !header.empty?

        nil
      end

      def kiwi_param(name)
        params[name]
      rescue StandardError
        nil
      end

      def kiwi_render_failure(code, detail, options)
        status = options.fetch(:failure_status, 422)
        body = JSON.generate('error' => { 'code' => code, 'detail' => detail })
        if response.respond_to?(:status=)
          response.status = status
          response.headers['Content-Type'] = 'application/json'
          response.body = body
        end
        body
      end
    end

    # The form helper: the Rails equivalent of the Django field idea.
    # A form declares its scope; the helper renders the hidden widget
    # inputs the driver script fills, so the markup keeps working
    # unchanged while the challenge lifecycle runs.
    module FormHelper
      DEFAULT_SCRIPT_PATH = '/kiwi.js'

      # The hidden token input plus the driver script tag, carrying the
      # scope on the input itself so one helper call is the whole Tier A
      # drop-in: the driver script reads the scope, solves the
      # challenge and fills the token before submit.
      def kiwi_form_field(scope, token_field: ControllerConcern::DEFAULT_TOKEN_FIELD, script: DEFAULT_SCRIPT_PATH)
        safe_scope = scope.to_s.gsub(/[^A-Za-z0-9._:-]/, '')
        safe_field = token_field.to_s.gsub(/[^A-Za-z0-9_-]/, '')
        safe_script = script.to_s.gsub(/"/, '')
        <<~HTML
          <script src="#{safe_script}" defer></script>
          <input type="hidden" name="#{safe_field}" data-kiwi="#{safe_scope}">
        HTML
      end

      # The opening form tag fragment: the scope declaration the
      # middleware and driver agree on.
      def kiwi_form_attributes(scope)
        safe_scope = scope.to_s.gsub(/[^A-Za-z0-9._:-]/, '')
        "data-kiwi=\"#{safe_scope}\""
      end
    end
  end
end
