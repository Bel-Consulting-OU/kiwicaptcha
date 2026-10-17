# frozen_string_literal: true

require 'uri'

module KiwiCaptcha
  # The shared token authority rule of the server SDKs, pinned by
  # protocol/decision-v1/corpus.json.
  #
  # Every non-empty value is collected from all three sources (the
  # x-kiwi-token header, the configured form field, the same-named
  # query parameter), repeated values included. One distinct value
  # verifies, however many sources carry it. Two or more distinct
  # values refuse the request with token_source_conflict before any
  # candidate is verified, so a trusted gateway's header can never be
  # shadowed by an attacker-controlled body field.
  module TokenSource
    module_function

    # Every token value of the merged header line. The token alphabet
    # has no comma, so a comma-joined list is a list of candidates.
    def split_header(value)
      return [] unless value.is_a?(String)

      value.split(',').map(&:strip).reject(&:empty?)
    end

    # The decoded name/value pairs of a urlencoded string, duplicate
    # names preserved in order.
    def form_pairs(encoded)
      return [] unless encoded.is_a?(String) && !encoded.empty?

      encoded.split('&').map do |pair|
        name, value = pair.split('=', 2)
        [decode_component(name.to_s), decode_component(value.to_s)]
      end
    end

    # The non-empty values of one field, repeated values included.
    def values_for(pairs, field)
      pairs.select { |name, _| name == field }.map { |_, value| value }.reject(&:empty?)
    end

    # Resolve the collected source values under the authority rule.
    # Returns [token, nil] for one agreed value, [nil, failure_code]
    # otherwise.
    def resolve_values(header_values:, form_values:, query_values:)
      distinct = []
      [header_values, form_values, query_values].each do |values|
        values.each do |value|
          next unless value.is_a?(String) && !value.empty?
          next if distinct.include?(value)

          distinct << value
          return [nil, 'token_source_conflict'] if distinct.length > 1
        end
      end
      return [nil, 'malformed_token'] if distinct.empty?

      [distinct.first, nil]
    end

    def decode_component(text)
      URI.decode_www_form_component(text)
    rescue ArgumentError
      text
    end
  end
end
