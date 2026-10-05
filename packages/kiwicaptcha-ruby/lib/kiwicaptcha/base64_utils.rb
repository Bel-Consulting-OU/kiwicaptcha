# frozen_string_literal: true

module KiwiCaptcha
  # Strict base64 and hex helpers. Ruby's Array#unpack1('m') is lenient:
  # it skips invalid characters and accepts every padding spelling. The
  # wire protocols here require exactly one canonical spelling per
  # value, mirroring the PHP strict decoder plus the re-encode equality
  # check.
  module Base64Utils
    STANDARD_ALPHABET = /\A[A-Za-z0-9+\/]*={0,2}\z/.freeze
    URL_ALPHABET = /\A[A-Za-z0-9_-]*={0,2}\z/.freeze
    UNPADDED_URL_ALPHABET = /\A[A-Za-z0-9_-]+\z/.freeze
    LOWERCASE_HEX = /\A[0-9a-f]*\z/.freeze

    module_function

    def encode_std(bytes)
      [bytes].pack('m0') # standard alphabet, no newlines, padded
    end

    # Decode canonical standard base64. Accepts exactly one spelling:
    # standard alphabet, correct padding, no stray characters. Returns
    # nil for anything else.
    def decode_std(value)
      value = value.to_str
      return nil if value.bytesize % 4 != 0
      return nil unless STANDARD_ALPHABET.match?(value)

      bytes = value.unpack1('m')
      return nil unless value.ascii_only?

      encoded = encode_std(bytes)
      encoded == value ? bytes : nil
    rescue ArgumentError
      nil
    end

    # Encode to unpadded base64url, the driver trace wire format.
    def encode_url(bytes)
      [bytes].pack('m0').tr('+/', '-_').delete('=')
    end

    # Decode canonical unpadded base64url. Returns nil for anything
    # outside the unpadded url-safe alphabet.
    def decode_url(value)
      return nil if value.empty? || value.include?('=')
      return nil unless UNPADDED_URL_ALPHABET.match?(value)

      standard = value.tr('-_', '+/')
      standard += '=' * ((4 - (standard.bytesize % 4)) % 4)
      bytes = standard.unpack1('m')
      encode_url(bytes) == value ? bytes : nil
    rescue ArgumentError
      nil
    end

    def lowercase_hex?(value, length: nil)
      return false unless value.is_a?(String) && LOWERCASE_HEX.match?(value)

      length.nil? || value.length == length
    end
  end
end
