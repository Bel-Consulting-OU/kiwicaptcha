# frozen_string_literal: true

require 'openssl'

module KiwiCaptcha
  # The canonical signing bytes and the deployment binding tags, shared
  # with the PHP Issuer and the Rust issuer byte for byte.
  #
  # Canonical payload revision 4:
  #
  #   v4|protocol_version|nonce|scope|binding_tag|issued_at|expires_at|
  #     algorithm|m_kib|t|p|target_bits|salt|min_duration_ms|region|
  #     policy_version|request_binding|issuer|kid
  #
  # followed by the tagged extension segments in capability order:
  #
  #   ...|kid|d=decoy_field|e=version,commitment|r=modulus_sha256|m=1
  module Canonical
    POW_ALGORITHMS = %w[sha256 argon2id rsw].freeze

    CanonicalArgs = Struct.new(
      :protocol_version, :nonce, :scope, :binding_tag, :issued_at, :expires_at,
      :algorithm, :m_kib, :t, :p, :target_bits, :salt, :min_duration_ms,
      :region, :policy_version, :request_binding, :issuer, :kid,
      :decoy_field, :execution_version, :execution_commitment,
      :rsw_modulus_sha256, :server_mac_committed,
      keyword_init: true
    )

    module_function

    # Assemble the canonical signing payload. The extension segments
    # append only when armed, so the unarmed base keeps the plain field
    # set. The execution pair and the metadata marker each change the
    # signed bytes, so stripping or splicing any armed field breaks the
    # signature.
    def canonical_payload(args)
      base = "v4|#{args.protocol_version}|#{args.nonce}|#{args.scope}|#{args.binding_tag}|" \
             "#{args.issued_at}|#{args.expires_at}|#{args.algorithm}|#{args.m_kib}|#{args.t}|" \
             "#{args.p}|#{args.target_bits}|#{args.salt}|#{args.min_duration_ms}|#{args.region || ''}|" \
             "#{args.policy_version || 1}|#{args.request_binding || ''}|#{args.issuer || ''}|#{args.kid || 1}"
      out = base.dup
      if args.decoy_field
        out << "|d=#{args.decoy_field}"
      end
      has_version = !args.execution_version.nil?
      has_commitment = !args.execution_commitment.nil?
      if has_version || has_commitment
        raise TypeError, 'execution_version and execution_commitment must be passed together' unless has_version && has_commitment

        out << "|e=#{args.execution_version},#{args.execution_commitment}"
      end
      out << "|r=#{args.rsw_modulus_sha256}" if args.rsw_modulus_sha256
      out << '|m=1' if args.server_mac_committed
      out
    end

    # True when the challenge's signed canonical carries the record
    # metadata MAC marker (m=1). The marker is parsed from the embedded
    # canonical, never inferred from the stored MAC presence.
    def signed_canonical_commits_record_meta(challenge)
      pos = challenge.rindex('.')
      return false if pos.nil?

      encoded = challenge[0...pos]
      canonical = Base64Utils.decode_std(encoded)
      return false if canonical.nil?

      text = canonical.force_encoding('ASCII-8BIT')
      text.start_with?('v4|') && text.end_with?('|m=1')
    end

    # The authenticated execution commitment of a stored program: the
    # hex SHA-256 of the program's base64 wire string.
    def execution_commitment(execution_program)
      Digest::SHA256.hexdigest(execution_program.b)
    end

    # Legacy v1 IP hash: the hex SHA-256 of salt followed by the raw IP
    # string. Kept for v1 records inside the migration window.
    def hash_ip(ip, salt)
      Digest::SHA256.hexdigest("#{salt}#{ip}".b)
    end

    # The v1 signature: hex HMAC over the v1 payload keyed by the
    # master secret directly. Migration window compatibility only.
    def sign_payload_v1(canonical, secret_key)
      OpenSSL::HMAC.hexdigest('sha256', secret_key.to_s.b, canonical.b)
    end

    # The v2+ signature: hex HMAC over the canonical payload keyed by
    # the HKDF derived challenge-signing purpose key (tenant scoped
    # when a tenant id is configured).
    def sign_payload_v2(canonical, secret_key, tenant_id = nil)
      OpenSSL::HMAC.hexdigest('sha256', Keys.derived_keys(secret_key, tenant_id).challenge_key, canonical.b)
    end

    V4_STRICT = /\A(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\z/.freeze
    IPV6_GROUP = /\A[0-9A-Fa-f]{1,4}\z/.freeze

    def parse_ipv4(ip)
      match = V4_STRICT.match(ip)
      return nil if match.nil?

      octets = []
      match.captures.each do |part|
        return nil if part.length > 1 && part.start_with?('0')

        value = Integer(part, 10)
        return nil if value > 255

        octets << value
      rescue ArgumentError
        return nil
      end
      octets.pack('C4')
    end

    def parse_ipv6(ip)
      return nil if ip.include?('%')

      lower = ip.downcase
      double_colon = lower.index('::')
      if double_colon
        return nil if lower.index('::', double_colon + 1)

        head = double_colon.zero? ? [] : lower[0...double_colon].split(':')
        rest = lower[(double_colon + 2)..]
        tail = rest.empty? ? [] : rest.split(':')
      else
        head = lower.split(':')
        tail = []
      end
      tail_has_v4 = !tail.empty? && tail.last.include?('.')
      v4_bytes = nil
      if tail_has_v4
        v4_bytes = parse_ipv4(tail.last)
        return nil if v4_bytes.nil?

        tail = tail[0...-1]
      end
      (head + tail).each do |group|
        return nil if group.include?('.') || !IPV6_GROUP.match?(group)
      end
      explicit = head.length + tail.length + (tail_has_v4 ? 2 : 0)
      if double_colon
        return nil if explicit >= 8
      elsif explicit != 8
        return nil
      end
      bytes = ([0] * 16).pack('C*')
      at = 0
      write_group = lambda do |group|
        value = group.to_i(16)
        bytes.setbyte(at, (value >> 8) & 0xff)
        bytes.setbyte(at + 1, value & 0xff)
        at += 2
      end
      head.each(&write_group)
      at += (8 - explicit) * 2 if double_colon
      tail.each(&write_group)
      if v4_bytes
        4.times { |i| bytes.setbyte(12 + i, v4_bytes.getbyte(i)) }
      end
      bytes
    end

    # Canonical family byte plus packed address bytes: the inet_pton
    # output (4 or 16 bytes) with IPv4-mapped and IPv4-compatible IPv6
    # spellings normalized to the 4-byte IPv4 form. Two textual
    # spellings of one address therefore produce the same bytes.
    # Returns nil for any input outside the strict grammar.
    def canonical_ip_family(ip)
      return nil if ip.empty?

      if ip.include?(':')
        v6 = parse_ipv6(ip)
        return nil if v6.nil?

        prefix = v6[0, 12]
        low = v6[12, 4]
        zeros12 = ([0] * 12).pack('C*')
        mapped = prefix == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff].pack('C*')
        compatible = prefix == zeros12 && low != ([0] * 4).pack('C*') && low != [0, 0, 0, 1].pack('C*')
        return mapped || compatible ? [4].pack('C') + low : [6].pack('C') + v6
      end

      v4 = parse_ipv4(ip)
      return nil if v4.nil?

      [4].pack('C') + v4
    end

    IP_BIND_DOMAIN = "kiwicaptcha/ip-bind/v2\x00".b

    # The nonce-bound IP binding tag of a v2+ record: hex HMAC over the
    # domain string, the nonce and the canonical family bytes, keyed by
    # the IP-binding purpose key. Raises RangeError for an IP outside
    # the strict grammar, exactly like the PHP issuer.
    def binding_tag(nonce, ip, secret, tenant_id = nil)
      family = canonical_ip_family(ip)
      raise RangeError, "invalid IP address: #{ip}" if family.nil?

      message = IP_BIND_DOMAIN + nonce.b + [0].pack('C') + family
      OpenSSL::HMAC.hexdigest('sha256', Keys.derived_keys(secret, tenant_id).ip_bind_key, message)
    end
  end
end
