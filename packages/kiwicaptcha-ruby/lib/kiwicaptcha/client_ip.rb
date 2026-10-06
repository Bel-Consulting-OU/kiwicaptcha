# frozen_string_literal: true

require 'ipaddr'

module KiwiCaptcha
  # The trusted client-IP resolver: the canonical client IP of a
  # request is its socket peer unless the peer sits inside the
  # configured trusted-proxy CIDR list. An empty list trusts nobody,
  # so a client supplied forwarding header can never move the IP
  # binding. With a trusted peer, the X-Forwarded-For chain is walked
  # right to left: entries inside the trust list are skipped, the
  # first untrusted entry wins, and an entry that fails strict IP
  # parsing terminates the walk and falls back to the peer. X-Real-IP
  # is honored only when the peer is trusted and no forwarded chain
  # exists. The algorithm ports the Symfony bundle's ClientIpResolver
  # trusted-chain walk, so every SDK binds the same canonical IP for
  # the same request. Rack::Request#ip implements a different
  # forwarding model, so the resolver is implemented here explicitly
  # and never delegated to Rack.
  module ClientIp
    CONTROL_BYTES = /[\u0000-\u001F\u007F]/.freeze

    module_function

    # The canonical client IP per the shared trusted-proxy contract.
    # peer is the socket peer text, xff the merged X-Forwarded-For
    # value (or an array of header lines), real_ip the X-Real-IP
    # value, and trusted_proxies the trusted CIDR list.
    def resolve(peer:, xff: nil, real_ip: nil, trusted_proxies: [])
      peer_text = peer.to_s.strip
      trusted = Array(trusted_proxies).map { |c| c.to_s.strip }.reject(&:empty?)
      return peer_text if trusted.empty?

      xff_lines = xff.is_a?(Array) ? xff : (xff.nil? ? [] : [xff])
      visible = xff_lines.reject { |line| !line.is_a?(String) || line.strip.empty? }
      # A repeated forwarding header is parser ambiguity: one
      # intermediary reads the first line, another the last, so the
      # peer wins.
      return peer_text if visible.length > 1

      header = visible.first.to_s.strip
      if header.empty?
        return peer_text unless peer_trusted?(peer_text, trusted)

        candidate = real_ip.to_s.strip
        return peer_text if candidate.empty? || candidate.match?(CONTROL_BYTES)

        canonical = canonical_ip(candidate)
        return canonical || peer_text
      end

      return peer_text if header.match?(CONTROL_BYTES)
      return peer_text unless peer_trusted?(peer_text, trusted)

      header.split(',').reverse_each do |hop|
        canonical = canonical_ip(hop)
        # An unparsable hop terminates the trust chain: who lies
        # beyond it cannot be established, so the peer falls back.
        return peer_text if canonical.nil?
        return canonical unless in_trusted?(canonical, trusted)
      end
      peer_text
    end

    # The canonical text of one forwarded node, or nil when the node
    # is not a genuine address. Handles bare IPv4, IPv4 with a port,
    # bracketed IPv6 with an optional port, rejects unknown and
    # obfuscated tokens, and normalizes IPv4-mapped IPv6 to its IPv4
    # form.
    def canonical_ip(identifier)
      value = identifier.to_s.strip
      return nil if value.empty? || value == 'unknown' || value.start_with?('_')

      candidate = value
      if candidate.start_with?('[')
        closing = candidate.index(']')
        return nil if closing.nil?

        suffix = candidate[(closing + 1)..]
        return nil if !suffix.nil? && !suffix.empty? && !valid_port_suffix?(suffix)

        candidate = candidate[1...closing]
      elsif candidate.count(':') == 1
        # IPv4 with a port: the port splits only when the left side
        # is a valid IPv4 and the port is a genuine number.
        left, right = candidate.split(':')
        if strict_ipv4?(left) && valid_port_suffix?(":#{right}")
          candidate = left
        end
      end
      if candidate.include?(':') && candidate.count(':') < 2
        parts = candidate.split(':')
        candidate = parts[0...-1].join(':') if strict_ipv4?(parts.last)
      end
      # The dotted-quad gate keeps the parser from accepting the
      # decimal-integer and leading-zero spellings IPAddr tolerates.
      return nil if !candidate.include?(':') && !strict_ipv4?(candidate)

      parsed = parse_ip(candidate)
      return nil if parsed.nil?

      parsed = parsed.native if parsed.ipv6? && parsed.ipv4_mapped?
      parsed.to_s
    end

    # Whether one IP text sits inside any trusted CIDR. Host bits set
    # in a CIDR are masked away, and an IPv4-mapped IPv6 address
    # matches in its IPv4 form.
    def in_trusted?(ip_text, trusted)
      parsed = parse_ip(ip_text.to_s)
      return false if parsed.nil?

      parsed = parsed.native if parsed.ipv6? && parsed.ipv4_mapped?
      trusted.any? do |cidr|
        network = parse_cidr(cidr)
        next false if network.nil?

        network = network.native if network.ipv6? && network.ipv4_mapped?
        next false unless network.ipv4? == parsed.ipv4?

        network.include?(parsed)
      end
    end

    def peer_trusted?(peer_text, trusted)
      in_trusted?(peer_text.sub(/\A\[/, '').sub(/\]\z/, ''), trusted)
    end

    def parse_ip(text)
      IPAddr.new(text.to_s)
    rescue IPAddr::Error
      nil
    end

    # The CIDR parse masks the host bits away, so "10.0.0.1/24"
    # behaves as the 10.0.0.0/24 network.
    def parse_cidr(cidr)
      IPAddr.new(cidr.to_s)
    rescue IPAddr::Error
      nil
    end

    def strict_ipv4?(text)
      return false if text.nil?

      parts = text.split('.', -1)
      return false unless parts.length == 4

      parts.all? do |part|
        part.match?(/\A\d{1,3}\z/) && part.length <= 3 &&
          !(part.length > 1 && part.start_with?('0')) && part.to_i <= 255
      end
    end

    def valid_port_suffix?(suffix)
      return false if suffix.nil? || !suffix.start_with?(':')

      digits = suffix[1..]
      !digits.nil? && digits.match?(/\A\d{1,5}\z/) && digits.to_i.between?(1, 65_535)
    end
  end
end
