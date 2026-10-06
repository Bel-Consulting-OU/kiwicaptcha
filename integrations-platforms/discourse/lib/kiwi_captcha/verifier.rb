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
      ip = client_ip(server, settings[:trusted_proxies])
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

    # The client ip bound into the verify call, resolved through the
    # shared trusted-proxy walk: the socket peer wins unless the peer
    # sits inside the trusted proxy CIDR list (the default empty list
    # trusts nobody, so a forged X-Forwarded-For never moves the
    # binding). The chain is walked right to left through the trusted
    # hops and X-Real-IP is honored when no chain exists. Rack's own
    # forwarding model carries different semantics, so the resolver is
    # implemented here explicitly.
    def self.client_ip(server, trusted_proxies = nil)
      cidrs = Array(trusted_proxies).map { |c| c.to_s.strip }.reject(&:empty?)
      peer = server["REMOTE_ADDR"] || "127.0.0.1"
      return peer if cidrs.empty?

      peer_canonical = canonical_ip(peer)
      peer_trusted = !peer_canonical.nil? && in_trusted?(peer_canonical, cidrs)
      forwarded = (server["HTTP_X_FORWARDED_FOR"] || server["X-Forwarded-For"]).to_s.strip
      if forwarded.empty?
        return peer unless peer_trusted

        real_ip = server["HTTP_X_REAL_IP"].to_s.strip
        return peer if real_ip.empty? || real_ip.match?(/[\u0000-\u001F\u007F]/)

        canonical = canonical_ip(real_ip)
        return canonical || peer
      end
      return peer if forwarded.match?(/[\u0000-\u001F\u007F]/) || !peer_trusted

      forwarded.split(",").reverse_each do |hop|
        canonical = canonical_ip(hop)
        # An unparsable hop terminates the trust chain: who lies
        # beyond it cannot be established, so the peer falls back.
        return peer if canonical.nil?
        return canonical unless in_trusted?(canonical, cidrs)
      end
      peer
    end

    # The canonical text of one forwarded node, or nil when the node
    # is not a genuine address: bare IPv4, IPv4 with a port, bracketed
    # IPv6 with an optional port; unknown, obfuscated tokens and
    # malformed ports refuse; IPv4-mapped IPv6 normalizes to IPv4.
    def self.canonical_ip(identifier)
      value = identifier.to_s.strip
      return nil if value.empty? || value == "unknown" || value.start_with?("_")

      candidate = value
      if candidate.start_with?("[")
        closing = candidate.index("]")
        return nil if closing.nil?

        suffix = candidate[(closing + 1)..]
        return nil if !suffix.nil? && !suffix.empty? && !valid_port_suffix?(suffix)

        candidate = candidate[1...closing]
      elsif candidate.count(":") == 1
        left, right = candidate.split(":")
        candidate = left if strict_ipv4?(left) && valid_port_suffix?(":#{right}")
      end
      if candidate.include?(":") && candidate.count(":") < 2
        parts = candidate.split(":")
        candidate = parts[0...-1].join(":") if strict_ipv4?(parts.last)
      end
      parsed = parse_ip(candidate)
      return nil if parsed.nil?

      parsed = parsed.native if parsed.ipv6? && parsed.ipv4_mapped?
      parsed.to_s
    end

    # Whether one IP text sits inside any trusted CIDR. Host bits set
    # in a CIDR are masked away, and an IPv4-mapped IPv6 address
    # matches in its IPv4 form.
    def self.in_trusted?(ip_text, cidrs)
      parsed = parse_ip(ip_text.to_s)
      return false if parsed.nil?

      parsed = parsed.native if parsed.ipv6? && parsed.ipv4_mapped?
      cidrs.any? do |cidr|
        network = parse_ip(cidr)
        next false if network.nil?

        network = network.native if network.ipv6? && network.ipv4_mapped?
        next false unless network.ipv4? == parsed.ipv4?

        network.include?(parsed)
      end
    end

    def self.parse_ip(text)
      require "ipaddr"
      IPAddr.new(text.to_s)
    rescue IPAddr::Error
      nil
    end

    def self.strict_ipv4?(text)
      return false if text.nil?

      parts = text.split(".", -1)
      return false unless parts.length == 4

      parts.all? do |part|
        part.match?(/\A\d{1,3}\z/) && part.length <= 3 &&
          !(part.length > 1 && part.start_with?("0")) && part.to_i <= 255
      end
    end

    def self.valid_port_suffix?(suffix)
      return false if suffix.nil? || !suffix.start_with?(":")

      digits = suffix[1..]
      !digits.nil? && digits.match?(/\A\d{1,5}\z/) && digits.to_i.between?(1, 65_535)
    end
  end
end
