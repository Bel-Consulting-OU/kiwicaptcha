package kiwicaptcha

import (
	"net/netip"
	"strings"
)

// The trusted client-IP resolver: the canonical client IP of a request
// is its socket peer unless the peer sits inside the configured
// trusted-proxy CIDR list. An empty list trusts nobody, so a forwarded
// header never influences the binding. With a trusted peer, the
// X-Forwarded-For chain is walked right to left: entries inside the
// trust list are skipped, the first untrusted entry wins, and an entry
// that fails strict IP parsing terminates the walk and falls back to
// the peer. X-Real-IP is honored only when the peer is trusted and no
// forwarded chain exists. The algorithm ports the Symfony bundle's
// ClientIpResolver trusted-chain walk, so every SDK binds the same
// canonical IP for the same request.

// trustedPrefixes parses the CIDR configuration. Entries that fail to
// parse are skipped, so a typo can never widen the trust boundary.
func trustedPrefixes(cidrs []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes
}

// ipInTrusted reports whether one canonical address sits inside any
// trusted prefix. Host bits set in a prefix are masked away, and an
// IPv4-mapped IPv6 address matches in its IPv4 form.
func ipInTrusted(addr netip.Addr, prefixes []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// canonicalWithinTrust is ipInTrusted over canonical text (the output
// of canonicalIP, always parseable).
func canonicalWithinTrust(canonical string, prefixes []netip.Prefix) bool {
	addr, err := netip.ParseAddr(canonical)
	if err != nil {
		return false
	}
	return ipInTrusted(addr, prefixes)
}

// canonicalIP returns the canonical text of one forwarded node, or an
// empty string when the node is not a genuine address. Handles bare
// IPv4, IPv4 with a port, bracketed IPv6 with an optional port, and
// rejects unknown, obfuscated tokens, malformed ports and any
// spelling the strict parser refuses. IPv4-mapped IPv6 normalizes to
// its IPv4 form.
func canonicalIP(identifier string) string {
	value := strings.TrimSpace(identifier)
	if value == "" || value == "unknown" || strings.HasPrefix(value, "_") {
		return ""
	}
	candidate := value
	if strings.HasPrefix(candidate, "[") {
		closing := strings.Index(candidate, "]")
		if closing < 0 {
			return ""
		}
		if suffix := candidate[closing+1:]; suffix != "" && !isPortSuffix(suffix) {
			return ""
		}
		candidate = candidate[1:closing]
	} else if strings.Count(candidate, ":") == 1 {
		// IPv4 with a port: the port splits only when the left side
		// is a valid IPv4 and the port is a genuine number.
		parts := strings.Split(candidate, ":")
		if len(parts) == 2 && isStrictIPv4(parts[0]) && isPortSuffix(":"+parts[1]) {
			candidate = parts[0]
		}
	}
	if strings.Contains(candidate, ":") && strings.Count(candidate, ":") < 2 {
		parts := strings.Split(candidate, ":")
		if isStrictIPv4(parts[len(parts)-1]) {
			candidate = strings.Join(parts[:len(parts)-1], ":")
		}
	}
	addr, err := netip.ParseAddr(candidate)
	if err != nil || addr.Zone() != "" {
		return ""
	}
	addr = addr.Unmap()
	return addr.String()
}

// isPortSuffix reports whether the text is exactly ":" plus a decimal
// port in the 1..65535 range.
func isPortSuffix(suffix string) bool {
	if len(suffix) < 2 || suffix[0] != ':' {
		return false
	}
	digits := suffix[1:]
	for _, c := range digits {
		if c < '0' || c > '9' {
			return false
		}
	}
	if len(digits) > 5 {
		return false
	}
	port := 0
	for _, c := range digits {
		port = port*10 + int(c-'0')
	}
	return port >= 1 && port <= 65535
}

// isStrictIPv4 reports the dotted-quad grammar only: no decimal
// integer shorthand, no leading zeros.
func isStrictIPv4(text string) bool {
	parts := strings.Split(text, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		if len(part) > 1 && part[0] == '0' {
			return false
		}
		n := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

// hasControlBytes reports whether the header carries a raw control
// byte: such a value is refused whole, never trimmed into an address.
func hasControlBytes(header string) bool {
	for _, r := range header {
		if r < 0x20 || r == 0x7F {
			return true
		}
	}
	return false
}
