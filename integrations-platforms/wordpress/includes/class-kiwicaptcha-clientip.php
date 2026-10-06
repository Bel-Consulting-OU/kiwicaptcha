<?php
/**
 * The trusted client-IP resolver shared by the WordPress plugin.
 *
 * The canonical client IP of a request is its socket peer unless the
 * peer sits inside the configured trusted-proxy CIDR list. An empty
 * list trusts nobody, so a client supplied forwarding header can never
 * move the IP binding. With a trusted peer, the X-Forwarded-For chain
 * is walked right to left: entries inside the trust list are skipped,
 * the first untrusted entry wins, and an entry that fails strict IP
 * parsing terminates the walk and falls back to the peer. X-Real-IP is
 * honored only when the peer is trusted and no forwarded chain exists.
 * The algorithm ports the Symfony bundle's ClientIpResolver
 * trusted-chain walk, so every SDK binds the same canonical IP for the
 * same request.
 *
 * @package kiwicaptcha
 */

if (!defined('KIWI_CAPTCHA_CLIENT_IP')) {
    define('KIWI_CAPTCHA_CLIENT_IP', '1');

    /**
     * The trusted CIDR list from a comma-separated string: empty
     * entries dropped; one entry that fails to parse can never widen
     * the boundary.
     *
     * @param string $csv the raw comma-separated CIDR text
     * @return list<string>
     */
    function kiwi_captcha_parse_cidrs($csv)
    {
        $cidrs = [];
        foreach (explode(',', (string) $csv) as $candidate) {
            $candidate = trim((string) $candidate);
            if ($candidate !== '') {
                $cidrs[] = $candidate;
            }
        }

        return $cidrs;
    }

    /**
     * The canonical client IP per the shared trusted-proxy contract.
     *
     * @param string|null $peer           the socket peer text
     * @param string|null $forwardedFor   the merged X-Forwarded-For value
     * @param string|null $realIp         the X-Real-IP value
     * @param array<int, string> $trusted the trusted CIDR list
     * @return string the canonical client IP
     */
    function kiwi_captcha_client_ip($peer, $forwardedFor, $realIp, array $trusted)
    {
        $peer = trim((string) $peer);
        if ($trusted === []) {
            return $peer;
        }
        $peerCanonical = kiwi_captcha_canonical_ip($peer);
        $peerTrusted = $peerCanonical !== null && kiwi_captcha_in_trusted($peerCanonical, $trusted);
        $forwarded = is_string($forwardedFor) ? trim($forwardedFor) : '';
        if ($forwarded === '') {
            if (!$peerTrusted) {
                return $peer;
            }
            $realIp = is_string($realIp) ? trim($realIp) : '';
            if ($realIp === '' || preg_match('/[\x00-\x1F\x7F]/', $realIp) === 1) {
                return $peer;
            }
            $canonical = kiwi_captcha_canonical_ip($realIp);

            return $canonical === null ? $peer : $canonical;
        }
        if (preg_match('/[\x00-\x1F\x7F]/', $forwarded) === 1 || !$peerTrusted) {
            return $peer;
        }
        $hops = array_reverse(array_map('trim', explode(',', $forwarded)));
        foreach ($hops as $hop) {
            $canonical = kiwi_captcha_canonical_ip($hop);
            if ($canonical === null) {
                // An unparsable hop terminates the trust chain: who
                // lies beyond it cannot be established, so the peer
                // falls back.
                return $peer;
            }
            if (!kiwi_captcha_in_trusted($canonical, $trusted)) {
                return $canonical;
            }
        }

        return $peer;
    }

    /**
     * The canonical IP text of one forwarded node, or null when it is
     * not a genuine address. Handles bare IPv4, IPv4 with a port,
     * bracketed IPv6 with an optional port; rejects unknown,
     * obfuscated tokens and malformed ports; normalizes IPv4-mapped
     * IPv6 to its IPv4 form.
     *
     * @param string|null $identifier the raw node text
     * @return string|null the canonical text, or null
     */
    function kiwi_captcha_canonical_ip($identifier)
    {
        $value = trim((string) $identifier);
        if ($value === '' || $value === 'unknown' || str_starts_with($value, '_')) {
            return null;
        }
        $candidate = $value;
        if (str_starts_with($candidate, '[')) {
            $closing = strpos($candidate, ']');
            if ($closing === false) {
                return null;
            }
            $suffix = substr($candidate, $closing + 1);
            if ($suffix !== '' && !kiwi_captcha_port_suffix($suffix)) {
                return null;
            }
            $candidate = substr($candidate, 1, $closing - 1);
        } elseif (substr_count($candidate, ':') === 1) {
            $parts = explode(':', $candidate);
            if (count($parts) === 2
                && filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
                && kiwi_captcha_port_suffix(':'.$parts[1])) {
                $candidate = $parts[0];
            }
        }
        if (str_contains($candidate, ':') && substr_count($candidate, ':') < 2) {
            $parts = explode(':', $candidate);
            $last = array_pop($parts);
            if (filter_var($last, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $candidate = implode(':', $parts);
            }
        }
        if (filter_var($candidate, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        $packed = @inet_pton($candidate);
        if ($packed === false) {
            return null;
        }
        if (strlen($packed) === 16 && substr($packed, 0, 12) === "\0\0\0\0\0\0\0\0\0\0\xff\xff") {
            // IPv4-mapped IPv6 normalizes to its IPv4 form.
            return (string) inet_ntop(substr($packed, 12));
        }

        return (string) inet_ntop($packed);
    }

    /**
     * Exactly ":" plus a decimal port in the 1..65535 range.
     *
     * @param string $suffix the suffix text after the address
     */
    function kiwi_captcha_port_suffix($suffix)
    {
        if (!str_starts_with((string) $suffix, ':')) {
            return false;
        }
        $digits = substr((string) $suffix, 1);

        return ctype_digit($digits) && strlen($digits) <= 5
            && (int) $digits >= 1 && (int) $digits <= 65535;
    }

    /**
     * Whether one canonical IP text sits inside any trusted CIDR. Host
     * bits set in a CIDR are masked away, and an IPv4-mapped IPv6
     * address matches in its IPv4 form.
     *
     * @param string $ip    the canonical IP text
     * @param array<int, string> $cidrs the trusted CIDR list
     */
    function kiwi_captcha_in_trusted($ip, array $cidrs)
    {
        $packed = @inet_pton((string) $ip);
        if ($packed === false) {
            return false;
        }
        foreach ($cidrs as $cidr) {
            $cidr = trim((string) $cidr);
            if ($cidr === '') {
                continue;
            }
            if (!str_contains($cidr, '/')) {
                $network = kiwi_captcha_canonical_ip($cidr);
                if ($network !== null && $network === (string) $ip) {
                    return true;
                }
                continue;
            }
            [$networkText, $prefixText] = explode('/', $cidr, 2);
            if (!ctype_digit($prefixText)) {
                continue;
            }
            $networkCanonical = kiwi_captcha_canonical_ip($networkText);
            if ($networkCanonical === null) {
                continue;
            }
            $network = @inet_pton($networkCanonical);
            if ($network === false || strlen($network) !== strlen($packed)) {
                continue;
            }
            $bits = strlen($packed) * 8;
            $prefix = (int) $prefixText;
            if ($prefix < 0 || $prefix > $bits) {
                continue;
            }
            $fullBytes = intdiv($prefix, 8);
            $remainder = $prefix % 8;
            if (substr($network, 0, $fullBytes) !== substr($packed, 0, $fullBytes)) {
                continue;
            }
            if ($remainder > 0 && $fullBytes < strlen($packed)) {
                $mask = chr((0xFF << (8 - $remainder)) & 0xFF);
                if ((substr($network, $fullBytes, 1) & $mask) !== (substr($packed, $fullBytes, 1) & $mask)) {
                    continue;
                }
            }

            return true;
        }

        return false;
    }
}
