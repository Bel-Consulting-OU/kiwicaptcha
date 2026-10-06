package com.kiwicaptcha.servlet;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * The trusted client-IP resolver: the canonical client IP of a request
 * is its socket peer unless the peer sits inside the configured
 * trusted-proxy CIDR list. An empty list trusts nobody, so a client
 * supplied forwarding header can never move the IP binding. With a
 * trusted peer, the X-Forwarded-For chain is walked right to left:
 * entries inside the trust list are skipped, the first untrusted entry
 * wins, and an entry that fails strict IP parsing terminates the walk
 * and falls back to the peer. X-Real-IP is honored only when the peer
 * is trusted and no forwarded chain exists. The algorithm ports the
 * Symfony bundle's ClientIpResolver trusted-chain walk, so every SDK
 * binds the same canonical IP for the same request.
 */
public final class ClientIpResolver {
    private static final Pattern CONTROL_BYTES = Pattern.compile("[\\x00-\\x1F\\x7F]");
    private static final Pattern DIGITS = Pattern.compile("\\d+");
    private static final Pattern DOTTED_QUAD = Pattern.compile(
            "\\A(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}\\z");

    private ClientIpResolver() {
    }

    /**
     * The canonical client IP per the shared trusted-proxy contract.
     *
     * @param peer           the socket peer text
     * @param xffLines       every X-Forwarded-For header line the
     *                       surface can see (null when absent)
     * @param realIp         the X-Real-IP header value (null when absent)
     * @param trustedProxies the trusted CIDR list; empty trusts nobody
     */
    public static String resolve(String peer, List<String> xffLines, String realIp, List<String> trustedProxies) {
        String peerText = peer == null ? "" : peer.trim();
        List<Prefix> trusted = trustedPrefixes(trustedProxies);
        if (trusted.isEmpty()) {
            return peerText;
        }
        List<String> lines = new ArrayList<>();
        if (xffLines != null) {
            for (String line : xffLines) {
                if (line != null && !line.trim().isEmpty()) {
                    lines.add(line);
                }
            }
        }
        // A repeated forwarding header is parser ambiguity: one
        // intermediary reads the first line, another the last, so the
        // peer wins.
        if (lines.size() > 1) {
            return peerText;
        }
        String header = lines.isEmpty() ? "" : lines.get(0).trim();
        if (header.isEmpty()) {
            if (!peerTrusted(peerText, trusted) || realIp == null) {
                return peerText;
            }
            String candidate = realIp.trim();
            if (candidate.isEmpty() || CONTROL_BYTES.matcher(candidate).find()) {
                return peerText;
            }
            String canonical = canonicalIp(candidate);
            return canonical != null ? canonical : peerText;
        }
        if (CONTROL_BYTES.matcher(header).find() || !peerTrusted(peerText, trusted)) {
            return peerText;
        }
        String[] hops = header.split(",");
        for (int i = hops.length - 1; i >= 0; i--) {
            String canonical = canonicalIp(hops[i]);
            if (canonical == null) {
                // An unparsable hop terminates the trust chain: who
                // lies beyond it cannot be established, so the peer
                // falls back.
                return peerText;
            }
            if (!prefixTrusted(canonical, trusted)) {
                return canonical;
            }
        }
        return peerText;
    }

    /**
     * The canonical text of one forwarded node, or null when the node
     * is not a genuine address. Handles bare IPv4, IPv4 with a port,
     * bracketed IPv6 with an optional port, rejects unknown and
     * obfuscated tokens and malformed ports, and normalizes
     * IPv4-mapped IPv6 to its IPv4 form.
     */
    public static String canonicalIp(String identifier) {
        if (identifier == null) {
            return null;
        }
        String value = identifier.trim();
        if (value.isEmpty() || value.equals("unknown") || value.startsWith("_")) {
            return null;
        }
        String candidate = value;
        if (candidate.startsWith("[")) {
            int closing = candidate.indexOf(']');
            if (closing < 0) {
                return null;
            }
            String suffix = candidate.substring(closing + 1);
            if (!suffix.isEmpty() && !isPortSuffix(suffix)) {
                return null;
            }
            candidate = candidate.substring(1, closing);
        } else if (countColons(candidate) == 1) {
            // IPv4 with a port: the port splits only when the left
            // side is a valid IPv4 and the port is a genuine number.
            String[] parts = candidate.split(":", -1);
            if (parts.length == 2 && isStrictIpv4(parts[0]) && isPortSuffix(":" + parts[1])) {
                candidate = parts[0];
            }
        }
        if (candidate.indexOf(':') >= 0 && countColons(candidate) < 2) {
            String[] parts = candidate.split(":", -1);
            if (isStrictIpv4(parts[parts.length - 1])) {
                StringBuilder joined = new StringBuilder();
                for (int i = 0; i < parts.length - 1; i++) {
                    if (i > 0) {
                        joined.append(':');
                    }
                    joined.append(parts[i]);
                }
                candidate = joined.toString();
            }
        }
        InetAddress parsed = parseAddress(candidate);
        if (parsed == null) {
            return null;
        }
        return canonicalText(parsed);
    }

    /**
     * Whether one IP text sits inside any trusted CIDR. Host bits set
     * in a CIDR are masked away, and an IPv4-mapped IPv6 address
     * matches in its IPv4 form.
     */
    public static boolean inTrusted(String ipText, List<String> trustedProxies) {
        InetAddress parsed = parseAddress(ipText == null ? "" : ipText);
        if (parsed == null || trustedProxies == null) {
            return false;
        }
        byte[] address = normalizeFamily(parsed);
        for (String cidr : trustedProxies) {
            Prefix prefix = parsePrefix(cidr);
            if (prefix != null && prefix.contains(address)) {
                return true;
            }
        }
        return false;
    }

    private static boolean peerTrusted(String peerText, List<Prefix> trusted) {
        if (peerText.isEmpty()) {
            return false;
        }
        InetAddress parsed = parseAddress(stripBrackets(peerText));
        if (parsed == null) {
            return false;
        }
        byte[] address = normalizeFamily(parsed);
        for (Prefix prefix : trusted) {
            if (prefix.contains(address)) {
                return true;
            }
        }
        return false;
    }

    /** Membership for canonical text (the output of canonicalIp). */
    private static boolean prefixTrusted(String canonical, List<Prefix> trusted) {
        InetAddress parsed = parseAddress(canonical);
        if (parsed == null) {
            return false;
        }
        byte[] address = normalizeFamily(parsed);
        for (Prefix prefix : trusted) {
            if (prefix.contains(address)) {
                return true;
            }
        }
        return false;
    }

    private static List<Prefix> trustedPrefixes(List<String> cidrs) {
        List<Prefix> prefixes = new ArrayList<>();
        if (cidrs != null) {
            for (String cidr : cidrs) {
                if (cidr == null || cidr.trim().isEmpty()) {
                    continue;
                }
                Prefix prefix = parsePrefix(cidr);
                if (prefix != null) {
                    prefixes.add(prefix);
                }
            }
        }
        return prefixes;
    }

    private static String stripBrackets(String text) {
        String trimmed = text.trim();
        if (trimmed.startsWith("[") && trimmed.endsWith("]") && trimmed.length() >= 2) {
            return trimmed.substring(1, trimmed.length() - 1);
        }
        return trimmed;
    }

    private static byte[] normalizeFamily(InetAddress address) {
        // Java renders an IPv4-mapped literal as an Inet4Address
        // already; the byte form is what the prefix comparison wants.
        return address.getAddress();
    }

    private static String canonicalText(InetAddress address) {
        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            return dottedQuad(bytes, 0);
        }
        if (isMappedBytes(bytes)) {
            return dottedQuad(bytes, 12);
        }
        return compressIpv6(bytes);
    }

    private static boolean isMappedBytes(byte[] bytes) {
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }
        return bytes[10] == (byte) 0xFF && bytes[11] == (byte) 0xFF;
    }

    private static String dottedQuad(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFF) + "." + (bytes[offset + 1] & 0xFF)
                + "." + (bytes[offset + 2] & 0xFF) + "." + (bytes[offset + 3] & 0xFF);
    }

    /** The RFC 5952 compressed lowercase text: one longest zero run becomes "::". */
    private static String compressIpv6(byte[] bytes) {
        String[] groups = new String[8];
        int bestStart = -1;
        int bestLength = 0;
        int currentStart = -1;
        int currentLength = 0;
        for (int i = 0; i < 8; i++) {
            int value = ((bytes[i * 2] & 0xFF) << 8) | (bytes[i * 2 + 1] & 0xFF);
            groups[i] = Integer.toString(value, 16);
            if (value == 0) {
                if (currentStart < 0) {
                    currentStart = i;
                }
                currentLength++;
                if (currentLength > bestLength) {
                    bestStart = currentStart;
                    bestLength = currentLength;
                }
            } else {
                currentStart = -1;
                currentLength = 0;
            }
        }
        if (bestLength < 2) {
            return String.join(":", groups);
        }
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < bestStart; i++) {
            text.append(groups[i]).append(':');
        }
        text.append(':');
        for (int i = bestStart + bestLength; i < 8; i++) {
            text.append(groups[i]);
            if (i < 7) {
                text.append(':');
            }
        }
        return text.toString();
    }

    /**
     * The strict address parse: literals only (no DNS), zones
     * refused. A trailing zone on an IPv6 literal is dropped before
     * the parse, matching the other SDK ports.
     */
    private static InetAddress parseAddress(String text) {
        String trimmed = text == null ? "" : text.trim();
        if (trimmed.isEmpty() || !looksLikeAddress(trimmed)) {
            return null;
        }
        int percent = trimmed.indexOf('%');
        if (percent >= 0) {
            return null;
        }
        try {
            return InetAddress.getByName(trimmed);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static boolean looksLikeAddress(String text) {
        return DOTTED_QUAD.matcher(text).find() || text.indexOf(':') >= 0;
    }

    private static Prefix parsePrefix(String cidr) {
        if (cidr == null) {
            return null;
        }
        String trimmed = cidr.trim();
        int slash = trimmed.lastIndexOf('/');
        String addressText;
        String lengthText;
        if (slash < 0) {
            addressText = trimmed;
            lengthText = null;
        } else {
            addressText = trimmed.substring(0, slash).trim();
            lengthText = trimmed.substring(slash + 1).trim();
        }
        InetAddress network = parseAddress(addressText);
        if (network == null) {
            return null;
        }
        byte[] bytes = network.getAddress();
        int bits = bytes.length * 8;
        int prefixLength = bits;
        if (lengthText != null) {
            if (!DIGITS.matcher(lengthText).matches()) {
                return null;
            }
            prefixLength = Integer.parseInt(lengthText);
            if (prefixLength < 0 || prefixLength > bits) {
                return null;
            }
        }
        return new Prefix(maskAddress(bytes, prefixLength), prefixLength);
    }

    private static byte[] maskAddress(byte[] address, int prefixLength) {
        byte[] masked = address.clone();
        int fullBytes = prefixLength / 8;
        int remainder = prefixLength % 8;
        for (int i = fullBytes; i < masked.length; i++) {
            masked[i] = 0;
        }
        if (remainder > 0 && fullBytes < masked.length) {
            int mask = 0xFF << (8 - remainder);
            masked[fullBytes] = (byte) (masked[fullBytes] & mask);
        }
        return masked;
    }

    private static boolean isPortSuffix(String suffix) {
        if (suffix.length() < 2 || suffix.charAt(0) != ':') {
            return false;
        }
        String digits = suffix.substring(1);
        if (digits.length() > 5 || !DIGITS.matcher(digits).matches()) {
            return false;
        }
        int port = Integer.parseInt(digits);
        return port >= 1 && port <= 65535;
    }

    private static boolean isStrictIpv4(String text) {
        return text != null && DOTTED_QUAD.matcher(text).find();
    }

    private static int countColons(String text) {
        int count = 0;
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) == ':') {
                count++;
            }
        }
        return count;
    }

    /** One parsed CIDR: the masked network bytes plus the prefix length. */
    private static final class Prefix {
        private final byte[] network;
        private final int prefixLength;

        Prefix(byte[] network, int prefixLength) {
            this.network = network;
            this.prefixLength = prefixLength;
        }

        boolean contains(byte[] address) {
            if (address.length != network.length) {
                return false;
            }
            int fullBytes = prefixLength / 8;
            int remainder = prefixLength % 8;
            for (int i = 0; i < fullBytes; i++) {
                if (network[i] != address[i]) {
                    return false;
                }
            }
            if (remainder > 0) {
                int mask = 0xFF << (8 - remainder);
                return (network[fullBytes] & mask) == (address[fullBytes] & mask);
            }
            return true;
        }
    }
}
