using System;
using System.Collections.Generic;
using System.Net;
using System.Text.RegularExpressions;

namespace KiwiCaptcha;

/// <summary>
/// The trusted client-IP resolver: the canonical client IP of a
/// request is its socket peer unless the peer sits inside the
/// configured trusted-proxy CIDR list. An empty list trusts nobody, so
/// a client supplied forwarding header can never move the IP binding.
/// With a trusted peer, the X-Forwarded-For chain is walked right to
/// left: entries inside the trust list are skipped, the first
/// untrusted entry wins, and an entry that fails strict IP parsing
/// terminates the walk and falls back to the peer. X-Real-IP is
/// honored only when the peer is trusted and no forwarded chain
/// exists. The algorithm ports the Symfony bundle's ClientIpResolver
/// trusted-chain walk, so every SDK binds the same canonical IP for
/// the same request. ASP.NET's KnownProxies are deliberately not
/// consulted: the resolver implements the boundary directly so the
/// behavior matches every other SDK.
/// </summary>
public static class ClientIpResolver
{
    private static readonly Regex ControlBytes = new("[\\u0000-\\u001F\\u007F]", RegexOptions.Compiled);
    private static readonly Regex Digits = new("^\\d+$", RegexOptions.Compiled);
    private static readonly Regex DottedQuad = new(
        "^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$",
        RegexOptions.Compiled);

    /// <summary>
    /// The canonical client IP per the shared trusted-proxy contract.
    /// </summary>
    /// <param name="peer">The socket peer text.</param>
    /// <param name="xffLines">Every X-Forwarded-For header line.</param>
    /// <param name="realIp">The X-Real-IP header value, or null.</param>
    /// <param name="trustedProxies">The trusted CIDR list; empty trusts nobody.</param>
    public static string Resolve(string peer, IEnumerable<string>? xffLines, string? realIp,
        IEnumerable<string>? trustedProxies)
    {
        var peerText = (peer ?? "").Trim();
        var trusted = trustedProxies == null
            ? new List<string>()
            : new List<string>(trustedProxies);
        if (trusted.Count == 0)
        {
            return peerText;
        }
        var visible = new List<string>();
        if (xffLines != null)
        {
            foreach (var line in xffLines)
            {
                if (!string.IsNullOrWhiteSpace(line))
                {
                    visible.Add(line);
                }
            }
        }
        // A repeated forwarding header is parser ambiguity: one
        // intermediary reads the first line, another the last, so the
        // peer wins.
        if (visible.Count > 1)
        {
            return peerText;
        }
        var header = visible.Count == 1 ? visible[0].Trim() : "";
        if (header.Length == 0)
        {
            if (!PeerTrusted(peerText, trusted) || realIp == null)
            {
                return peerText;
            }
            var candidate = realIp.Trim();
            if (candidate.Length == 0 || ControlBytes.IsMatch(candidate))
            {
                return peerText;
            }
            var canonical = CanonicalIp(candidate);
            return canonical ?? peerText;
        }
        if (ControlBytes.IsMatch(header) || !PeerTrusted(peerText, trusted))
        {
            return peerText;
        }
        var hops = header.Split(',');
        for (var i = hops.Length - 1; i >= 0; i--)
        {
            var canonical = CanonicalIp(hops[i]);
            if (canonical == null)
            {
                // An unparsable hop terminates the trust chain: who
                // lies beyond it cannot be established, so the peer
                // falls back.
                return peerText;
            }
            if (!InTrusted(canonical, trusted))
            {
                return canonical;
            }
        }
        return peerText;
    }

    /// <summary>
    /// The canonical text of one forwarded node, or null when the node
    /// is not a genuine address. Handles bare IPv4, IPv4 with a port,
    /// bracketed IPv6 with an optional port, rejects unknown and
    /// obfuscated tokens and malformed ports, and normalizes
    /// IPv4-mapped IPv6 to its IPv4 form.
    /// </summary>
    public static string? CanonicalIp(string? identifier)
    {
        if (identifier == null)
        {
            return null;
        }
        var value = identifier.Trim();
        if (value.Length == 0 || value == "unknown" || value.StartsWith("_"))
        {
            return null;
        }
        var candidate = value;
        if (candidate.StartsWith("["))
        {
            var closing = candidate.IndexOf(']');
            if (closing < 0)
            {
                return null;
            }
            var suffix = candidate[(closing + 1)..];
            if (suffix.Length > 0 && !IsPortSuffix(suffix))
            {
                return null;
            }
            candidate = candidate[1..closing];
        }
        else if (CountColons(candidate) == 1)
        {
            // IPv4 with a port: the port splits only when the left
            // side is a valid IPv4 and the port is a genuine number.
            var parts = candidate.Split(':');
            if (parts.Length == 2 && IsStrictIpv4(parts[0]) && IsPortSuffix(":" + parts[1]))
            {
                candidate = parts[0];
            }
        }
        if (candidate.Contains(':') && CountColons(candidate) < 2)
        {
            var parts = candidate.Split(':');
            if (IsStrictIpv4(parts[^1]))
            {
                candidate = string.Join(':', parts[..^1]);
            }
        }
        var parsed = ParseAddress(candidate);
        return parsed == null ? null : CanonicalText(parsed);
    }

    /// <summary>
    /// Whether one IP text sits inside any trusted CIDR. Host bits set
    /// in a CIDR are masked away, and an IPv4-mapped IPv6 address
    /// matches in its IPv4 form.
    /// </summary>
    public static bool InTrusted(string? ipText, IEnumerable<string>? trustedProxies)
    {
        var parsed = ParseAddress(ipText ?? "");
        if (parsed == null || trustedProxies == null)
        {
            return false;
        }
        foreach (var cidr in trustedProxies)
        {
            if (CidrContains(cidr, parsed))
            {
                return true;
            }
        }
        return false;
    }

    private static bool PeerTrusted(string peerText, List<string> trusted)
    {
        if (peerText.Length == 0)
        {
            return false;
        }
        return InTrusted(peerText.Trim('['), trusted) || InTrusted(peerText.Trim('[', ']'), trusted);
    }

    private static bool CidrContains(string? cidr, IPAddress address)
    {
        if (cidr == null)
        {
            return false;
        }
        var trimmed = cidr.Trim();
        if (trimmed.Length == 0)
        {
            return false;
        }
        string addressText;
        string? lengthText = null;
        var slash = trimmed.LastIndexOf('/');
        if (slash < 0)
        {
            addressText = trimmed;
        }
        else
        {
            addressText = trimmed[..slash].Trim();
            lengthText = trimmed[(slash + 1)..].Trim();
        }
        var network = ParseAddress(addressText);
        if (network == null || (lengthText != null && !Digits.IsMatch(lengthText)))
        {
            return false;
        }
        var bits = network.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        var prefixLength = bits;
        if (lengthText != null)
        {
            prefixLength = int.Parse(lengthText);
            if (prefixLength < 0 || prefixLength > bits)
            {
                return false;
            }
        }
        // Both sides normalize: an IPv4-mapped IPv6 address (or
        // network) matches in its IPv4 form, so family comparisons
        // stay exact.
        if (network.IsIPv4MappedToIPv6)
        {
            network = network.MapToIPv4();
        }
        var candidate = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        if (network.AddressFamily != candidate.AddressFamily)
        {
            return false;
        }
        var networkBytes = network.GetAddressBytes();
        var candidateBytes = candidate.GetAddressBytes();
        var fullBytes = prefixLength / 8;
        var remainder = prefixLength % 8;
        if (fullBytes > candidateBytes.Length)
        {
            return false;
        }
        for (var i = 0; i < fullBytes; i++)
        {
            if (networkBytes[i] != candidateBytes[i])
            {
                return false;
            }
        }
        if (remainder > 0 && fullBytes < candidateBytes.Length)
        {
            var mask = (byte)(0xFF << (8 - remainder));
            return (networkBytes[fullBytes] & mask) == (candidateBytes[fullBytes] & mask);
        }
        return true;
    }

    private static IPAddress? ParseAddress(string text)
    {
        var trimmed = text.Trim();
        if (trimmed.Length == 0 || trimmed.Contains('%'))
        {
            return null;
        }
        // The gate keeps IPAddress.Parse's lenient shorthand out: no
        // decimal integer form, no leading-zero octets.
        if (!trimmed.Contains(':') && !DottedQuad.IsMatch(trimmed))
        {
            return null;
        }
        return IPAddress.TryParse(trimmed, out var parsed) ? parsed : null;
    }

    private static string CanonicalText(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            return address.MapToIPv4().ToString();
        }
        var bytes = address.GetAddressBytes();
        if (bytes.Length == 4)
        {
            return address.ToString();
        }
        return CompressIpv6(bytes);
    }

    /// <summary>The RFC 5952 compressed lowercase text: one longest zero run becomes "::".</summary>
    private static string CompressIpv6(byte[] bytes)
    {
        var groups = new string[8];
        var bestStart = -1;
        var bestLength = 0;
        var currentStart = -1;
        var currentLength = 0;
        for (var i = 0; i < 8; i++)
        {
            var value = (bytes[i * 2] << 8) | bytes[i * 2 + 1];
            groups[i] = value.ToString("x");
            if (value == 0)
            {
                if (currentStart < 0)
                {
                    currentStart = i;
                }
                currentLength++;
                if (currentLength > bestLength)
                {
                    bestStart = currentStart;
                    bestLength = currentLength;
                }
            }
            else
            {
                currentStart = -1;
                currentLength = 0;
            }
        }
        if (bestLength < 2)
        {
            return string.Join(":", groups);
        }
        var head = string.Join(':', groups[..bestStart]);
        var foot = string.Join(':', groups[(bestStart + bestLength)..]);
        return head + "::" + foot;
    }

    private static bool IsPortSuffix(string suffix)
    {
        if (suffix.Length < 2 || suffix[0] != ':')
        {
            return false;
        }
        var digits = suffix[1..];
        return digits.Length <= 5 && Digits.IsMatch(digits)
            && int.TryParse(digits, out var port) && port >= 1 && port <= 65535;
    }

    private static bool IsStrictIpv4(string? text)
    {
        return text != null && DottedQuad.IsMatch(text);
    }

    private static int CountColons(string text)
    {
        var count = 0;
        foreach (var c in text)
        {
            if (c == ':')
            {
                count++;
            }
        }
        return count;
    }
}
