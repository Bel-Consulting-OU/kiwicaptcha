"""The trusted client-IP resolver.

The canonical client IP of a request is its socket peer unless the
peer sits inside the configured trusted-proxy CIDR list. An empty list
trusts nobody: ``X-Forwarded-For`` and ``X-Real-IP`` are ignored and
the peer wins, so a forged forwarding header can never influence the
binding. With a trusted peer, the ``X-Forwarded-For`` chain is walked
right to left: entries inside the trust list are skipped, the first
untrusted entry wins, and an entry that fails strict IP parsing
terminates the walk (the peer falls back, never a left-side guess).
``X-Real-IP`` is honored only when the peer is trusted and no
forwarded chain exists. The algorithm ports the Symfony bundle's
``ClientIpResolver`` trusted-chain walk, so every SDK binds the same
canonical IP for the same request.
"""

import ipaddress
import re

_CONTROL_BYTES = re.compile(r"[\x00-\x1F\x7F]")
# The strict dotted-quad grammar: filter_var's IPv4 validator accepts
# exactly this shape, while ipaddress also parses the decimal-integer
# form ("3232235521") the gate must refuse.
_IPV4_TEXT = re.compile(
    r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
)


def _has_control_bytes(text: str) -> bool:
    return _CONTROL_BYTES.search(text) is not None


def canonical_ip(text: str):
    """The canonical IP text of one forwarded node, or ``None``.

    Handles bare IPv4, IPv4 with a port, bracketed IPv6 with an
    optional port, rejects ``unknown``, ``_obfuscated`` tokens and any
    malformed spelling, and normalizes IPv4-mapped IPv6 to its IPv4
    form.
    """
    value = text.strip()
    if value == "" or value == "unknown" or value.startswith("_"):
        return None
    candidate = value
    if candidate.startswith("["):
        closing = candidate.find("]")
        if closing == -1:
            return None
        suffix = candidate[closing + 1:]
        if suffix != "" and not _is_valid_port(suffix):
            return None
        candidate = candidate[1:closing]
    elif candidate.count(":") == 1:
        # IPv4 with a port: the port splits only when the left side is
        # a valid IPv4 and the port is a genuine number.
        parts = candidate.split(":")
        if (
            len(parts) == 2
            and _is_ipv4(parts[0])
            and _is_valid_port(":" + parts[1])
        ):
            candidate = parts[0]
    if ":" in candidate and candidate.count(":") < 2:
        # A bare "2001:db8::1:4711" style remainder is ambiguous and
        # rejected rather than guessed; a single-colon "v6:v4" pair
        # collapses only when the right side is a real IPv4.
        parts = candidate.split(":")
        if _is_ipv4(parts[-1]):
            candidate = ":".join(parts[:-1])
    try:
        if ":" not in candidate and not _IPV4_TEXT.match(candidate):
            return None
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        return str(mapped)
    return str(addr)


def _is_ipv4(text: str) -> bool:
    return _IPV4_TEXT.match(text) is not None


def _is_valid_port(suffix: str) -> bool:
    if not suffix.startswith(":"):
        return False
    digits = suffix[1:]
    return digits.isdigit() and 1 <= int(digits) <= 65535


def ip_in_trusted(ip_text: str, trusted_proxies) -> bool:
    """Whether one canonical IP text sits inside any trusted CIDR.

    Host bits set in a CIDR are masked away. An IPv4-mapped IPv6
    address matches the trusted list in its IPv4 form.
    """
    try:
        addr = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    for cidr in trusted_proxies:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except (ValueError, TypeError):
            continue
        if network.version == addr.version and addr in network:
            return True
    return False


def resolve_client_ip(peer, xff, real_ip, trusted_proxies):
    """The canonical client IP per the shared trusted-proxy contract.

    ``peer`` is the socket peer text, ``xff`` the (merged)
    ``X-Forwarded-For`` header value or ``None``, ``real_ip`` the
    ``X-Real-IP`` header value or ``None``, and ``trusted_proxies`` the
    trusted CIDR list (empty: never trust forwarding headers).
    """
    peer_text = (peer or "").strip()
    trusted = [c.strip() for c in (trusted_proxies or []) if c and str(c).strip()]

    if not trusted:
        return peer_text

    def peer_is_trusted() -> bool:
        canonical = canonical_ip(peer_text)
        return canonical is not None and ip_in_trusted(canonical, trusted)

    if xff is None or (isinstance(xff, str) and xff.strip() == ""):
        # No forwarded chain: X-Real-IP when the immediate peer is
        # trusted, the peer otherwise.
        if real_ip and peer_is_trusted():
            if not isinstance(real_ip, str) or _has_control_bytes(real_ip):
                return peer_text
            canonical = canonical_ip(real_ip)
            return canonical if canonical is not None else peer_text
        return peer_text

    if not isinstance(xff, str) or _has_control_bytes(xff):
        return peer_text
    if not peer_is_trusted():
        return peer_text

    for candidate in reversed([part.strip() for part in xff.split(",")]):
        canonical = canonical_ip(candidate)
        if canonical is None:
            # An unparsable hop terminates the trust chain: who lies
            # beyond it cannot be established, so the peer falls back.
            return peer_text
        if not ip_in_trusted(canonical, trusted):
            return canonical
    return peer_text
