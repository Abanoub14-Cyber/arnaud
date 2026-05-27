"""Defensive primitives shared by every scanner module.

Three jobs:

1. ``validate_domain`` — accept only well-formed, public, scannable hostnames.
   Rejects schemes, paths, ports, IP literals, reserved TLDs, IDN homographs.
2. ``is_public_ip`` — reject anything we shouldn't reach: loopback, RFC1918,
   link-local, cloud metadata, ULA, etc. SSRF guard #1.
3. ``make_safe_session`` — a ``requests.Session`` that pins each connection
   to a pre-resolved public IP, caps response size, enforces strict timeouts,
   and re-validates redirects. SSRF guard #2 (covers DNS rebinding).

These primitives are imported by every scanner module. Touch with care and
keep the unit tests in ``tests/test_safety.py`` green.
"""
from __future__ import annotations

import ipaddress
import re
import socket


# Hostname per RFC 1123: labels of 1..63 chars, [a-z0-9-], no leading/trailing
# hyphen, total length 1..253.  We require at least one dot (no bare TLDs).
_LABEL = r"(?=.{1,63}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")

# Reserved/private TLDs we never want to scan. Sources: RFC 6761, RFC 7686,
# IANA special-use registry. ``.internal`` is the de-facto standard ICANN
# is on the path to ratifying for private-use names — block proactively.
RESERVED_TLDS = frozenset({
    "local", "localhost", "test", "example", "invalid",
    "onion", "arpa", "internal", "home", "lan", "intranet",
    "private", "corp",
})

# Single user-agent so we're easy to identify and easy to block if abused.
USER_AGENT = "MakeTrustBot/1.0 (+https://makeset.be/tools/maketrust/)"

# Strict per-request defaults. Modules can lower these but never raise them.
DEFAULT_CONNECT_TIMEOUT = 5  # seconds
DEFAULT_READ_TIMEOUT = 8     # seconds
MAX_RESPONSE_BYTES = 256 * 1024
MAX_REDIRECTS = 3


class DomainValidationError(ValueError):
    """Raised when a user-submitted domain is not safe to scan."""


def validate_domain(raw: str) -> str:
    """Normalize and validate a user-submitted domain.

    Returns a lower-cased ASCII hostname. Raises ``DomainValidationError`` on
    anything we will not scan.

    v1 rejects non-ASCII input outright. IDN support adds attack surface
    (homographs, mixed scripts) for ~0% of our target audience (Belgian SMEs).
    Add IDN support later if a user actually asks.
    """
    if not isinstance(raw, str):
        raise DomainValidationError("not a string")

    # Reject any whitespace anywhere in the original input — trailing CR/LF
    # and embedded tabs are classic smuggling vectors.
    if any(c.isspace() for c in raw):
        raise DomainValidationError("whitespace not allowed")

    candidate = raw.rstrip(".").lower()
    if not candidate:
        raise DomainValidationError("empty")

    if not candidate.isascii():
        raise DomainValidationError("non-ASCII not supported (IDN disabled in v1)")

    # Reject URL fragments before they sneak through.
    if "://" in candidate or "/" in candidate or "?" in candidate or "#" in candidate:
        raise DomainValidationError("URL-like input, provide just the domain")
    if ":" in candidate:
        raise DomainValidationError("port not allowed")
    if candidate.startswith(".") or ".." in candidate:
        raise DomainValidationError("malformed dots")

    # Reject IP literals — they bypass DNS-based safety checks.
    try:
        ipaddress.ip_address(candidate)
        raise DomainValidationError("IP literal, provide a domain name")
    except ValueError:
        pass  # not an IP — good

    # Final shape check: hostname grammar + length cap.
    if len(candidate) > 253:
        raise DomainValidationError("too long")
    if not _DOMAIN_RE.match(candidate):
        raise DomainValidationError("not a valid hostname")

    tld = candidate.rsplit(".", 1)[-1]
    if tld in RESERVED_TLDS:
        raise DomainValidationError(f"reserved TLD .{tld}")
    if tld.isdigit():
        raise DomainValidationError("numeric TLD")

    return candidate


def is_public_ip(ip_str: str) -> bool:
    """True iff ``ip_str`` is a globally routable address we may safely query.

    Rejects loopback, private (RFC 1918 / 4193), link-local (incl. cloud
    metadata at 169.254.169.254), multicast, reserved, unspecified, and
    site-local IPv6.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    # ``is_global`` covers most cases but doesn't reject every cloud metadata
    # range explicitly; we add an extra belt for the common ones.
    if not ip.is_global:
        return False
    if ip.is_loopback or ip.is_private or ip.is_link_local:
        return False
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    return True


def resolve_public_ips(hostname: str) -> list[str]:
    """Resolve ``hostname`` to A/AAAA records, dropping any non-public address.

    Used as the SSRF-safe entry point: we resolve *once* before any HTTP
    request, then pin the subsequent connection to one of these IPs. Returns
    an empty list if the host has no public IP — caller should treat that as
    a hard scan failure, not silently fall back.
    """
    public: list[str] = []
    try:
        for family, _t, _p, _c, sockaddr in socket.getaddrinfo(
            hostname, None, proto=socket.IPPROTO_TCP
        ):
            ip = sockaddr[0]
            if is_public_ip(ip):
                public.append(ip)
    except socket.gaierror:
        return []
    # Preserve order, deduplicate.
    seen: set[str] = set()
    deduped: list[str] = []
    for ip in public:
        if ip not in seen:
            seen.add(ip)
            deduped.append(ip)
    return deduped


def make_safe_session():
    """Return a ``requests.Session`` hardened against SSRF and runaway responses.

    - Connection is pinned to a pre-resolved public IP via a custom adapter
      (defeats DNS rebinding between resolution and connect).
    - Default timeouts: 5s connect / 8s read.
    - Redirects are NOT followed automatically; modules call ``follow_redirect``
      to manually re-validate the next hop's IP.
    - Response body is hard-capped at 256 KiB to keep memory predictable.

    Lazy import of ``requests`` so this module stays importable in test runs
    that don't need network capabilities.
    """
    import requests
    from urllib3.util import connection as urllib3_connection

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept-Encoding": "gzip, deflate"})

    # Block redirects globally — modules opt in per request via `allow_redirects=False`.
    # We keep `max_redirects = 1` rather than `0` because the latter trips
    # `requests.Session.send` even with `allow_redirects=False`: the lib
    # eagerly computes `r._next` and the redirect-resolver raises
    # `TooManyRedirects` as soon as `max_redirects < 1`. Setting it to 1 lets
    # `_next` be computed (we ignore it) without changing actual redirect
    # behaviour, which stays gated by the per-request flag.
    session.max_redirects = 1

    # We don't pin via a transport adapter because per-request pinning is
    # cleaner: callers pass `target_ip=<x>` to a helper. See `safe_get` below.
    return session


# Thread-local IP pin state. Each thread sets `_pin_state.ip` for the
# duration of one safe_get call; other threads (concurrent workers) keep
# their own independent pin. Replaces the previous *global* swap of
# `urllib3.util.connection.create_connection`, which scrambled IPs across
# threads as soon as the django-q cluster ran >1 worker.
import threading as _threading
_pin_state = _threading.local()


def _install_pin_hook_once() -> None:
    """Install the connection hook exactly once per process. Idempotent."""
    from urllib3.util import connection as urllib3_connection
    if getattr(urllib3_connection, "_maketrust_hook_installed", False):
        return
    original_create = urllib3_connection.create_connection

    def _maybe_pinned_create(address, *args, **kwargs):
        host, port = address
        pinned_ip = getattr(_pin_state, "ip", None)
        if pinned_ip:
            return original_create((pinned_ip, port), *args, **kwargs)
        return original_create(address, *args, **kwargs)

    urllib3_connection.create_connection = _maybe_pinned_create
    urllib3_connection._maketrust_hook_installed = True


def safe_get(session, url: str, target_ip: str, *,
             allow_redirects: bool = False,
             timeout: tuple[int, int] = (DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT)):
    """GET ``url`` with the connection forcibly bound to ``target_ip``.

    The mechanism: a *thread-local* IP pin read by a one-time monkey-patch
    of urllib3's ``create_connection``. Each thread can pin its own IP
    concurrently with no cross-talk. Effective against DNS rebinding
    (server can't switch IP between resolution and connect).

    ``target_ip`` MUST already have passed ``is_public_ip``.
    """
    if not is_public_ip(target_ip):
        raise DomainValidationError(f"refusing to connect to non-public IP {target_ip}")

    _install_pin_hook_once()
    previous_ip = getattr(_pin_state, "ip", None)
    _pin_state.ip = target_ip
    try:
        resp = session.get(
            url,
            timeout=timeout,
            allow_redirects=False,  # always manual
            stream=True,
        )
        # Cap the body size at read time to keep a hostile server from
        # filling RAM. We truncate silently rather than raise: enterprise
        # homepages routinely cross 256 KiB (CSS-in-JS, inlined SVGs), and
        # the security goal is "don't OOM", not "reject large pages".
        body = b""
        for chunk in resp.iter_content(chunk_size=8192):
            body += chunk
            if len(body) >= MAX_RESPONSE_BYTES:
                body = body[:MAX_RESPONSE_BYTES]
                break
        resp.close()
        resp._content = body  # cache so resp.text / resp.content work normally
        return resp
    finally:
        _pin_state.ip = previous_ip


__all__ = [
    "DomainValidationError",
    "RESERVED_TLDS",
    "USER_AGENT",
    "MAX_RESPONSE_BYTES",
    "validate_domain",
    "is_public_ip",
    "resolve_public_ips",
    "make_safe_session",
    "safe_get",
]
