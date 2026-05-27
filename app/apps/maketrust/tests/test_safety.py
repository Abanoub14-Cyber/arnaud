"""Attack-vector tests for safety primitives.

If any of these regress, MakeTrust becomes a public SSRF/scanning oracle —
treat failures here as production-blockers.
"""
from __future__ import annotations

import pytest

from apps.maketrust.scanner.safety import (
    DomainValidationError,
    is_public_ip,
    validate_domain,
)


# ---------------------------- validate_domain ----------------------------

@pytest.mark.parametrize("raw, expected", [
    ("makeset.be", "makeset.be"),
    ("MakeSet.BE", "makeset.be"),
    ("makeset.be.", "makeset.be"),                # trailing dot tolerated
    ("sub.domain.makeset.be", "sub.domain.makeset.be"),
    ("xn--bcher-kva.com", "xn--bcher-kva.com"),   # already-punycoded label is plain ASCII
])
def test_validate_domain_accepts_legit(raw, expected):
    assert validate_domain(raw) == expected


@pytest.mark.parametrize("hostile", [
    # Schemes / URLs
    "http://makeset.be",
    "https://makeset.be/admin",
    "ftp://makeset.be",
    "javascript:alert(1)",
    "data:text/html,xxx",

    # Paths / query / fragment
    "makeset.be/",
    "makeset.be/admin",
    "makeset.be?id=1",
    "makeset.be#frag",

    # Port appended
    "makeset.be:8080",
    "makeset.be:22",

    # IP literals (we are a domain scanner, refuse for v1)
    "127.0.0.1",
    "169.254.169.254",            # AWS/GCP metadata
    "10.0.0.1",
    "192.168.1.1",
    "::1",
    "[::1]",
    "fe80::1",

    # Reserved TLDs
    "anything.local",
    "anything.localhost",
    "anything.test",
    "service.internal",
    "machine.invalid",
    "abc.onion",
    "xxx.arpa",

    # Whitespace / control
    "make set.be",
    "makeset.be\n",
    "makeset.be\t",
    " makeset.be",            # leading space — must NOT be silently stripped
    "makeset.be ",            # trailing space

    # Dot abuse
    ".makeset.be",
    "make..set.be",

    # Empty / type
    "",
    "   ",

    # IDN / non-ASCII rejected outright in v1
    "mаkeset.be",       # Cyrillic а (U+0430) — homograph
    "bücher.example",   # plain non-ASCII

    # Numeric-only TLD (looks like an IP-as-domain trick)
    "host.123",

    # Bare TLDs (no dot)
    "localhost",
    "be",

    # Excessive length (single label > 63 or total > 253)
    "a" * 64 + ".be",
    ("x" * 60 + ".") * 5 + "be",  # > 253 total
])
def test_validate_domain_rejects_hostile(hostile):
    with pytest.raises((DomainValidationError, Exception)):
        validate_domain(hostile)


def test_validate_domain_rejects_non_string():
    with pytest.raises(DomainValidationError):
        validate_domain(None)  # type: ignore[arg-type]
    with pytest.raises(DomainValidationError):
        validate_domain(123)   # type: ignore[arg-type]


# ---------------------------- is_public_ip ----------------------------

@pytest.mark.parametrize("ip", [
    "8.8.8.8",
    "1.1.1.1",
    "104.16.132.229",
    "2606:4700:4700::1111",     # Cloudflare DNS
    "2001:4860:4860::8888",     # Google DNS
])
def test_is_public_ip_accepts_global(ip):
    assert is_public_ip(ip) is True


@pytest.mark.parametrize("ip", [
    # Loopback
    "127.0.0.1",
    "127.255.255.254",
    "::1",
    # RFC 1918 private
    "10.0.0.1",
    "10.255.255.255",
    "172.16.0.1",
    "172.31.255.254",
    "192.168.0.1",
    "192.168.255.255",
    # Link-local + cloud metadata
    "169.254.0.1",
    "169.254.169.254",          # AWS / GCP / Azure metadata
    "fe80::1",
    # IPv6 ULA
    "fd00::1",
    "fc00::1",
    # Multicast
    "224.0.0.1",
    "ff02::1",
    # Reserved / special
    "0.0.0.0",
    "255.255.255.255",
    "::",
    # Invalid
    "not.an.ip",
    "999.999.999.999",
    "",
])
def test_is_public_ip_rejects_unsafe(ip):
    assert is_public_ip(ip) is False
