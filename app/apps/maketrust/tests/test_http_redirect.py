"""Tests for the www-variant helper used by http_redirect."""
from __future__ import annotations

from apps.maketrust.scanner.http_redirect import _www_variant


class TestWwwVariant:
    def test_apex_to_www(self):
        assert _www_variant("example.com") == "www.example.com"

    def test_www_to_apex(self):
        assert _www_variant("www.example.com") == "example.com"

    def test_two_label_apex_to_www(self):
        assert _www_variant("example.org") == "www.example.org"

    def test_subdomain_returns_none(self):
        assert _www_variant("blog.example.com") is None

    def test_deep_subdomain_returns_none(self):
        assert _www_variant("a.b.example.com") is None

    def test_www_subdomain_one_level_supported(self):
        # "www.acme.co.uk" -> 4 labels, neither apex nor www-of-apex pattern.
        assert _www_variant("www.acme.co.uk") is None
