"""Tests for cookie security checks in http_headers (W2)."""
from __future__ import annotations

from apps.maketrust.scanner.http_headers import (
    _cookie_findings,
    _split_cookies,
)


class TestSplitCookies:
    def test_single_cookie(self):
        assert _split_cookies("session=abc; Path=/; Secure") == ["session=abc; Path=/; Secure"]

    def test_two_cookies_simple(self):
        blob = "a=1; Path=/, b=2; Path=/"
        assert _split_cookies(blob) == ["a=1; Path=/", "b=2; Path=/"]

    def test_does_not_split_inside_expires(self):
        blob = "session=abc; Expires=Wed, 21 Oct 2025 07:28:00 GMT; Path=/"
        # Should remain ONE cookie even though there are commas in Expires.
        assert _split_cookies(blob) == [blob]

    def test_two_cookies_with_expires(self):
        blob = (
            "a=1; Expires=Wed, 21 Oct 2025 07:28:00 GMT; Path=/, "
            "b=2; Path=/"
        )
        parts = _split_cookies(blob)
        assert len(parts) == 2
        assert parts[0].startswith("a=1")
        assert parts[1].startswith("b=2")


class TestCookieFlags:
    def test_all_flags_set_returns_pass(self):
        results = _cookie_findings("session=abc; Secure; HttpOnly; SameSite=Lax")
        assert any(r.title_key == "cookies.ok" for r in results)
        assert all(r.severity == "pass" for r in results)

    def test_missing_secure_is_high(self):
        results = _cookie_findings("session=abc; HttpOnly; SameSite=Lax")
        assert any(r.title_key == "cookies.no_secure" and r.severity == "high"
                   for r in results)

    def test_missing_httponly_is_low(self):
        results = _cookie_findings("session=abc; Secure; SameSite=Lax")
        assert any(r.title_key == "cookies.no_httponly" and r.severity == "low"
                   for r in results)

    def test_missing_samesite_is_low(self):
        results = _cookie_findings("session=abc; Secure; HttpOnly")
        assert any(r.title_key == "cookies.no_samesite" and r.severity == "low"
                   for r in results)

    def test_consent_cookie_no_httponly_warning(self):
        # Consent cookies legitimately need to be JS-readable.
        results = _cookie_findings("cookielawinfo-checkbox=yes; Secure; SameSite=Lax")
        assert not any(r.title_key == "cookies.no_httponly" for r in results)

    def test_no_cookies_returns_empty(self):
        assert _cookie_findings("") == []

    def test_cap_at_ten_cookies(self):
        blob = ", ".join(f"c{i}=x; Secure; HttpOnly; SameSite=Lax" for i in range(20))
        results = _cookie_findings(blob)
        # cookies.ok is one finding because all are correctly set.
        assert len(results) == 1
        assert results[0].title_key == "cookies.ok"
        # The evidence claims 10 cookies inspected, not 20.
        assert "10 cookie" in results[0].evidence
