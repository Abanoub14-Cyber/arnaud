"""Tests for the RDAP module's pure helpers (no network).

The bootstrap fetcher and full module integration are exercised via the
orchestrator integration test that mocks `_fetch_json` per call.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from apps.maketrust.scanner import rdap


# --- _parse_event_date ---------------------------------------------------

class TestParseEventDate:
    def test_finds_registration(self):
        events = [
            {"eventAction": "registration", "eventDate": "2020-01-15T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2030-01-15T00:00:00Z"},
        ]
        d = rdap._parse_event_date(events, "registration")
        assert d is not None
        assert d.year == 2020 and d.month == 1 and d.day == 15

    def test_finds_expiration(self):
        events = [{"eventAction": "expiration", "eventDate": "2030-01-15T00:00:00Z"}]
        d = rdap._parse_event_date(events, "expiration")
        assert d is not None and d.year == 2030

    def test_missing_returns_none(self):
        assert rdap._parse_event_date([], "registration") is None

    def test_malformed_skipped(self):
        events = [{"eventAction": "registration", "eventDate": "not-a-date"}]
        assert rdap._parse_event_date(events, "registration") is None

    def test_case_insensitive_action(self):
        events = [{"eventAction": "Registration", "eventDate": "2020-01-15T00:00:00Z"}]
        assert rdap._parse_event_date(events, "registration") is not None


# --- _registrar_name -----------------------------------------------------

class TestRegistrarName:
    def test_extracts_from_vcard_fn(self):
        entities = [{
            "roles": ["registrar"],
            "vcardArray": ["vcard", [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "Acme Registrar Inc."],
            ]],
        }]
        assert rdap._registrar_name(entities) == "Acme Registrar Inc."

    def test_falls_back_to_handle(self):
        entities = [{"roles": ["registrar"], "handle": "ACME-1"}]
        assert rdap._registrar_name(entities) == "ACME-1"

    def test_skips_non_registrar(self):
        entities = [
            {"roles": ["registrant"], "handle": "OWNER-1"},
            {"roles": ["registrar"], "handle": "REG-1"},
        ]
        assert rdap._registrar_name(entities) == "REG-1"

    def test_empty(self):
        assert rdap._registrar_name([]) == ""


# --- _bootstrap_for_tld --------------------------------------------------

@pytest.fixture(autouse=True)
def _no_cache_between_tests():
    from django.core.cache import cache
    cache.delete(rdap.BOOTSTRAP_CACHE_KEY)


class TestBootstrap:
    def test_returns_https_url_for_known_tld(self):
        with mock.patch.object(rdap, "_fetch_json", return_value={
            "services": [
                [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
                [["be"], ["https://rdap.dnsbelgium.be/"]],
            ],
        }):
            base = rdap._bootstrap_for_tld("be")
            assert base == "https://rdap.dnsbelgium.be/"

    def test_returns_none_for_unknown_tld(self):
        with mock.patch.object(rdap, "_fetch_json", return_value={
            "services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]],
        }):
            assert rdap._bootstrap_for_tld("zzz") is None

    def test_returns_none_when_iana_unreachable(self):
        with mock.patch.object(rdap, "_fetch_json", return_value=None):
            assert rdap._bootstrap_for_tld("com") is None


# --- Module integration --------------------------------------------------

class TestRdapModuleIntegration:
    def _mock_fetch(self, body):
        """Build a side_effect that returns bootstrap, then the per-domain body."""
        bootstrap = {
            "services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]],
        }
        return mock.patch.object(
            rdap, "_fetch_json",
            side_effect=[bootstrap, body],
        )

    def test_expiry_ok(self):
        from apps.maketrust.scanner.base import ScanContext
        future = datetime.now(timezone.utc) + timedelta(days=200)
        body = {
            "events": [
                {"eventAction": "registration", "eventDate": "2018-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": future.isoformat()},
            ],
            "entities": [{"roles": ["registrar"], "handle": "REG-1"}],
        }
        with self._mock_fetch(body):
            ctx = ScanContext(domain="example.com", public_ips=["1.1.1.1"])
            results = rdap.RdapModule().run(ctx)
            assert any(r.title_key == "rdap.expiry_ok" for r in results)

    def test_expiring_soon(self):
        from apps.maketrust.scanner.base import ScanContext
        soon = datetime.now(timezone.utc) + timedelta(days=10)
        body = {
            "events": [
                {"eventAction": "registration", "eventDate": "2018-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": soon.isoformat()},
            ],
            "entities": [],
        }
        with self._mock_fetch(body):
            ctx = ScanContext(domain="example.com", public_ips=["1.1.1.1"])
            results = rdap.RdapModule().run(ctx)
            assert any(r.title_key == "rdap.expiring_soon" for r in results)
            assert any(r.severity == "high" for r in results)

    def test_recently_registered(self):
        from apps.maketrust.scanner.base import ScanContext
        recent = datetime.now(timezone.utc) - timedelta(days=10)
        future = datetime.now(timezone.utc) + timedelta(days=300)
        body = {
            "events": [
                {"eventAction": "registration", "eventDate": recent.isoformat()},
                {"eventAction": "expiration", "eventDate": future.isoformat()},
            ],
            "entities": [],
        }
        with self._mock_fetch(body):
            ctx = ScanContext(domain="example.com", public_ips=["1.1.1.1"])
            results = rdap.RdapModule().run(ctx)
            assert any(r.title_key == "rdap.recently_registered" for r in results)

    def test_unsupported_tld_emits_info(self):
        from apps.maketrust.scanner.base import ScanContext
        with mock.patch.object(rdap, "_fetch_json", return_value={"services": []}):
            ctx = ScanContext(domain="example.zzz", public_ips=["1.1.1.1"])
            results = rdap.RdapModule().run(ctx)
            assert len(results) == 1
            assert results[0].title_key == "rdap.unavailable"
            assert results[0].severity == "info"
