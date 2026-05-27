"""Tests for the SPF+DKIM+DMARC -> single verdict synthesis.

Drives `_spoof_synthesis` directly through a synthetic ScanContext so we
don't need DNS access.
"""
from __future__ import annotations

from apps.maketrust.scanner.base import ScanContext
from apps.maketrust.scanner.dmarc import _spoof_synthesis


def _ctx(spf: str | None, dkim: bool, dmarc_tags: dict | None) -> ScanContext:
    cache: dict = {}
    if spf is not None:
        cache["SPF"] = [f"v=spf1 include:_spf.example.com {spf}"]
    cache["DKIM_FOUND"] = dkim
    if dmarc_tags is not None:
        cache["DMARC"] = dmarc_tags
    return ScanContext(domain="example.com", public_ips=["1.2.3.4"], dns_cache=cache)


class TestSpoofResistant:
    def test_full_lockdown(self):
        tags = {"p": "reject", "aspf": "s", "adkim": "s"}
        r = _spoof_synthesis(_ctx("-all", True, tags), tags)
        assert r.severity == "pass"
        assert r.title_key == "email.synth_spoof_resistant"


class TestModerate:
    def test_reject_with_dkim_but_softfail(self):
        tags = {"p": "reject"}
        r = _spoof_synthesis(_ctx("~all", True, tags), tags)
        assert r.title_key == "email.synth_moderate"

    def test_quarantine_with_dkim(self):
        tags = {"p": "quarantine"}
        r = _spoof_synthesis(_ctx("-all", True, tags), tags)
        assert r.title_key == "email.synth_moderate"
        assert r.severity == "medium"


class TestWeak:
    def test_p_none(self):
        tags = {"p": "none"}
        r = _spoof_synthesis(_ctx("-all", True, tags), tags)
        assert r.title_key == "email.synth_weak"
        assert r.severity == "high"


class TestSpoofable:
    def test_no_dmarc(self):
        r = _spoof_synthesis(_ctx("-all", True, {}), {})
        assert r.title_key == "email.synth_spoofable"
        assert r.severity == "critical"

    def test_no_dmarc_no_spf_no_dkim(self):
        r = _spoof_synthesis(_ctx(None, False, {}), {})
        assert r.title_key == "email.synth_spoofable"

    def test_permissive_spf_no_dkim_with_dmarc_invalid(self):
        # DMARC tags with no policy = invalid -> dmarc_p == ""
        r = _spoof_synthesis(_ctx("+all", False, {}), {})
        assert r.title_key == "email.synth_spoofable"
