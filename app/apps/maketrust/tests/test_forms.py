"""Tests for ScanForm: validation, blocklist, per-domain cap."""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.maketrust.forms import BLOCKLIST, MAX_SCANS_PER_IP_24H, ScanForm
from apps.maketrust.models import Scan


pytestmark = pytest.mark.django_db


class TestDomainValidation:
    def test_valid_domain_passes(self):
        # acme.org is not on the blocklist; example.* is.
        form = ScanForm(data={"domain": "acme.org"})
        assert form.is_valid(), form.errors
        assert form.cleaned_data["domain"] == "acme.org"

    def test_invalid_domain_rejected(self):
        form = ScanForm(data={"domain": "not a domain"})
        assert not form.is_valid()
        assert "domain" in form.errors


class TestEmailInput:
    """The domain field also accepts `user@domain.tld` — useful for email-only
    domains where the user thinks in terms of their email address."""

    def test_simple_email_extracts_domain(self):
        form = ScanForm(data={"domain": "arnaud@querinjean.be"})
        assert form.is_valid(), form.errors
        assert form.cleaned_data["domain"] == "querinjean.be"

    def test_email_with_plus_extracts_domain(self):
        form = ScanForm(data={"domain": "me+filter@example.org"})
        # example.org is blocked but the domain extraction still happens first.
        assert not form.is_valid()
        # Confirm it failed for blocklist reason, not "invalid":
        assert any("publiquement" in str(e) for e in form.errors["domain"])

    def test_pathological_double_at_takes_tail(self):
        form = ScanForm(data={"domain": "a@b@acme.org"})
        assert form.is_valid(), form.errors
        assert form.cleaned_data["domain"] == "acme.org"

    def test_whitespace_around_email_is_trimmed(self):
        form = ScanForm(data={"domain": "  arnaud@acme.org  "})
        assert form.is_valid(), form.errors
        assert form.cleaned_data["domain"] == "acme.org"


class TestDisposableEmailBlocklist:
    """Disposable / throwaway email providers are refused for the email-gate."""

    def test_legit_email_passes(self):
        form = ScanForm(
            data={"domain": "acme.org", "email": "arnaud@acme.org"},
            email_required=True,
        )
        assert form.is_valid(), form.errors
        assert form.cleaned_data["email"] == "arnaud@acme.org"

    @pytest.mark.parametrize("addr", [
        "test@mailinator.com",
        "test@10minutemail.com",
        "test@guerrillamail.com",
        "test@yopmail.com",
        "test@tempmail.com",
        "test@sharklasers.com",
        "test@dispostable.com",
    ])
    def test_disposable_top_level_rejected(self, addr):
        form = ScanForm(
            data={"domain": "acme.org", "email": addr},
            email_required=True,
        )
        assert not form.is_valid()
        assert "email" in form.errors
        assert any("jetable" in str(e) for e in form.errors["email"])

    def test_disposable_subdomain_rejected(self):
        form = ScanForm(
            data={"domain": "acme.org", "email": "test@foo.mailinator.com"},
            email_required=True,
        )
        assert not form.is_valid()
        assert "email" in form.errors

    def test_empty_email_allowed_when_not_required(self):
        # Disposable check should not trip on an empty input.
        form = ScanForm(data={"domain": "acme.org", "email": ""})
        assert form.is_valid(), form.errors


class TestRescanFlag:
    """Hidden rescan field forces email-gate regardless of IP quota."""

    def test_rescan_forces_email_required(self):
        # Even with email_required=False (fresh IP), passing rescan=True
        # via initial should flip the gate on.
        form = ScanForm(
            initial={"domain": "acme.org", "rescan": True},
            email_required=False,
        )
        assert form.email_required is True
        assert form.is_rescan is True

    def test_rescan_post_submitted_forces_email(self):
        form = ScanForm(
            data={"domain": "acme.org", "rescan": "on", "email": ""},
            email_required=False,
        )
        # is_bound path: reads from self.data
        assert form.is_rescan is True
        assert not form.is_valid()
        assert "email" in form.errors

    def test_rescan_with_email_succeeds(self):
        form = ScanForm(
            data={"domain": "acme.org", "rescan": "on", "email": "me@acme.org"},
            email_required=False,
        )
        assert form.is_valid(), form.errors

    def test_no_rescan_keeps_optional_email(self):
        form = ScanForm(
            data={"domain": "acme.org", "email": ""},
            email_required=False,
        )
        assert form.is_rescan is False
        assert form.is_valid(), form.errors


class TestBlocklist:
    @pytest.mark.parametrize("d", sorted(BLOCKLIST))
    def test_each_blocklisted_domain_is_rejected(self, d):
        form = ScanForm(data={"domain": d})
        assert not form.is_valid()
        assert "domain" in form.errors

    def test_message_does_not_leak_blocklist(self):
        form = ScanForm(data={"domain": "example.com"})
        form.is_valid()
        assert any("publiquement" in str(e) for e in form.errors["domain"])


class TestProgressiveCooldown:
    """Per-IP / per-email rolling cooldown that ramps quadratically after a
    free tier of 2 scans / hour."""

    def _make_scans(self, n: int, *, ip_hash: str = "", email_hash: str = ""):
        # Spread scans out, with the most recent one *just now* so the
        # cooldown's elapsed time is ~0 and the delay applies fully.
        from apps.maketrust.models import Scan
        now = timezone.now()
        for i in range(n):
            Scan.objects.create(
                domain="acme.org",
                status=Scan.Status.DONE,
                requested_ip_hash=ip_hash,
                requested_email_hash=email_hash,
            )
        # Force the most recent queued_at to "right now" so the test isn't
        # racy on slow CI.
        Scan.objects.update(queued_at=now)

    def test_under_free_tier_no_delay(self):
        self._make_scans(2, ip_hash="abc")
        form = ScanForm(data={"domain": "acme.org"}, ip_hash="abc")
        assert form.is_valid(), form.errors
        assert form.get_cooldown_delay() == 0

    def test_third_scan_triggers_delay(self):
        self._make_scans(3, ip_hash="abc")
        form = ScanForm(data={"domain": "acme.org"}, ip_hash="abc")
        # Form stays VALID — cooldown is no longer a rejection, just a delay.
        assert form.is_valid(), form.errors
        assert form.get_cooldown_delay() > 0

    def test_delay_grows_with_count(self):
        from apps.maketrust.forms import _progressive_cooldown_remaining
        from apps.maketrust.models import Scan

        ip = "growing"
        def seed(n):
            Scan.objects.filter(requested_ip_hash=ip).delete()
            self._make_scans(n, ip_hash=ip)

        seed(3)
        d3 = _progressive_cooldown_remaining(ip)
        seed(5)
        d5 = _progressive_cooldown_remaining(ip)
        seed(8)
        d8 = _progressive_cooldown_remaining(ip)
        assert 0 < d3 < d5 < d8 <= 300

    def test_old_scans_dont_count(self):
        from apps.maketrust.models import Scan
        self._make_scans(5, ip_hash="abc")
        Scan.objects.update(queued_at=timezone.now() - timedelta(hours=2))
        form = ScanForm(data={"domain": "acme.org"}, ip_hash="abc")
        assert form.is_valid(), form.errors
        assert form.get_cooldown_delay() == 0

    def test_aborted_scans_dont_count(self):
        from apps.maketrust.models import Scan
        for _ in range(5):
            Scan.objects.create(
                domain="acme.org", status=Scan.Status.ABORTED,
                requested_ip_hash="abc",
            )
        Scan.objects.update(queued_at=timezone.now())
        form = ScanForm(data={"domain": "acme.org"}, ip_hash="abc")
        assert form.is_valid(), form.errors
        assert form.get_cooldown_delay() == 0

    def test_no_ip_no_email_no_check(self):
        self._make_scans(5, ip_hash="")
        form = ScanForm(data={"domain": "acme.org"}, ip_hash="")
        assert form.is_valid(), form.errors
        assert form.get_cooldown_delay() == 0

    def test_staff_skips_cooldown(self):
        # Authenticated Django admins bypass all rate-limits.
        self._make_scans(8, ip_hash="some-staff-hash")
        form = ScanForm(
            data={"domain": "acme.org"},
            ip_hash="some-staff-hash",
            is_staff=True,
        )
        assert form.is_valid(), form.errors
        assert form.get_cooldown_delay() == 0


class TestPerIPCap:
    """Single cap: 10 scans / IP / 24h across all domains. Subsumes any
    per-(IP, domain) cap because hitting N scans on one domain implies N
    scans for that IP."""

    def _seed(self, n: int, ip_hash: str = "spray", domain_prefix: str = "target"):
        from apps.maketrust.models import Scan
        for i in range(n):
            Scan.objects.create(
                domain=f"{domain_prefix}{i}.com",
                status=Scan.Status.DONE,
                requested_ip_hash=ip_hash,
            )

    def test_under_cap_passes(self):
        self._seed(MAX_SCANS_PER_IP_24H - 1)
        form = ScanForm(data={"domain": "newtarget.com"}, ip_hash="spray")
        assert form.is_valid()

    def test_at_cap_rejected_with_contact_message(self):
        self._seed(MAX_SCANS_PER_IP_24H)
        form = ScanForm(data={"domain": "newtarget.com"}, ip_hash="spray")
        assert not form.is_valid()
        msg = " ".join(str(e) for e in form.errors.get("domain", []))
        assert "limite" in msg.lower()
        assert "contact" in msg.lower()

    def test_at_cap_allows_other_ips_through(self):
        # An attacker spent their 10 scans. A legitimate visitor from a
        # different IP must still be able to scan.
        self._seed(MAX_SCANS_PER_IP_24H)
        form = ScanForm(data={"domain": "newtarget.com"}, ip_hash="legit")
        assert form.is_valid(), form.errors

    def test_aborted_scans_dont_count(self):
        from apps.maketrust.models import Scan
        for i in range(MAX_SCANS_PER_IP_24H):
            Scan.objects.create(
                domain=f"x{i}.com", status=Scan.Status.ABORTED,
                requested_ip_hash="spray",
            )
        form = ScanForm(data={"domain": "newtarget.com"}, ip_hash="spray")
        assert form.is_valid()

    def test_old_scans_dont_count(self):
        from apps.maketrust.models import Scan
        self._seed(MAX_SCANS_PER_IP_24H)
        Scan.objects.filter(requested_ip_hash="spray").update(
            queued_at=timezone.now() - timedelta(hours=25),
        )
        form = ScanForm(data={"domain": "newtarget.com"}, ip_hash="spray")
        assert form.is_valid()

    def test_staff_bypass(self):
        self._seed(MAX_SCANS_PER_IP_24H + 3)
        form = ScanForm(
            data={"domain": "newtarget.com"}, ip_hash="spray", is_staff=True,
        )
        assert form.is_valid()
