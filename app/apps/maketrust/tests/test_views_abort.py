"""Tests for the abort flow.

Authorisation rule: only the IP that submitted the scan can cancel it.
We compare hashed IPs (the same hash the middleware would produce) so the
test seeds the Scan row with a hash matching what the test client sends.
"""
from __future__ import annotations

import pytest
from django.urls import reverse

from apps.maketrust.models import Scan
from apps.website.middleware import hash_ip


pytestmark = pytest.mark.django_db


@pytest.fixture
def scan_with_ip():
    """A queued scan tied to 1.2.3.4 (hashed)."""
    return Scan.objects.create(
        domain="example.org",
        status=Scan.Status.QUEUED,
        requested_ip_hash=hash_ip("1.2.3.4"),
    )


def _abort_url(scan):
    return reverse("maketrust:scan_abort", kwargs={"scan_id": scan.id})


class TestAbortAuth:
    def test_correct_ip_can_abort(self, client, scan_with_ip):
        resp = client.post(_abort_url(scan_with_ip), REMOTE_ADDR="1.2.3.4")
        scan_with_ip.refresh_from_db()
        assert scan_with_ip.status == Scan.Status.ABORTED
        # Without HX-Request, we get a 302 redirect.
        assert resp.status_code in (302, 303)

    def test_other_ip_cannot_abort(self, client, scan_with_ip):
        resp = client.post(_abort_url(scan_with_ip), REMOTE_ADDR="9.9.9.9")
        scan_with_ip.refresh_from_db()
        assert scan_with_ip.status == Scan.Status.QUEUED
        assert resp.status_code == 403

    def test_get_not_allowed(self, client, scan_with_ip):
        resp = client.get(_abort_url(scan_with_ip), REMOTE_ADDR="1.2.3.4")
        assert resp.status_code == 405


class TestAbortIdempotency:
    def test_abort_already_done_redirects(self, client, scan_with_ip):
        scan_with_ip.status = Scan.Status.DONE
        scan_with_ip.save()
        resp = client.post(_abort_url(scan_with_ip), REMOTE_ADDR="1.2.3.4")
        scan_with_ip.refresh_from_db()
        assert scan_with_ip.status == Scan.Status.DONE
        assert resp.status_code in (302, 303)

    def test_abort_already_aborted_does_not_double_save(self, client, scan_with_ip):
        scan_with_ip.status = Scan.Status.ABORTED
        scan_with_ip.save()
        resp = client.post(_abort_url(scan_with_ip), REMOTE_ADDR="1.2.3.4")
        scan_with_ip.refresh_from_db()
        assert scan_with_ip.status == Scan.Status.ABORTED


class TestAbortHTMX:
    def test_htmx_request_returns_partial(self, client, scan_with_ip):
        resp = client.post(
            _abort_url(scan_with_ip),
            REMOTE_ADDR="1.2.3.4",
            HTTP_HX_REQUEST="true",
        )
        assert resp.status_code == 200
        body = resp.content.decode("utf-8")
        assert "scan-progress" in body
