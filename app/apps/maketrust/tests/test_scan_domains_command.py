"""Tests for the ``scan_domains`` management command.

The command is the admin-only batch entry point used by other apps (e.g. the
Prospect CRM) to scan a list of domains and get back scan_id / score /
top_finding for each one. It bypasses the email gate and the per-IP cap
because it's invoked from a trusted shell, never from a web request.

The orchestrator (``run_scan``) is mocked: it has its own integration test
surface and the network it touches isn't available in unit tests. We assert
that the command:

* Builds one Scan row per input domain,
* Invokes run_scan once per Scan,
* Picks the highest-severity Check as ``top_finding``,
* Outputs a JSON list with the contract documented in the brief,
* Reports per-record errors without crashing the whole batch,
* De-duplicates intra-run repeats.
"""
from __future__ import annotations

import json
import uuid
from io import StringIO
from unittest import mock

import pytest
from django.core.management import call_command
from django.utils import timezone

from apps.maketrust.models import Check, Scan

pytestmark = pytest.mark.django_db


def _fake_run_scan_factory(per_domain):
    """Build a fake ``run_scan(scan_id)`` that populates the Scan + Checks.

    ``per_domain`` is ``{domain: {"score": int, "checks": [(severity, title_key), ...]}}``.
    """
    def fake_run_scan(scan_id):
        scan = Scan.objects.get(id=scan_id)
        spec = per_domain.get(scan.domain)
        if spec is None:
            scan.status = Scan.Status.FAILED
            scan.finished_at = timezone.now()
            scan.error_message = "no fake spec"
            scan.save()
            return f"failed {scan.id}"
        scan.overall_score = spec["score"]
        scan.grade = spec.get("grade", "C")
        scan.status = Scan.Status.DONE
        scan.finished_at = timezone.now()
        scan.save()
        for severity, title_key in spec["checks"]:
            Check.objects.create(
                scan=scan, module="dmarc",
                severity=severity, title_key=title_key,
            )
        return f"done {scan.id}"

    return fake_run_scan


def _write_input(tmp_path, payload):
    path = tmp_path / "in.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _read_output(path):
    return json.loads(path.read_text(encoding="utf-8"))


class TestScanDomainsHappyPath:
    def test_single_domain_returns_scan_id_score_and_top_finding(self, tmp_path):
        spec = {
            "good.be": {
                "score": 78,
                "checks": [
                    ("medium", "dmarc.missing"),
                    ("low", "spf.policy_soft"),
                ],
            },
        }
        input_path = _write_input(tmp_path, [{"domain": "good.be"}])
        output_path = tmp_path / "out.json"

        with mock.patch(
            "apps.maketrust.management.commands.scan_domains.run_scan",
            side_effect=_fake_run_scan_factory(spec),
        ):
            call_command(
                "scan_domains",
                "--input", str(input_path),
                "--output", str(output_path),
                stdout=StringIO(),
            )

        result = _read_output(output_path)
        assert len(result) == 1
        entry = result[0]
        assert entry["domain"] == "good.be"
        assert entry["score"] == 78
        # Highest severity finding ("medium" > "low") becomes top_finding.
        # We don't assert the exact translated string here (varies with locale)
        # but it must be a non-empty user-facing string, NOT the raw key.
        assert entry["top_finding"]
        assert "." not in entry["top_finding"][:20]  # not the slug
        # scan_id is the Scan's UUID, as a string.
        uuid.UUID(entry["scan_id"])
        assert "scan/" in entry["url"]
        assert entry["scan_id"] in entry["url"]


class TestScanDomainsBlocklist:
    def test_blocklisted_example_dot_com_returns_error(self, tmp_path):
        input_path = _write_input(tmp_path, [{"domain": "example.com"}])
        output_path = tmp_path / "out.json"

        with mock.patch(
            "apps.maketrust.management.commands.scan_domains.run_scan"
        ) as runner:
            call_command(
                "scan_domains",
                "--input", str(input_path),
                "--output", str(output_path),
                stdout=StringIO(),
            )
            runner.assert_not_called()

        result = _read_output(output_path)
        assert len(result) == 1
        assert result[0]["domain"] == "example.com"
        assert "error" in result[0]
        assert result[0]["error"]


class TestScanDomainsTopFindingSeverity:
    def test_picks_highest_severity_across_checks(self, tmp_path):
        spec = {
            "mix.be": {
                "score": 30,
                "checks": [
                    ("low", "spf.policy_soft"),
                    ("critical", "dmarc.missing"),
                    ("medium", "dns.no_caa"),
                    ("high", "tls_cert.expired"),
                ],
            },
        }
        input_path = _write_input(tmp_path, [{"domain": "mix.be"}])
        output_path = tmp_path / "out.json"

        with mock.patch(
            "apps.maketrust.management.commands.scan_domains.run_scan",
            side_effect=_fake_run_scan_factory(spec),
        ):
            call_command(
                "scan_domains",
                "--input", str(input_path),
                "--output", str(output_path),
                stdout=StringIO(),
            )

        result = _read_output(output_path)
        assert len(result) == 1
        # The "dmarc.missing" finding (critical) outranks the others. We assert
        # against the catalog directly rather than re-implementing it here so
        # the test stays insensitive to wording tweaks.
        from apps.maketrust.findings import FINDINGS
        expected = str(FINDINGS["dmarc.missing"]["title"])
        assert result[0]["top_finding"] == expected


class TestScanDomainsIdempotent:
    def test_same_domain_listed_twice_runs_once(self, tmp_path):
        spec = {
            "dup.be": {"score": 50, "checks": [("medium", "spf.missing")]},
        }
        input_path = _write_input(tmp_path, [
            {"domain": "dup.be"},
            {"domain": "dup.be"},
        ])
        output_path = tmp_path / "out.json"

        with mock.patch(
            "apps.maketrust.management.commands.scan_domains.run_scan",
            side_effect=_fake_run_scan_factory(spec),
        ) as runner:
            call_command(
                "scan_domains",
                "--input", str(input_path),
                "--output", str(output_path),
                stdout=StringIO(),
            )
            assert runner.call_count == 1

        result = _read_output(output_path)
        # Output still contains two entries (one per input row), but they
        # carry the same scan_id and score (the scan ran once and was reused).
        assert len(result) == 2
        assert result[0]["scan_id"] == result[1]["scan_id"]
        assert result[0]["score"] == result[1]["score"] == 50


class TestScanDomainsErrorIsolation:
    def test_one_bad_record_does_not_abort_the_batch(self, tmp_path):
        spec = {
            "ok.be": {"score": 80, "checks": [("low", "spf.policy_soft")]},
        }
        input_path = _write_input(tmp_path, [
            {"domain": "ok.be"},
            {"domain": ""},   # invalid: empty
            {"domain": "alsook.be"},
        ])
        # The fake_run_scan would crash on "alsook.be" because we didn't list
        # it in the spec — emulates an orchestrator failure. We map it via
        # a separate side_effect.
        spec["alsook.be"] = {"score": 65, "checks": [("info", "rdap.recent_registration")]}
        output_path = tmp_path / "out.json"

        with mock.patch(
            "apps.maketrust.management.commands.scan_domains.run_scan",
            side_effect=_fake_run_scan_factory(spec),
        ):
            call_command(
                "scan_domains",
                "--input", str(input_path),
                "--output", str(output_path),
                stdout=StringIO(),
            )

        result = _read_output(output_path)
        assert len(result) == 3
        # Middle one errored, the other two carry scores.
        assert result[0]["score"] == 80
        assert "error" in result[1]
        assert result[2]["score"] == 65


class TestScanDomainsInvalidInput:
    def test_missing_input_file_raises(self, tmp_path):
        from django.core.management.base import CommandError
        output_path = tmp_path / "out.json"
        with pytest.raises(CommandError):
            call_command(
                "scan_domains",
                "--input", str(tmp_path / "nope.json"),
                "--output", str(output_path),
                stdout=StringIO(),
            )
