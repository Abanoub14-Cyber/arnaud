"""Batch domain scanner intended for trusted shell use.

Reads a JSON list of ``{"domain": "..."}`` entries, runs every scanner module
against each domain (skipping the public-facing email gate and rate-limits),
and writes back a JSON list with ``scan_id``, ``score``, ``top_finding``
and a deep-link ``url`` per entry.

Usage:

    docker exec makeset python manage.py scan_domains \\
        --input /tmp/in.json --output /tmp/out.json

This command is the bridge for the Prospect CRM: it dumps the prospects'
websites into ``in.json``, calls this command via ``docker cp``, then
imports ``out.json`` to enrich each Prospect with its security posture.

Failure isolation: one bad record (invalid domain, blocked, orchestrator
crash) is written to ``out.json`` as ``{"domain": "...", "error": "..."}``
and the batch continues. The command's exit status only reflects fatal
issues like an unreadable input file.

Idempotency inside a single run: if the same domain is listed twice the
scanner runs once and both output rows carry the same ``scan_id``. To
re-scan an already-scanned domain across runs, just call again - we
always create a fresh Scan row per invocation (no historical lookup).
"""
from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.urls import reverse

from apps.maketrust.findings import FINDINGS
from apps.maketrust.forms import BLOCKLIST
from apps.maketrust.models import Check, Scan
from apps.maketrust.scanner.orchestrator import run_scan
from apps.maketrust.scanner.safety import DomainValidationError, validate_domain

# Public site URL we prefix to the scan_result path so the output is a
# clickable link from the Prospect CRM. Overridable for staging/local via
# the MAKESET_PUBLIC_BASE_URL setting, but the command shouldn't crash if
# it isn't set - we just emit a relative URL in that case.
_DEFAULT_PUBLIC_BASE_URL = "https://makeset.be"


def _public_base_url() -> str:
    from django.conf import settings
    return getattr(settings, "MAKESET_PUBLIC_BASE_URL", _DEFAULT_PUBLIC_BASE_URL)


def _scan_url(scan: Scan) -> str:
    path = reverse("maketrust:scan_result", kwargs={"scan_id": scan.id})
    base = _public_base_url().rstrip("/")
    return f"{base}{path}"


def _top_finding(scan: Scan) -> str:
    """Translated title of the highest-severity finding on ``scan``.

    Tiebreak: lowest Check.id (module emission order). Returns "" when the
    scan has no Check rows at all (e.g. orchestrator failed before persisting).
    """
    sev_order = Check.SEVERITY_ORDER
    checks = list(Check.objects.filter(scan=scan).only("severity", "title_key", "id"))
    if not checks:
        return ""
    # Skip PASS findings - they're not "top" anything, they're just noise
    # when used as a personalisation hook for a cold email.
    actionable = [c for c in checks if c.severity != Check.Severity.PASS]
    pool = actionable or checks
    pool.sort(key=lambda c: (sev_order.get(c.severity, 99), c.id))
    top = pool[0]
    info = FINDINGS.get(top.title_key)
    if info is None:
        return top.title_key
    return str(info["title"])


def _run_one(domain: str) -> Scan:
    """Create a new admin-flagged Scan and run the orchestrator inline."""
    scan = Scan.objects.create(
        domain=domain,
        status=Scan.Status.QUEUED,
        is_internal=True,
        # Empty hashes - the command is shell-driven, no end-user IP/email.
        requested_ip_hash="",
        requested_email_hash="",
    )
    run_scan(str(scan.id))
    scan.refresh_from_db()
    return scan


class Command(BaseCommand):
    help = "Batch-scan domains. Reads --input JSON, writes results to --output JSON."

    def add_arguments(self, parser):
        parser.add_argument("--input", required=True, help="Path to input JSON")
        parser.add_argument("--output", required=True, help="Path to output JSON")

    def handle(self, *args, **opts):
        in_path = Path(opts["input"])
        out_path = Path(opts["output"])
        if not in_path.exists():
            raise CommandError(f"Input file not found: {in_path}")
        try:
            raw = json.loads(in_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise CommandError(f"Input file is not valid JSON: {exc}") from exc
        if not isinstance(raw, list):
            raise CommandError("Input must be a JSON list of objects")

        # Domain -> already-completed Scan, used for intra-run dedup. We key
        # by the *validated* domain string so casing / trailing dot variations
        # of the same host collapse to one scan.
        seen: dict[str, Scan] = {}
        results: list[dict] = []

        for entry in raw:
            raw_domain = (entry or {}).get("domain", "") if isinstance(entry, dict) else ""
            results.append(self._process_one(raw_domain, seen))

        out_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
        self.stdout.write(self.style.SUCCESS(
            f"Wrote {len(results)} record(s) to {out_path}"
        ))

    def _process_one(self, raw_domain: str, seen: dict[str, Scan]) -> dict:
        if not raw_domain:
            return {"domain": raw_domain, "error": "empty domain"}
        try:
            domain = validate_domain(raw_domain)
        except DomainValidationError as exc:
            return {"domain": raw_domain, "error": f"invalid domain: {exc}"}

        if domain in BLOCKLIST:
            return {
                "domain": domain,
                "error": "domain is on the public blocklist (RFC 2606 reserved)",
            }

        cached = seen.get(domain)
        if cached is not None:
            return self._format_result(cached)

        try:
            scan = _run_one(domain)
        except Exception as exc:  # safety net: keep the batch alive
            return {
                "domain": domain,
                "error": f"{exc.__class__.__name__}: {exc}",
            }

        seen[domain] = scan

        if scan.status == Scan.Status.FAILED:
            return {
                "domain": domain,
                "scan_id": str(scan.id),
                "error": scan.error_message or "scan failed",
                "url": _scan_url(scan),
            }

        return self._format_result(scan)

    def _format_result(self, scan: Scan) -> dict:
        return {
            "domain": scan.domain,
            "scan_id": str(scan.id),
            "score": scan.overall_score,
            "top_finding": _top_finding(scan),
            "url": _scan_url(scan),
        }
