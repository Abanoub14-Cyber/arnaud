"""Run all modules against a single Scan, persist findings, compute score.

Entry point ``run_scan(scan_id)`` is what django-q2 invokes from the queue.
Modules are invoked sequentially — they're all I/O-bound and the longest
ones (TLS handshake, HTTPS GET) finish in <2s, so threading would buy us
0.5s at the cost of unpredictable error handling.

Cooperative cancellation: between every module, we re-read the Scan row.
If a user clicked "Abort" through the progress page, the row's status is
flipped to ABORTED, and we persist what we have and exit.
"""
from __future__ import annotations

import logging
import time
import traceback

from django.utils import timezone

from .base import (
    CheckResult, Module, ScanContext, SEV_CRITICAL,
)
from .safety import resolve_public_ips


logger = logging.getLogger(__name__)


def _registered_modules() -> list[type[Module]]:
    """Return module classes in the order we want them to run.

    Imported lazily so the orchestrator module stays cheap to import (the
    queue worker imports it on every task pick-up).

    site_profile runs first — it owns the homepage HTTPS fetch and stashes
    the response so http_headers can reuse it. rdap runs last — it's a
    pure metadata lookup with no dependencies.
    """
    from . import (
        breach_domain, dkim, dmarc, dns_basics, dnssec,
        http_headers, http_redirect, rdap, site_profile, spf, tls_cert,
    )
    return [
        site_profile.SiteProfileModule,
        dns_basics.DnsBasicsModule,
        dnssec.DnssecModule,
        spf.SpfModule,
        dkim.DkimModule,
        dmarc.DmarcModule,
        tls_cert.TlsCertModule,
        http_redirect.HttpRedirectModule,
        http_headers.HttpHeadersModule,
        breach_domain.BreachDomainModule,
        rdap.RdapModule,
    ]


def registered_module_slugs() -> list[str]:
    """Public accessor for the views — keeps the order used in the UI in sync."""
    return [cls.slug for cls in _registered_modules()]


def _scan_was_aborted(scan_id: str) -> bool:
    """Cheap one-row read used between modules for cooperative cancel."""
    from apps.maketrust.models import Scan
    return Scan.objects.filter(id=scan_id, status=Scan.Status.ABORTED).exists()


def run_scan(scan_id: str) -> str:
    """Execute every module against ``scan.domain`` and store results."""
    from apps.maketrust.models import Check, Scan
    from apps.maketrust.scoring import compute_grade, compute_summary

    scan_started_at = time.perf_counter()
    scan = Scan.objects.get(id=scan_id)

    # Honour an abort issued before the worker picked the task up.
    if scan.status == Scan.Status.ABORTED:
        logger.info(
            "scan_aborted_pre_start scan_id=%s domain=%s",
            scan.id, scan.domain,
        )
        return f"aborted-pre-start {scan.id}"

    logger.info(
        "scan_start scan_id=%s domain=%s ip_prefix=%s is_internal=%s "
        "scheduled_for=%s extra_dkim_selectors=%s",
        scan.id, scan.domain,
        (scan.requested_ip_hash or "")[:12], scan.is_internal,
        scan.scheduled_for.isoformat() if scan.scheduled_for else "-",
        scan.extra_dkim_selectors or "-",
    )

    # Cooldown: if the scan was scheduled in the future, wait until then.
    # Re-check the abort flag every second so the user can still cancel
    # during the wait. Capped defensively at 600s.
    if scan.scheduled_for:
        import time as _time
        deadline = scan.scheduled_for
        while True:
            now = timezone.now()
            remaining = (deadline - now).total_seconds()
            if remaining <= 0:
                break
            if remaining > 600:
                remaining = 600  # safety clamp
            _time.sleep(min(remaining, 1.0))
            # Refresh abort state from DB cheaply.
            if _scan_was_aborted(scan_id):
                return f"aborted-during-cooldown {scan.id}"

    scan.status = Scan.Status.RUNNING
    scan.started_at = timezone.now()
    scan.save(update_fields=["status", "started_at"])

    try:
        ips = resolve_public_ips(scan.domain)
        if not ips:
            scan.status = Scan.Status.FAILED
            scan.finished_at = timezone.now()
            scan.error_message = "DNS resolution returned no public IP"
            Check.objects.create(
                scan=scan,
                module="dns_basics",
                severity=SEV_CRITICAL,
                title_key="dns.no_public_ip",
                fix_key="dns.fix_no_public_ip",
                evidence="No A/AAAA record resolves to a public IP.",
            )
            scan.save()
            return scan.error_message

        # Pre-seed the dns_cache with the user-supplied DKIM selectors, if
        # any. The DKIM module reads this key to extend its built-in
        # COMMON_SELECTORS list.
        extra_selectors = [
            s for s in (scan.extra_dkim_selectors or "").split(",") if s.strip()
        ]
        ctx = ScanContext(
            domain=scan.domain,
            public_ips=ips,
            dns_cache={"EXTRA_DKIM_SELECTORS": extra_selectors},
        )

        check_rows: list[Check] = []
        aborted = False
        for cls in _registered_modules():
            # Cooperative cancellation: bail before starting any new module
            # if the user has clicked Abort.
            if _scan_was_aborted(scan_id):
                aborted = True
                break

            mod = cls()
            t0 = time.perf_counter()
            try:
                results: list[CheckResult] = mod.run(ctx)
            except Exception as exc:
                logger.exception(
                    "scanner_module_crashed scan_id=%s domain=%s "
                    "scanner_module=%s exc_class=%s",
                    scan_id, scan.domain, mod.slug, exc.__class__.__name__,
                )
                results = [CheckResult(
                    severity="info",
                    title_key="module.crashed",
                    evidence=f"{exc.__class__.__name__}: {exc}".strip(),
                )]
            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            logger.info(
                "scanner_module_done scan_id=%s domain=%s scanner_module=%s "
                "duration_ms=%d findings=%d severities=%s",
                scan_id, scan.domain, mod.slug, elapsed_ms, len(results),
                ",".join(sorted(set(r.severity for r in results))),
            )
            for r in results:
                check_rows.append(Check(
                    scan=scan,
                    module=mod.slug,
                    severity=r.severity,
                    title_key=r.title_key,
                    fix_key=r.fix_key,
                    finding=r.finding,
                    evidence=r.evidence[:5000],
                    duration_ms=elapsed_ms,
                ))

        Check.objects.bulk_create(check_rows)

        total_duration_ms = int((time.perf_counter() - scan_started_at) * 1000)

        if aborted:
            # Reload to keep the user-set status. Persist whatever findings we
            # already have so the partial report is still readable.
            scan.refresh_from_db(fields=["status"])
            scan.summary = compute_summary(check_rows)
            scan.preview_image_url = ctx.dns_cache.get("preview_image_url", "") or ""
            scan.preview_title = ctx.dns_cache.get("preview_title", "") or ""
            scan.finished_at = timezone.now()
            scan.save()
            logger.info(
                "scan_aborted scan_id=%s domain=%s duration_ms=%d "
                "modules_completed=%d",
                scan.id, scan.domain, total_duration_ms,
                len({c.module for c in check_rows}),
            )
            return f"aborted {scan.id}"

        score, grade = compute_grade(check_rows, _registered_modules())
        scan.overall_score = score
        scan.grade = grade
        scan.summary = compute_summary(check_rows)
        scan.preview_image_url = ctx.dns_cache.get("preview_image_url", "") or ""
        scan.preview_title = ctx.dns_cache.get("preview_title", "") or ""
        scan.status = Scan.Status.DONE
        scan.finished_at = timezone.now()
        scan.save()
        logger.info(
            "scan_done scan_id=%s domain=%s ip_prefix=%s is_internal=%s "
            "grade=%s score=%d duration_ms=%d summary=%s",
            scan.id, scan.domain,
            (scan.requested_ip_hash or "")[:12], scan.is_internal,
            grade, score, total_duration_ms, scan.summary,
        )
        return f"done {scan.id} grade={grade} score={score}"

    except Exception as exc:  # safety net
        logger.exception(
            "scan_failed scan_id=%s domain=%s exc_class=%s",
            scan_id, scan.domain, exc.__class__.__name__,
        )
        scan.status = Scan.Status.FAILED
        scan.finished_at = timezone.now()
        scan.error_message = (
            f"{exc.__class__.__name__}: {exc}\n"
            + traceback.format_exc()[-1000:]
        )
        scan.save()
        return f"failed {scan.id}"
