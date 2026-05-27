from __future__ import annotations

from datetime import timedelta

from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.translation import get_language
from django.views.decorators.http import require_http_methods, require_POST
from django_q.tasks import async_task

from apps.website.middleware import hash_ip

from .forms import RescanForm, ScanForm, _ip_overscanned
from .models import Check, Scan


QUOTA_WINDOW = timedelta(hours=24)


def _ip_hit_quota(ip_hash: str) -> bool:
    """True iff this IP has already started a scan in the last 24h.

    The first scan is free with no email; the second one requires an email
    so we have a way to follow up. Quota is per real IP hash, not per email
    (an attacker can spin up disposable mailboxes; spinning up a fresh IP
    behind Cloudflare is meaningfully harder for our threat model). Aborted
    scans don't consume the quota.
    """
    if not ip_hash:
        return False
    cutoff = timezone.now() - QUOTA_WINDOW
    return Scan.objects.filter(
        requested_ip_hash=ip_hash,
        queued_at__gte=cutoff,
    ).exclude(status=Scan.Status.ABORTED).exists()


@require_http_methods(["GET", "POST"])
def landing(request):
    """Input form. POST creates the Scan, queues the task, redirects to /scan/<uuid>/progress/."""
    ip_hash = getattr(request, "real_ip_hash", "") or ""
    is_staff = bool(request.user.is_authenticated and request.user.is_staff)
    email_required = _ip_hit_quota(ip_hash) and not is_staff

    if request.method == "POST":
        form = ScanForm(request.POST, email_required=email_required,
                        ip_hash=ip_hash, is_staff=is_staff)
        if form.is_valid():
            email = form.cleaned_data.get("email", "")
            cooldown_seconds = form.get_cooldown_delay()
            scheduled_for = (
                timezone.now() + timedelta(seconds=cooldown_seconds)
                if cooldown_seconds > 0 else None
            )
            scan = Scan.objects.create(
                domain=form.cleaned_data["domain"],
                status=Scan.Status.QUEUED,
                requested_ip_hash=ip_hash,
                requested_email=email,
                requested_email_hash=hash_ip(email) if email else "",
                locale=get_language() or "fr",
                scheduled_for=scheduled_for,
                is_internal=is_staff,
            )
            async_task(
                "apps.maketrust.scanner.orchestrator.run_scan",
                str(scan.id),
                task_name=f"scan:{scan.domain}",
            )
            return redirect("maketrust:scan_progress", scan_id=scan.id)
    else:
        # Allow ?domain=... to pre-fill the form. Used by the "Relancer le
        # scan" button on the result page so the visitor lands here with the
        # previous domain already there and just needs to confirm. The form's
        # validators still apply; pre-fill is purely a UX shortcut, no trust
        # is placed in the query string. Bounded defensively.
        initial = {}
        prefill_domain = (request.GET.get("domain") or "").strip()[:253]
        if prefill_domain:
            initial["domain"] = prefill_domain
        # The rescan FAB sets ?rescan=1 — propagate it as initial so the
        # hidden form field round-trips through POST, and ScanForm sees it
        # to force email_required even on a fresh IP.
        if request.GET.get("rescan") == "1":
            initial["rescan"] = True
        form = ScanForm(initial=initial or None, email_required=email_required,
                        ip_hash=ip_hash, is_staff=is_staff)

    return render(request, "pages/maketrust/landing.html", {
        "form": form,
        "email_required": email_required,
    })


def _scan_or_404(scan_id) -> Scan:
    return get_object_or_404(Scan, id=scan_id, is_public=True)


def _module_progress(scan: Scan) -> list[dict]:
    """Build the per-module checklist the progress partial renders.

    Order matches the orchestrator: completed modules show ✓, the next one
    is "running", the rest are pending. We detect completion by the presence
    of at least one Check row for that module on this scan.
    """
    from .findings import get_module_label
    from .scanner.orchestrator import registered_module_slugs

    completed = set(
        Check.objects.filter(scan=scan).values_list("module", flat=True)
    )

    items: list[dict] = []
    next_running_assigned = False
    for slug in registered_module_slugs():
        label = get_module_label(slug)
        if slug in completed:
            state = "done"
        elif scan.status == Scan.Status.RUNNING and not next_running_assigned:
            state = "running"
            next_running_assigned = True
        else:
            state = "pending"
        items.append({"slug": slug, "title": label["title"],
                      "subtitle": label["subtitle"], "state": state})
    return items


def _seconds_until_start(scan: Scan) -> int:
    """Whole seconds before a scheduled scan is allowed to start. 0 when no
    schedule applies or the deadline has already passed."""
    if not scan.scheduled_for:
        return 0
    remaining = (scan.scheduled_for - timezone.now()).total_seconds()
    return max(0, int(remaining))


def scan_progress(request, scan_id):
    scan = _scan_or_404(scan_id)
    if scan.is_finished and scan.status != Scan.Status.ABORTED:
        return redirect("maketrust:scan_result", scan_id=scan.id)
    modules = _module_progress(scan)
    can_abort = (
        scan.status in (Scan.Status.QUEUED, Scan.Status.RUNNING)
        and getattr(request, "real_ip_hash", "") == (scan.requested_ip_hash or "")
        and bool(scan.requested_ip_hash)
    )
    return render(request, "pages/maketrust/scan_progress.html", {
        "scan": scan,
        "modules": modules,
        "done_count": sum(1 for m in modules if m["state"] == "done"),
        "total_count": len(modules),
        "position": 1,
        "can_abort": can_abort,
        "seconds_until_start": _seconds_until_start(scan),
    })


def scan_status_partial(request, scan_id):
    """HTMX poll endpoint. Returns either the progress partial or, when the
    scan is done, a small fragment that redirects the client to the result page."""
    scan = _scan_or_404(scan_id)
    if scan.status == Scan.Status.DONE:
        resp = HttpResponse("")
        resp["HX-Redirect"] = scan.get_absolute_url()
        return resp
    if scan.status == Scan.Status.FAILED:
        return render(request, "partials/maketrust/scan_failed.html", {"scan": scan})
    if scan.status == Scan.Status.ABORTED:
        return render(request, "partials/maketrust/scan_aborted.html", {"scan": scan})

    if scan.status == Scan.Status.QUEUED:
        ahead = Scan.objects.filter(
            status=Scan.Status.QUEUED, queued_at__lt=scan.queued_at,
        ).count()
        running = Scan.objects.filter(status=Scan.Status.RUNNING).count()
        position = ahead + running + 1
    else:
        position = 0

    modules = _module_progress(scan)
    done_count = sum(1 for m in modules if m["state"] == "done")
    can_abort = (
        scan.status in (Scan.Status.QUEUED, Scan.Status.RUNNING)
        and getattr(request, "real_ip_hash", "") == (scan.requested_ip_hash or "")
        and bool(scan.requested_ip_hash)
    )
    return render(request, "partials/maketrust/scan_progress.html", {
        "scan": scan, "position": position,
        "modules": modules,
        "done_count": done_count,
        "total_count": len(modules),
        "can_abort": can_abort,
        "seconds_until_start": _seconds_until_start(scan),
    })


@require_POST
def scan_abort(request, scan_id):
    """Mark a still-running scan as ABORTED.

    Authorisation: only the IP that submitted the scan may cancel it. We
    compare hashes (not raw IPs) and require both sides to be non-empty,
    so an empty `requested_ip_hash` (legacy / shouldn't happen) cannot be
    matched by an empty middleware value.
    """
    scan = _scan_or_404(scan_id)
    requester_hash = getattr(request, "real_ip_hash", "") or ""
    if not requester_hash or requester_hash != (scan.requested_ip_hash or ""):
        return HttpResponseForbidden()
    if scan.status not in (Scan.Status.QUEUED, Scan.Status.RUNNING):
        # Already finished — treat as a no-op success and let the template
        # redirect to the result.
        return redirect("maketrust:scan_progress", scan_id=scan.id)
    scan.status = Scan.Status.ABORTED
    scan.save(update_fields=["status"])
    if request.headers.get("HX-Request"):
        # HTMX caller: replace the in-page partial with the aborted state.
        return render(request, "partials/maketrust/scan_aborted.html", {"scan": scan})
    return redirect("maketrust:scan_progress", scan_id=scan.id)


@require_http_methods(["GET", "POST"])
def scan_rescan(request, scan_id):
    """In-page rescan flow triggered by the result page FAB.

    GET (HTMX): returns the modal partial pre-filled with the source scan's
        email (if any) so the visitor only has to confirm.
    POST: validates email, creates a new Scan that copies the domain and
        DKIM-selectors from the source, queues it, and redirects (HX-Redirect
        for HTMX, regular 302 otherwise) to /scan/<new-id>/progress/.

    The rescan is the abuse-control choke point: email is always required,
    disposable providers are blocked, per-domain 24h cap still applies.
    """
    from django.urls import reverse

    src = _scan_or_404(scan_id)

    ip_hash = getattr(request, "real_ip_hash", "") or ""
    is_staff = bool(request.user.is_authenticated and request.user.is_staff)
    if request.method == "POST":
        form = RescanForm(request.POST, ip_hash=ip_hash, is_staff=is_staff)
        if form.is_valid():
            if not is_staff and _ip_overscanned(ip_hash):
                form.add_error(
                    None,
                    "Vous avez atteint la limite de scans pour aujourd'hui. "
                    "Contactez-nous à contact@makeset.be si vous avez un "
                    "besoin légitime de plus de scans.",
                )
            else:
                email = form.cleaned_data.get("email", "")
                cooldown_seconds = form.get_cooldown_delay()
                scheduled_for = (
                    timezone.now() + timedelta(seconds=cooldown_seconds)
                    if cooldown_seconds > 0 else None
                )
                new_scan = Scan.objects.create(
                    domain=src.domain,
                    status=Scan.Status.QUEUED,
                    requested_ip_hash=ip_hash,
                    requested_email=email,
                    requested_email_hash=hash_ip(email) if email else "",
                    locale=get_language() or "fr",
                    scheduled_for=scheduled_for,
                    is_internal=is_staff,
                )
                async_task(
                    "apps.maketrust.scanner.orchestrator.run_scan",
                    str(new_scan.id),
                    task_name=f"scan:{new_scan.domain}",
                )
                progress_url = reverse(
                    "maketrust:scan_progress", kwargs={"scan_id": new_scan.id},
                )
                if request.headers.get("HX-Request"):
                    resp = HttpResponse("")
                    resp["HX-Redirect"] = progress_url
                    return resp
                return redirect(progress_url)
    else:
        # Only pre-fill the email when the requester matches the original
        # submitter. The scan URL is public — without this guard, anyone
        # sharing the link could open the rescan modal and read another
        # visitor's email out of the input's `value=` attribute. Staff
        # session also gets the pre-fill (their own admin-driven scans).
        owner_match = (
            bool(ip_hash) and ip_hash == (src.requested_ip_hash or "")
        )
        prefill_email = src.requested_email if (owner_match or is_staff) else ""
        form = RescanForm(
            initial={"email": prefill_email},
            ip_hash=ip_hash, is_staff=is_staff,
        )

    return render(request, "partials/maketrust/rescan_modal.html", {
        "form": form,
        "scan": src,
    })


CATEGORY_ORDER = ("email", "web", "hygiene", "privacy")

# Same penalties as scoring.py — kept here so we can compute per-category
# without recomputing the global score. Source: SEVERITY_WEIGHT.
_PENALTY = {"critical": 14, "high": 9, "medium": 5, "low": 2, "info": 0, "pass": 0}


def _category_score(category_checks) -> int | None:
    if not category_checks:
        return None
    penalty = sum(_PENALTY[c.severity] for c in category_checks)
    reference = _PENALTY["high"] * len(category_checks)
    if reference == 0:
        return 100
    return max(0, round(100 - 100 * (penalty / reference)))


def _category_summary(category_checks) -> dict:
    counts = {sev: 0 for sev in _PENALTY}
    for c in category_checks:
        counts[c.severity] = counts.get(c.severity, 0) + 1
    return counts


def _percentile_for(scan: Scan) -> int | None:
    """How this scan ranks against every OTHER distinct domain ever scanned.

    Counts each domain ONCE (its best historical score) so a domain scanned
    50 times doesn't get 50 votes in the pool. `is_internal` scans
    (dogfooding by logged-in admins) are also excluded so our own activity
    doesn't move the metric.

    Returns None when there's nothing else to compare against. Capped at 99%
    unless the scan actually scored 100/100 — "better than 100% of domains"
    reads as impossible to a visitor.

    Cached for an hour keyed by (score, domain): a result page can render
    thousands of times in an hour without re-running the GROUP BY. The pool
    changes slowly (one new domain per few hours at the projected volume),
    a 1h drift in percentile is well below the metric's intrinsic noise.
    """
    if scan.overall_score is None:
        return None

    from django.core.cache import cache
    from django.db.models import Max

    cache_key = f"mt:pct:{scan.overall_score}:{scan.domain}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached if cached >= 0 else None  # sentinel -1 for "None"

    others = (
        Scan.objects
        .filter(status=Scan.Status.DONE, is_internal=False)
        .exclude(domain=scan.domain)
        .values("domain")
        .annotate(best=Max("overall_score"))
    )
    total = others.count()
    if total == 0:
        cache.set(cache_key, -1, 3600)
        return None

    worse = others.filter(best__lt=scan.overall_score).count()
    pct = round(100 * worse / total)
    if pct >= 100 and scan.overall_score < 100:
        pct = 99
    cache.set(cache_key, pct, 3600)
    return pct


def _site_profile_check(scan: Scan) -> Check | None:
    """Pull the single site_profile finding for the hero card extension."""
    return Check.objects.filter(scan=scan, module="site_profile").first()


def scan_result(request, scan_id):
    from .findings import (
        CATEGORY_LABELS, MODULE_TO_CATEGORY, get_category_label,
    )

    scan = _scan_or_404(scan_id)
    if not scan.is_finished:
        return redirect("maketrust:scan_progress", scan_id=scan.id)

    severity_rank = Check.SEVERITY_ORDER
    all_checks = sorted(
        Check.objects.filter(scan=scan),
        key=lambda c: (severity_rank.get(c.severity, 99), c.module, c.id),
    )

    site_profile = _site_profile_check(scan)
    profile_payload = (site_profile.finding or {}) if site_profile else {}

    # "Email-only domain" framing: when the website is unreachable BUT we
    # found MX records, the user is most likely scanning a domain used for
    # email only (e.g. querinjean.be — emails, no website). Reframe the
    # banner so they don't read "your site is broken" — it's not, they just
    # don't have one.
    email_only_domain = (
        profile_payload.get("type") == "unreachable"
        and any(c.module == "dns_basics" and c.title_key == "dns.has_mx" for c in all_checks)
    )

    # Top 3 actionable priorities — what the visitor should fix first.
    priorities = [
        c for c in all_checks if c.severity in ("critical", "high", "medium")
    ][:3]

    # Group findings by category in the canonical order.
    grouped: list[dict] = []
    for cat in CATEGORY_ORDER:
        cat_checks = [
            c for c in all_checks if MODULE_TO_CATEGORY.get(c.module) == cat
        ]
        if not cat_checks:
            continue
        # When every check in a category bailed out because the homepage
        # was unreachable, displaying "100/100" or "0/100" both lie. Mark
        # the category as `skipped` and let the template draw a neutral
        # "Ignoré" badge instead of a score.
        skipped = all(
            c.title_key == "web.skipped_no_homepage" for c in cat_checks
        )
        # When the whole category is skipped, three modules each emit the
        # same "skipped" finding. Show only one so the report doesn't read
        # like a stutter.
        display_checks = cat_checks[:1] if skipped else cat_checks
        label = get_category_label(cat)
        grouped.append({
            "slug": cat,
            "label": label,
            "checks": display_checks,
            "score": None if skipped else _category_score(cat_checks),
            "summary": _category_summary(cat_checks),
            "skipped": skipped,
            "count_issues": sum(
                1 for c in cat_checks
                if c.severity in ("critical", "high", "medium", "low")
            ),
        })

    return render(request, "pages/maketrust/scan_result.html", {
        "scan": scan,
        "checks": all_checks,         # legacy / fallback
        "priorities": priorities,
        "categories": grouped,
        "percentile": _percentile_for(scan),
        "profile": profile_payload,
        "email_only_domain": email_only_domain,
    })
