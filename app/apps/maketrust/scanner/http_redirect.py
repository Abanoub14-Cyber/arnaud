"""HTTP→HTTPS redirect check, plus the www. variant probe (W1).

Two angles:

1. Apex on port 80: does it answer? Does it redirect to HTTPS with a 301?
2. www. variant: if the user submitted `example.com`, also probe
   `www.example.com` (and vice versa). Many sites configure only one,
   leaving visitors on the other landing on a confusing page or a stranger
   site that happens to share the IP.

Both checks reuse the SSRF-safe pinned session.
"""
from __future__ import annotations

from .base import (
    CheckResult, Module, ScanContext,
    SEV_HIGH, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_PASS,
)
from .safety import make_safe_session, resolve_public_ips, safe_get
from .site_profile import CACHE_HOME_FAILED


def _check_apex(ctx: ScanContext) -> tuple[list[CheckResult], str]:
    """Returns (findings, redirect_target).

    `redirect_target` is the Location header on a 3xx, empty otherwise. The
    www-variant check uses it to know that apex already points at www so it
    won't double-flag the situation as split-brain.
    """
    if not ctx.public_ips:
        return [CheckResult(
            severity=SEV_INFO,
            title_key="redirect.no_target",
            evidence="No public IP to connect to on port 80.",
        )], ""

    url = f"http://{ctx.domain}/"
    try:
        session = make_safe_session()
        resp = safe_get(session, url, ctx.public_ips[0])
    except Exception as exc:
        return [CheckResult(
            severity=SEV_INFO,
            title_key="redirect.no_http",
            evidence=f"Port 80 closed or unreachable: {exc.__class__.__name__}",
        )], ""

    loc = resp.headers.get("Location", "")

    if not (300 <= resp.status_code < 400):
        return [CheckResult(
            severity=SEV_HIGH,
            title_key="redirect.serves_http",
            fix_key="redirect.fix_force_https",
            finding={"status": resp.status_code},
            evidence=(
                f"Port 80 returned {resp.status_code} without redirecting. "
                "Visitors land on plain HTTP and can be MITM-ed."
            ),
        )], loc

    if not loc.startswith("https://"):
        return [CheckResult(
            severity=SEV_HIGH,
            title_key="redirect.target_not_https",
            fix_key="redirect.fix_force_https",
            finding={"status": resp.status_code, "location": loc},
            evidence=f"Redirect target: {loc[:200]}",
        )], loc

    if resp.status_code == 301:
        return [CheckResult(
            severity=SEV_PASS,
            title_key="redirect.permanent_https",
            finding={"status": 301, "location": loc},
            evidence=f"301 -> {loc[:200]}",
        )], loc

    return [CheckResult(
        severity=SEV_LOW,
        title_key="redirect.temporary_only",
        fix_key="redirect.fix_make_permanent",
        finding={"status": resp.status_code, "location": loc},
        evidence=f"{resp.status_code} -> {loc[:200]}",
    )], loc


def _www_variant(domain: str) -> str | None:
    """The 'other' name to probe.

    Given `example.com` -> `www.example.com`. Given `www.example.com` ->
    `example.com`. Given anything with more than one subdomain (e.g.
    `blog.example.com`), we don't probe (out of scope, and risk surprise).
    """
    parts = domain.split(".")
    if len(parts) == 2:
        return f"www.{domain}"
    if len(parts) == 3 and parts[0] == "www":
        return ".".join(parts[1:])
    return None


def _check_www_variant(ctx: ScanContext, apex_redirect_target: str) -> list[CheckResult]:
    """Resolve and (optionally) GET the alternate host.

    `apex_redirect_target` is the Location the apex (port 80) handed back, if
    any. When apex already points at the www variant (or vice versa), the
    setup is correctly canonicalising and we skip the probe entirely — that
    case is a PASS, not a finding.

    INFO-only when the variant is missing: many sites legitimately only
    configure one side.
    """
    other = _www_variant(ctx.domain)
    if other is None:
        return []

    # Already correctly canonicalising? (apex 30x -> www, or www 30x -> apex)
    if apex_redirect_target and other in apex_redirect_target:
        return []

    other_ips = resolve_public_ips(other)
    if not other_ips:
        # Subdomain not configured. Surface as INFO so user knows.
        return [CheckResult(
            severity=SEV_INFO,
            title_key="redirect.www_missing",
            fix_key="redirect.fix_www",
            finding={"variant": other},
            evidence=f"{other} does not resolve.",
        )]

    # Try to fetch the variant's https home. We expect a redirect to the
    # canonical name, or the same content. Anything that looks like split
    # brain (different content with no redirect) is medium severity.
    url = f"https://{other}/"
    try:
        session = make_safe_session()
        resp = safe_get(session, url, other_ips[0])
    except Exception as exc:
        return [CheckResult(
            severity=SEV_LOW,
            title_key="redirect.www_unreachable",
            fix_key="redirect.fix_www",
            finding={"variant": other},
            evidence=f"Cannot fetch https://{other}/: {exc.__class__.__name__}",
        )]

    loc = resp.headers.get("Location", "")
    if 300 <= resp.status_code < 400 and ctx.domain in loc:
        return [CheckResult(
            severity=SEV_PASS,
            title_key="redirect.www_redirects",
            finding={"variant": other, "status": resp.status_code},
            evidence=f"{other} {resp.status_code} -> {loc[:200]}",
        )]

    if resp.status_code == 200:
        # Both serve content. Could be intentional (mirror) but most often a
        # split-brain misconfig.
        return [CheckResult(
            severity=SEV_MEDIUM,
            title_key="redirect.www_split_brain",
            fix_key="redirect.fix_www",
            finding={"variant": other},
            evidence=(
                f"{other} answered 200 without redirecting to {ctx.domain}. "
                "Likely split-brain configuration."
            ),
        )]

    return [CheckResult(
        severity=SEV_LOW,
        title_key="redirect.www_other",
        fix_key="redirect.fix_www",
        finding={"variant": other, "status": resp.status_code},
        evidence=f"{other} -> HTTP {resp.status_code}",
    )]


class HttpRedirectModule(Module):
    slug = "http_redirect"
    weight = 3

    def run(self, ctx: ScanContext) -> list[CheckResult]:
        # If site_profile couldn't reach the homepage, neither apex:80 nor the
        # www variant on :443 will respond either. Skip the two extra fetches
        # (each is a 5-13s timeout when nothing answers) and emit a single
        # INFO finding so the report stays consistent with the rest.
        if ctx.dns_cache.get(CACHE_HOME_FAILED):
            return [CheckResult(
                severity=SEV_INFO,
                title_key="web.skipped_no_homepage",
                evidence="Skipping redirect/www probes — site unreachable on 443.",
            )]
        apex_results, apex_target = _check_apex(ctx)
        return apex_results + _check_www_variant(ctx, apex_target)
