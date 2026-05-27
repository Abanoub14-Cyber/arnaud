"""HTTP security headers — HSTS, CSP, X-Frame, X-Content-Type, Referrer-Policy,
plus cookie security flags on Set-Cookie.

The actual fetch happens earlier in `site_profile.py`, which leaves the body,
headers, and status in `ctx.dns_cache`. This module reads from there. If the
cache is empty (site_profile failed or wasn't run), we fall back to fetching
ourselves, so the module remains usable in isolation (e.g., from tests).

As a side effect we also lift og:image and the page title out of the cached
body for the report's visual preview.
"""
from __future__ import annotations

import re
import urllib.parse

from .base import (
    CheckResult, Module, ScanContext,
    SEV_HIGH, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_PASS,
)
from .safety import make_safe_session, safe_get
from .site_profile import (
    CACHE_HOME_BODY, CACHE_HOME_FAILED, CACHE_HOME_HEADERS,
    CACHE_HOME_IP, CACHE_HOME_STATUS,
)


# Loose but safe HTML scanning. We never execute the body; we only pull a
# couple of metadata strings to visualise the scan, so a permissive regex is
# fine. Bounded by MAX_RESPONSE_BYTES upstream.
_OG_IMAGE_RE = re.compile(
    r'<meta[^>]+(?:property|name)=["\']og:image["\'][^>]*content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_OG_IMAGE_RE_REVERSE = re.compile(
    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]*(?:property|name)=["\']og:image["\']',
    re.IGNORECASE,
)
_TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,300})</title>", re.IGNORECASE | re.DOTALL)


# Cookies whose name suggests they really do need to be readable from JS
# (consent banners, language preference). We avoid hammering them with
# HttpOnly findings.
_JS_LEGITIMATE_COOKIE_NAMES = frozenset({
    "cookielawinfo-checkbox", "cookieconsent", "cc_cookie",
    "lang", "language", "locale", "preferred_language",
})

# Cap how many cookies we analyse — anti-DoS, since a hostile homepage could
# in theory stuff dozens of Set-Cookie headers.
_MAX_COOKIES_ANALYSED = 10


def _absolutize(url: str, page_url: str) -> str:
    """Make a possibly-relative og:image absolute, anchored on the scanned page."""
    if not url:
        return ""
    return urllib.parse.urljoin(page_url, url.strip())


def _get(headers, name: str) -> str:
    for h, v in headers.items():
        if h.lower() == name.lower():
            return v
    return ""


# --- Set-Cookie parsing ---------------------------------------------------

def _split_cookies(blob: str) -> list[str]:
    """Split a `Set-Cookie` blob into individual cookie strings.

    Multiple Set-Cookie response headers are joined by `requests` with ", ".
    We can't naively split on commas though — `Expires=Wed, 21 Oct ...` also
    contains commas. Heuristic: split on commas that look like a header
    separator (next non-space is a `name=` token).
    """
    if not blob:
        return []
    parts: list[str] = []
    current = ""
    i = 0
    while i < len(blob):
        c = blob[i]
        if c == "," and current:
            # Lookahead: is the next non-space chunk shaped like "name="?
            j = i + 1
            while j < len(blob) and blob[j] == " ":
                j += 1
            tail = blob[j:j + 80]
            if re.match(r"^[A-Za-z0-9_\-]+\s*=", tail):
                parts.append(current.strip())
                current = ""
                i = j
                continue
        current += c
        i += 1
    if current.strip():
        parts.append(current.strip())
    return parts


def _cookie_findings(set_cookie_blob: str) -> list[CheckResult]:
    """Inspect every cookie's flags. Returns one or more CheckResults."""
    results: list[CheckResult] = []
    cookies = _split_cookies(set_cookie_blob)[:_MAX_COOKIES_ANALYSED]

    if not cookies:
        return results

    for raw in cookies:
        # Cookie name is everything before the first '='.
        name_eq, *attr_parts = [p.strip() for p in raw.split(";")]
        if "=" not in name_eq:
            continue
        name = name_eq.split("=", 1)[0].strip()
        attrs_lower = {a.split("=", 1)[0].strip().lower() for a in attr_parts}

        is_legit_js = any(
            name.lower().startswith(p) for p in _JS_LEGITIMATE_COOKIE_NAMES
        )

        if "secure" not in attrs_lower:
            results.append(CheckResult(
                severity=SEV_HIGH,
                title_key="cookies.no_secure",
                fix_key="cookies.fix_secure",
                finding={"name": name},
                evidence=f"Set-Cookie: {raw[:200]}",
            ))
        if "httponly" not in attrs_lower and not is_legit_js:
            results.append(CheckResult(
                severity=SEV_LOW,
                title_key="cookies.no_httponly",
                fix_key="cookies.fix_httponly",
                finding={"name": name},
                evidence=f"Set-Cookie: {raw[:200]}",
            ))
        if "samesite" not in attrs_lower:
            results.append(CheckResult(
                severity=SEV_LOW,
                title_key="cookies.no_samesite",
                fix_key="cookies.fix_samesite",
                finding={"name": name},
                evidence=f"Set-Cookie: {raw[:200]}",
            ))

    if not results:
        # All inspected cookies were correctly flagged.
        results.append(CheckResult(
            severity=SEV_PASS,
            title_key="cookies.ok",
            evidence=f"{len(cookies)} cookie(s) inspected, all flags OK.",
        ))

    return results


def _fetch_or_reuse(ctx: ScanContext) -> tuple[int, dict, str, str] | None:
    """Return (status, headers, body, ip) from cache, or fetch ourselves.

    `None` if neither path produces a response.
    """
    cached_status = ctx.dns_cache.get(CACHE_HOME_STATUS)
    if cached_status is not None and not ctx.dns_cache.get(CACHE_HOME_FAILED):
        return (
            cached_status,
            ctx.dns_cache.get(CACHE_HOME_HEADERS, {}),
            ctx.dns_cache.get(CACHE_HOME_BODY, ""),
            ctx.dns_cache.get(CACHE_HOME_IP, ""),
        )

    if ctx.dns_cache.get(CACHE_HOME_FAILED):
        return None

    if not ctx.public_ips:
        return None

    url = f"https://{ctx.domain}/"
    ip = ctx.public_ips[0]
    try:
        session = make_safe_session()
        resp = safe_get(session, url, ip)
    except Exception:
        return None
    try:
        body = resp.content.decode("utf-8", errors="replace")
    except Exception:
        body = ""
    return resp.status_code, dict(resp.headers), body, ip


class HttpHeadersModule(Module):
    slug = "http_headers"
    weight = 4

    def run(self, ctx: ScanContext) -> list[CheckResult]:
        cached = _fetch_or_reuse(ctx)
        if cached is None:
            # No web server to inspect — emit INFO, not HIGH. Scoring this as
            # HIGH penalises domains that legitimately don't host a website
            # (email-only setups), which would be unfair.
            return [CheckResult(
                severity=SEV_INFO,
                title_key="web.skipped_no_homepage",
                evidence="No homepage to inspect — site is unreachable on port 443.",
            )]

        status, headers, body, ip = cached
        url = f"https://{ctx.domain}/"

        out: list[CheckResult] = [CheckResult(
            severity=SEV_PASS,
            title_key="headers.fetched",
            finding={"status": status, "server": _get(headers, "Server")},
            evidence=f"HTTP {status} from {url}",
        )]

        # Lift og:image + title from the body for the report preview card.
        # Best effort — never raises, never blocks the scan.
        m = _OG_IMAGE_RE.search(body) or _OG_IMAGE_RE_REVERSE.search(body)
        if m:
            preview_url = _absolutize(m.group(1), url)
            # Only keep https URLs to avoid mixed-content warnings on the report.
            if preview_url.startswith("https://"):
                ctx.dns_cache["preview_image_url"] = preview_url
        t = _TITLE_RE.search(body)
        if t:
            ctx.dns_cache["preview_title"] = " ".join(t.group(1).split())[:300]

        # Strict-Transport-Security
        hsts = _get(headers, "Strict-Transport-Security")
        if not hsts:
            # Severity is MEDIUM, not HIGH: HSTS only protects the very first
            # visit before any HTTPS handshake (an attacker on the local
            # network MITM-ing the 'http://' navigation). In practice the
            # vast majority of visitors arrive via an https link from search
            # engines or bookmarks and are already on TLS, so the realistic
            # blast radius is narrower than a "high" rating suggests. OWASP
            # ASVS and Mozilla Observatory both rate HSTS in the "recommended,
            # not critical" tier.
            out.append(CheckResult(
                severity=SEV_MEDIUM,
                title_key="headers.no_hsts",
                fix_key="headers.fix_hsts",
                evidence="HSTS missing, first request can be MITM-downgraded.",
            ))
        else:
            try:
                max_age = int(next(
                    (p.split("=", 1)[1] for p in hsts.split(";")
                     if p.strip().startswith("max-age=")),
                    "0",
                ))
            except ValueError:
                max_age = 0
            if max_age < 15768000:  # 6 months
                out.append(CheckResult(
                    severity=SEV_LOW,
                    title_key="headers.hsts_short",
                    fix_key="headers.fix_hsts_long",
                    finding={"max_age": max_age},
                    evidence=hsts,
                ))
            else:
                out.append(CheckResult(
                    severity=SEV_PASS,
                    title_key="headers.hsts_ok",
                    finding={"max_age": max_age},
                    evidence=hsts,
                ))

        # Content-Security-Policy
        csp = _get(headers, "Content-Security-Policy")
        if not csp:
            out.append(CheckResult(
                severity=SEV_MEDIUM,
                title_key="headers.no_csp",
                fix_key="headers.fix_csp",
                evidence="No CSP, XSS payloads run with no constraint.",
            ))
        else:
            out.append(CheckResult(
                severity=SEV_PASS,
                title_key="headers.csp_ok",
                evidence=csp[:400],
            ))

        # X-Frame-Options or CSP frame-ancestors
        xfo = _get(headers, "X-Frame-Options")
        has_frame_ancestors = "frame-ancestors" in csp.lower()
        if not xfo and not has_frame_ancestors:
            out.append(CheckResult(
                severity=SEV_MEDIUM,
                title_key="headers.no_clickjacking",
                fix_key="headers.fix_clickjacking",
                evidence="No X-Frame-Options nor CSP frame-ancestors.",
            ))

        # X-Content-Type-Options
        if _get(headers, "X-Content-Type-Options").lower() != "nosniff":
            out.append(CheckResult(
                severity=SEV_LOW,
                title_key="headers.no_nosniff",
                fix_key="headers.fix_nosniff",
                evidence="X-Content-Type-Options header missing or wrong value.",
            ))

        # Referrer-Policy
        if not _get(headers, "Referrer-Policy"):
            out.append(CheckResult(
                severity=SEV_LOW,
                title_key="headers.no_referrer_policy",
                fix_key="headers.fix_referrer_policy",
                evidence="Referrer-Policy not set, defaults vary by browser.",
            ))

        # Server header — leaking version is a recon signal.
        server = _get(headers, "Server")
        if server and any(c.isdigit() for c in server):
            out.append(CheckResult(
                severity=SEV_INFO,
                title_key="headers.server_version_leak",
                fix_key="headers.fix_hide_server",
                finding={"server": server},
                evidence=f"Server: {server}",
            ))

        # Permissions-Policy
        if not _get(headers, "Permissions-Policy"):
            out.append(CheckResult(
                severity=SEV_LOW,
                title_key="headers.no_permissions_policy",
                fix_key="headers.fix_permissions_policy",
                evidence="No Permissions-Policy header.",
            ))

        # COOP
        coop = _get(headers, "Cross-Origin-Opener-Policy")
        if not coop:
            out.append(CheckResult(
                severity=SEV_LOW,
                title_key="headers.no_coop",
                fix_key="headers.fix_coop",
                evidence="No Cross-Origin-Opener-Policy header.",
            ))

        # COEP — informational only (rarely needed)
        coep = _get(headers, "Cross-Origin-Embedder-Policy")
        if not coep:
            out.append(CheckResult(
                severity=SEV_INFO,
                title_key="headers.no_coep",
                fix_key="headers.fix_coep",
                evidence="No Cross-Origin-Embedder-Policy header (optional).",
            ))

        # CORP
        if not _get(headers, "Cross-Origin-Resource-Policy"):
            out.append(CheckResult(
                severity=SEV_INFO,
                title_key="headers.no_corp",
                fix_key="headers.fix_corp",
                evidence="No Cross-Origin-Resource-Policy header.",
            ))

        # --- Cookie security on the home response (W2) -------------------
        out.extend(_cookie_findings(_get(headers, "Set-Cookie")))

        return out
