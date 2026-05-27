"""Site profile: classify the page + identify a WAF/CDN in front.

Runs first in the orchestrator. Owns the single HTTPS GET to the homepage
(SSRF-safe via `safe_get` with IP pinning) and stashes the response in
`ctx.dns_cache` under the `home_*` keys so later modules (notably
`http_headers`) can reuse it without re-fetching.

Two outputs, both informational (severity = pass/info, never penalises):

1. Site type — real_site | parked | for_sale | registrar_default
   | unreachable | non_html.  Helps the reader interpret the rest of the
   report. A parked domain failing security checks is not a "problem to fix".
2. WAF/CDN identification — Cloudflare, Akamai, CloudFront, Fastly, Sucuri,
   Imperva, BunnyCDN, or none detected. Recognised purely from headers and
   cookies — no third-party lookups, no ASN service.

Security:
- Reuses the project-wide `safe_get` (IP-pinned, byte-capped, redirect-blocked).
- Body classification regexes are short, anchored, and non-backtracking.
- Cookie inspection is a header parse, not a Set-Cookie execution.
"""
from __future__ import annotations

import re

from urllib.parse import urlparse, urlunparse

from .base import (
    CheckResult, Module, ScanContext,
    SEV_INFO, SEV_PASS,
)
from .safety import make_safe_session, resolve_public_ips, safe_get


# Cache keys this module writes for downstream consumers.
CACHE_HOME_STATUS = "home_status"
CACHE_HOME_HEADERS = "home_headers"
CACHE_HOME_BODY = "home_body"
CACHE_HOME_IP = "home_ip"
CACHE_HOME_FAILED = "home_fetch_failed"


# --- Parking / for-sale / registrar default fingerprints -----------------
#
# Patterns are case-insensitive substring checks rather than regexes — fastest,
# zero backtracking, easy to audit. Order matters for nothing here (we OR
# them all).

_PARKED_MARKERS = (
    "sedoparking.com", "parkingcrew", "parking.namesilo",
    "godaddy.com/forsale", "afternic.com", "dan.com",
    "bodis.com",
    "namebright.com",
    "domaincntrl.com",
    "parkingaccess.com",
    "domainparking.ru",
)

_FOR_SALE_MARKERS = (
    "this domain is for sale",
    "this domain may be for sale",
    "buy this domain",
    "ce domaine est à vendre",
    "domain for sale",
)

_REGISTRAR_DEFAULT_MARKERS = (
    "welcome to nginx",
    "apache2 ubuntu default page",
    "apache2 debian default page",
    "it works!",
    "iis windows server",
    "default plesk page",
    "cpanel-branded",
    "openresty welcome",
)


# --- Stack fingerprints ---------------------------------------------------

# Generator meta tag is the most reliable signal; everything else is fallback.
_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']{1,120})["\']',
    re.IGNORECASE,
)

# Body markers, ordered roughly by popularity. Substring checks only.
_STACK_BODY_MARKERS: tuple[tuple[str, str], ...] = (
    ("wordpress", "/wp-content/"),
    ("wordpress", "/wp-includes/"),
    ("shopify", "cdn.shopify.com"),
    ("shopify", "shopifycdn.net"),
    ("wix", "static.wixstatic.com"),
    ("wix", "wix.com"),
    ("squarespace", "squarespace.com"),
    ("squarespace", "static1.squarespace.com"),
    ("webflow", "webflow.com"),
    ("webflow", ".webflow.io"),
    ("ghost", '"generator":"ghost'),
    ("drupal", '"drupal-settings-json"'),
    ("joomla", "/components/com_"),
    ("prestashop", "prestashop"),
    ("statamic", '<meta name="generator" content="statamic'),
)


# --- WAF / CDN signatures -------------------------------------------------

# Headers (lower-case-key match, value can be anything containing the marker).
_WAF_HEADER_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    # (canonical_name, header_lower, expected_substring_lower)
    # Empty substring => any value matches.
    ("cloudflare", "cf-ray", ""),
    ("cloudflare", "server", "cloudflare"),
    ("akamai", "server", "akamaighost"),
    ("akamai", "x-akamai-transformed", ""),
    ("aws_cloudfront", "x-amz-cf-id", ""),
    ("fastly", "x-fastly-request-id", ""),
    ("fastly", "x-served-by", "cache-"),  # Fastly uses cache-XXX
    ("sucuri", "x-sucuri-id", ""),
    ("sucuri", "x-sucuri-cache", ""),
    ("imperva", "x-iinfo", ""),
    ("bunnycdn", "server", "bunnycdn"),
    ("ovh", "server", "iplb"),
)

_WAF_COOKIE_SIGNATURES: tuple[tuple[str, str], ...] = (
    # (canonical_name, cookie_name_lower)
    ("cloudflare", "__cf_bm"),
    ("cloudflare", "cf_clearance"),
    ("imperva", "incap_ses_"),  # prefix match
    ("imperva", "visid_incap_"),
    ("akamai", "akamai_session"),
)


# Headers may have multiple Set-Cookie values; requests joins them with ", ".
_SET_COOKIE_NAME_RE = re.compile(r'(?:^|,\s*)([A-Za-z0-9_\-]+)\s*=', re.ASCII)


# --- Same-domain redirect following ---------------------------------------
#
# Plenty of legitimate sites 301 the apex to a language-prefixed URL or to
# the www. variant (e.g. energymarketprice.com -> www.energymarketprice.com/
# home/en/). Without following, every HTTP check downstream gets an empty
# body and a misleading "redirects" profile. We follow up to 2 hops, but
# ONLY if each hop stays on the same registrable domain (or its www-flip).
# An open redirect aimed at an attacker-controlled host is never followed.

MAX_REDIRECT_HOPS = 2


def _is_same_or_www_variant(source: str, target: str) -> bool:
    """True iff `target` is the same host as `source`, the www. variant of
    `source`, or `source` is the www. variant of `target`.

    Restricted on purpose — we won't follow `example.com` -> `app.example.com`
    or any cross-subdomain hop. Misses some legit setups but keeps the SSRF
    surface minimal until we wire in a proper public-suffix list.
    """
    source = source.lower().strip(".")
    target = target.lower().strip(".")
    if source == target:
        return True
    if target == "www." + source:
        return True
    if source == "www." + target:
        return True
    return False


def _follow_same_domain_redirect(
    session, source_domain: str, resp,
) -> tuple[object, str]:
    """Walk up to MAX_REDIRECT_HOPS same-domain 3xx redirects.

    Returns (final_response, final_ip). When a hop targets a different host
    (open redirect risk) or fails IP validation, we stop and return the last
    safe response we have. `session` is the SSRF-safe Requests session.
    """
    current = resp
    current_ip = ""
    seen_urls: set[str] = set()

    for _ in range(MAX_REDIRECT_HOPS):
        if not (300 <= current.status_code < 400):
            return current, current_ip

        loc = current.headers.get("Location", "")
        if not loc:
            return current, current_ip

        try:
            parsed = urlparse(loc)
        except Exception:
            return current, current_ip

        # Honour Location either as an absolute URL or as a path-relative hint.
        target_host = (parsed.netloc or source_domain).lower()
        target_scheme = parsed.scheme or "https"
        if target_scheme not in ("http", "https"):
            return current, current_ip

        if not _is_same_or_www_variant(source_domain, target_host):
            return current, current_ip

        target_ips = resolve_public_ips(target_host)
        if not target_ips:
            return current, current_ip

        target_url = urlunparse((
            target_scheme, target_host, parsed.path or "/",
            "", parsed.query, "",
        ))
        if target_url in seen_urls:
            return current, current_ip  # loop guard
        seen_urls.add(target_url)

        try:
            current = safe_get(session, target_url, target_ips[0])
            current_ip = target_ips[0]
        except Exception:
            return current, current_ip

    return current, current_ip


def _classify_body(body: str, status: int) -> tuple[str, str]:
    """Return (type, stack). Stack is meaningful only when type=real_site."""
    if status == 0:
        return ("unreachable", "")

    # 3xx — the page itself doesn't exist at this URL, the host redirects
    # elsewhere. Don't try to read the empty body.
    if 300 <= status < 400:
        return ("redirects", "")

    lo = body.lower()

    # Order: parked > for-sale > registrar > non-html > real
    for needle in _PARKED_MARKERS:
        if needle in lo:
            return ("parked", "")

    for needle in _FOR_SALE_MARKERS:
        if needle in lo:
            return ("for_sale", "")

    # Tiny default pages with no real content.
    if len(body) < 2048:
        for needle in _REGISTRAR_DEFAULT_MARKERS:
            if needle in lo:
                return ("registrar_default", "")

    if "<html" not in lo and "<!doctype html" not in lo:
        return ("non_html", "")

    # Real site — try to fingerprint the stack.
    m = _GENERATOR_RE.search(body)
    if m:
        gen = m.group(1).lower()
        for stack in ("wordpress", "shopify", "wix", "squarespace",
                      "webflow", "ghost", "drupal", "joomla", "statamic",
                      "hugo", "jekyll", "gatsby", "next.js", "nuxt"):
            if stack in gen:
                return ("real_site", stack.replace(".js", "js"))
        return ("real_site", "custom")

    for stack, marker in _STACK_BODY_MARKERS:
        if marker in lo:
            return ("real_site", stack)

    return ("real_site", "custom")


def _detect_waf(headers: dict, set_cookie: str) -> str:
    """Return canonical WAF/CDN name or empty string if none detected."""
    # Lower-case header view for comparison; preserves the original dict.
    lower = {k.lower(): v for k, v in headers.items()}

    for name, header, needle in _WAF_HEADER_SIGNATURES:
        v = lower.get(header, "")
        if v and (not needle or needle in v.lower()):
            return name

    if set_cookie:
        cookie_lo = set_cookie.lower()
        for name, marker in _WAF_COOKIE_SIGNATURES:
            if marker in cookie_lo:
                return name

    return ""


def _set_cookie_blob(headers: dict) -> str:
    """Concatenate every Set-Cookie value (requests merges them with ', ')."""
    return next(
        (v for k, v in headers.items() if k.lower() == "set-cookie"), "",
    )


class SiteProfileModule(Module):
    slug = "site_profile"
    weight = 1

    def run(self, ctx: ScanContext) -> list[CheckResult]:
        if not ctx.public_ips:
            ctx.dns_cache[CACHE_HOME_FAILED] = True
            return [CheckResult(
                severity=SEV_INFO,
                title_key="site.unreachable",
                evidence="No public IP, cannot fetch homepage.",
                finding={"type": "unreachable"},
            )]

        url = f"https://{ctx.domain}/"
        ip = ctx.public_ips[0]
        try:
            session = make_safe_session()
            resp = safe_get(session, url, ip)
        except Exception as exc:
            ctx.dns_cache[CACHE_HOME_FAILED] = True
            return [CheckResult(
                severity=SEV_INFO,
                title_key="site.unreachable",
                evidence=f"{exc.__class__.__name__}: {exc}",
                finding={"type": "unreachable"},
            )]

        # If the apex 301s to (e.g.) www.example.com/home/en/, follow it
        # before classifying — otherwise every downstream HTTP module sees
        # an empty body and we surface a misleading "redirects" profile for
        # what is in fact a perfectly real site. We only follow within the
        # same registrable domain (or its www. variant) so an open redirect
        # to an attacker host is never chased.
        followed_from_url = ""
        if 300 <= resp.status_code < 400:
            final_resp, final_ip = _follow_same_domain_redirect(
                session, ctx.domain, resp,
            )
            if final_resp is not resp:
                followed_from_url = url
                resp = final_resp
                if final_ip:
                    ip = final_ip

        # Stash for downstream modules.
        try:
            body = resp.content.decode("utf-8", errors="replace")
        except Exception:
            body = ""
        ctx.dns_cache[CACHE_HOME_STATUS] = resp.status_code
        ctx.dns_cache[CACHE_HOME_HEADERS] = dict(resp.headers)
        ctx.dns_cache[CACHE_HOME_BODY] = body
        ctx.dns_cache[CACHE_HOME_IP] = ip

        site_type, stack = _classify_body(body, resp.status_code)
        set_cookie = _set_cookie_blob(resp.headers)
        waf = _detect_waf(resp.headers, set_cookie)

        # Pick a title key reflecting site type. We always emit one PASS-severity
        # finding so the report can render the profile card from it.
        if site_type == "real_site":
            title_key = "site.real"
        elif site_type == "parked":
            title_key = "site.parked"
        elif site_type == "for_sale":
            title_key = "site.for_sale"
        elif site_type == "registrar_default":
            title_key = "site.registrar_default"
        elif site_type == "non_html":
            title_key = "site.non_html"
        elif site_type == "redirects":
            title_key = "site.redirects"
        else:
            title_key = "site.unreachable"

        # parked / for_sale / registrar_default are "not a real site" but we
        # still surface them at INFO not PASS so the reader knows why their
        # report looks empty.
        severity = SEV_PASS if site_type == "real_site" else SEV_INFO

        finding_payload = {
            "type": site_type,
            "stack": stack,
            "waf": waf,
            "ip": ip,
            "status": resp.status_code,
        }
        evidence_lines = [
            f"HTTP {resp.status_code} from {url} ({ip})",
            f"type={site_type} stack={stack or '-'} waf={waf or 'none'}",
        ]
        if followed_from_url:
            finding_payload["followed_redirect_from"] = followed_from_url
            evidence_lines.append(f"followed redirect from {followed_from_url}")

        return [CheckResult(
            severity=severity,
            title_key=title_key,
            finding=finding_payload,
            evidence="\n".join(evidence_lines),
        )]
