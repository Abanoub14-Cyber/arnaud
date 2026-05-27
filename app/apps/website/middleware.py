"""Site-wide middleware: real-IP resolution and legacy URL redirects."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress

from django.conf import settings
from django.http import HttpResponsePermanentRedirect
from django.urls import reverse
from django.utils import translation


# Cloudflare edge IP ranges (https://www.cloudflare.com/ips/, refreshed 2026-05-04).
# Update via `manage.py refresh_cloudflare_ips`.
CLOUDFLARE_IPV4 = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)
CLOUDFLARE_IPV6 = (
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)
_CLOUDFLARE_NETS = tuple(
    ipaddress.ip_network(cidr) for cidr in CLOUDFLARE_IPV4 + CLOUDFLARE_IPV6
)

# Private ranges where our reverse proxy (Traefik on the docker `web` network)
# legitimately reaches the app. Treating these as trusted lets us follow the
# CF-Connecting-IP header through Cloudflare → Traefik → app. Nothing else
# listens on the app's port from these subnets, so an attacker would need a
# foothold inside the docker network to spoof the header.
_TRUSTED_PROXY_NETS = tuple(ipaddress.ip_network(cidr) for cidr in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC 1918
    "127.0.0.0/8", "::1/128", "fc00::/7",
))


def _is_trusted_hop(ip_str: str) -> bool:
    """True if the immediate peer is one we accept CF-Connecting-IP from:
    Cloudflare directly, or our internal proxy network."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in _CLOUDFLARE_NETS + _TRUSTED_PROXY_NETS)


def _is_valid_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return True


def hash_ip(ip_str: str) -> str:
    """Stable, non-reversible identifier we can store and index without keeping raw IPs."""
    key = settings.SECRET_KEY.encode("utf-8")
    return hmac.new(key, ip_str.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


class RealIPMiddleware:
    """Set request.real_ip + request.real_ip_hash.

    Behind Cloudflare the visitor IP arrives in `CF-Connecting-IP`. We trust
    that header *only* when REMOTE_ADDR itself sits in a Cloudflare CIDR;
    otherwise any client could spoof their identity by sending the header.

    Also resolves request.cf_country (ISO 3166-1 alpha-2 like "BE"/"FR")
    from the `CF-IPCountry` header, under the same trust check.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        remote = request.META.get("REMOTE_ADDR", "") or ""
        cf_ip = (request.META.get("HTTP_CF_CONNECTING_IP", "") or "").strip()
        cf_country = (request.META.get("HTTP_CF_IPCOUNTRY", "") or "").strip().upper()

        trusted = _is_trusted_hop(remote)
        if cf_ip and trusted and _is_valid_ip(cf_ip):
            real_ip = cf_ip
        else:
            real_ip = remote

        request.real_ip = real_ip
        request.real_ip_hash = hash_ip(real_ip) if real_ip else ""
        # Only honour the country header when the hop is trusted (same as
        # CF-Connecting-IP). Otherwise a direct visitor could spoof country.
        request.cf_country = cf_country if trusted and cf_country else ""
        return self.get_response(request)


class AdminGeoRestrictMiddleware:
    """Block /admin/* from visitors whose Cloudflare-resolved country is
    not in ``settings.ADMIN_ALLOWED_COUNTRIES``.

    Cloudflare adds the ISO country code in ``CF-IPCountry``. The earlier
    RealIPMiddleware reads it (with the same trust check as CF-Connecting-IP)
    and exposes it as ``request.cf_country``. We rely on that.

    Behaviour:
      * Empty/missing country (e.g. local dev, request not going through
        CF) → allow. Local dev needs the admin reachable.
      * Country present and not in allowlist → return 404 (not 403, to
        avoid telling the attacker the admin URL exists at all).
      * Authenticated staff session passes through regardless — needed
        so a logged-in admin who travels abroad isn't kicked out of an
        existing session mid-task. Login itself still requires the right
        country.

    ``ADMIN_ALLOWED_COUNTRIES`` should be a set of upper-case ISO codes.
    Falsy value (None, empty set) disables the check entirely — useful
    for staging if you don't want the geo barrier there.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.allowed = frozenset(
            getattr(settings, "ADMIN_ALLOWED_COUNTRIES", set()) or set()
        )

    def __call__(self, request):
        if self.allowed and request.path.startswith("/admin/"):
            country = getattr(request, "cf_country", "") or ""
            already_logged_in = (
                getattr(request, "user", None) is not None
                and request.user.is_authenticated
                and request.user.is_staff
            )
            if country and country not in self.allowed and not already_logged_in:
                from django.http import HttpResponseNotFound
                return HttpResponseNotFound("Not Found")
        return self.get_response(request)


# Legacy PHP slug -> Django URL name.
LEGACY_REDIRECTS = {
    "/cybersecurity": "service_cyber",
    "/websolutions": "service_web",
    "/ai-automation": "service_ia",
    "/support": "service_support",
    "/services": "services_index",
    "/blogs": "blog_list",
    "/contact": "contact",
    "/legal": "legal_mentions",
    "/privacy": "legal_privacy",
    "/terms": "legal_terms",
    "/index": "home",
}


class LegacyPhpRedirectMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        target = self._resolve_redirect(request)
        if target is not None:
            return HttpResponsePermanentRedirect(target)
        return self.get_response(request)

    def _resolve_redirect(self, request):
        path = request.path
        normalized = path.rstrip("/")
        if normalized.endswith(".php"):
            normalized = normalized[:-4]

        target = None
        lang = request.LANGUAGE_CODE or "fr"

        # /articles/<slug>(.php)? -> /blog/<lang-slug>/ — the legacy slug is the
        # English one (PHP era), so we look up the article and reverse with the
        # current language's slug (slug_fr or slug_en via modeltranslation).
        if normalized.startswith("/articles/"):
            from apps.blog.models import Article

            slug = normalized[len("/articles/"):].strip("/")
            if slug and "/" not in slug:
                article = Article.objects.filter(slug_en=slug).first()
                if article is None:
                    # Fallback: maybe the URL already uses the FR slug.
                    article = Article.objects.filter(slug_fr=slug).first()
                if article is not None:
                    with translation.override(lang):
                        target = article.get_absolute_url()

        # Exact legacy PHP slug match.
        elif normalized in LEGACY_REDIRECTS:
            with translation.override(lang):
                target = reverse(LEGACY_REDIRECTS[normalized])

        # Defensive: never redirect a path to itself.
        if target is None or target == path:
            return None
        return target
