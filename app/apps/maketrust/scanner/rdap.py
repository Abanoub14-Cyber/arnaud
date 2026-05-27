"""RDAP module — read the registrar, creation date, and expiration date.

RDAP (RFC 7480-7484) is the modern, JSON-based successor to WHOIS. We use
the IANA bootstrap file to discover which RDAP server serves a given TLD,
then query that server for the domain.

Why this matters in a trust scanner:
  * Domain about to expire (< 30 days): users will see a cert error or
    nothing at all very soon. Strong "fix this NOW" finding.
  * Domain just registered (< 30 days): classic phishing / lookalike
    fingerprint. Surfaces as MEDIUM.

Security:
  * No SSRF surface here — we only contact the IANA bootstrap and the RDAP
    server it points us to (an HTTPS endpoint published by ICANN-accredited
    registries). The user-controlled input is the domain name, which is
    already validated upstream by `safety.validate_domain`.
  * Bounded: 5s timeout, 64 KiB response cap, no redirect chasing across
    arbitrary hosts.
  * Bootstrap cached in the Django cache for 24h (it changes weekly at most).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from django.core.cache import cache

from .base import (
    CheckResult, Module, ScanContext,
    SEV_HIGH, SEV_INFO, SEV_MEDIUM, SEV_PASS,
)


BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_CACHE_KEY = "maketrust:rdap:bootstrap"
BOOTSTRAP_CACHE_TTL = 60 * 60 * 24  # 24h
USER_AGENT = "MakeTrustBot/1.0 (+https://makeset.be/tools/maketrust/)"

REQUEST_TIMEOUT = 5.0
# 256 KiB: the IANA bootstrap is ~70 KiB and individual RDAP responses are
# usually under 16 KiB, but registrar payloads occasionally include large
# nameserver lists. Keep enough headroom without giving a hostile RDAP
# server room to OOM us.
MAX_BYTES = 256 * 1024


def _fetch_json(url: str) -> dict | None:
    """Tight JSON fetcher: timeout, byte cap, no redirect to surprise hosts.

    Returns parsed dict or None on any kind of failure.
    """
    import requests
    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json, application/json"},
            stream=True,
        )
    except Exception:
        return None
    if resp.status_code != 200:
        resp.close()
        return None

    body = b""
    try:
        for chunk in resp.iter_content(chunk_size=8192):
            body += chunk
            if len(body) >= MAX_BYTES:
                # Hard stop: anything beyond the cap is not parsed. Returning
                # None here is safer than parsing a truncated JSON document.
                resp.close()
                return None
    except Exception:
        return None
    finally:
        resp.close()

    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except (ValueError, UnicodeError):
        return None


def _bootstrap_for_tld(tld: str) -> str | None:
    """Return the canonical RDAP base URL for `tld`, or None if unsupported."""
    cached = cache.get(BOOTSTRAP_CACHE_KEY)
    if cached is None:
        cached = _fetch_json(BOOTSTRAP_URL)
        if cached is None:
            return None
        cache.set(BOOTSTRAP_CACHE_KEY, cached, BOOTSTRAP_CACHE_TTL)

    for entry in cached.get("services", []):
        # Each entry is [["tld1", "tld2", ...], ["url1", "url2", ...]]
        if not isinstance(entry, list) or len(entry) != 2:
            continue
        tlds, urls = entry
        if tld in [t.lower() for t in tlds]:
            for u in urls:
                if u.startswith("https://"):
                    return u.rstrip("/") + "/"
    return None


def _parse_event_date(events: list, action: str) -> datetime | None:
    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        if (ev.get("eventAction") or "").lower() == action:
            date_str = ev.get("eventDate", "")
            try:
                return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            except ValueError:
                continue
    return None


def _registrar_name(entities: list) -> str:
    """Pull a human-readable registrar name out of an RDAP entity array."""
    for ent in entities or []:
        if not isinstance(ent, dict):
            continue
        roles = [r.lower() for r in ent.get("roles", [])]
        if "registrar" not in roles:
            continue
        # Prefer the vCard FN field; fall back to the `handle` if absent.
        vcard = ent.get("vcardArray") or []
        if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
            for field in vcard[1]:
                if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                    name = field[3]
                    if isinstance(name, str) and name.strip():
                        return name.strip()
        if isinstance(ent.get("handle"), str):
            return ent["handle"]
    return ""


class RdapModule(Module):
    slug = "rdap"
    weight = 1

    def run(self, ctx: ScanContext) -> list[CheckResult]:
        # The TLD is what we look up in the bootstrap.
        tld = ctx.domain.rsplit(".", 1)[-1].lower()
        base = _bootstrap_for_tld(tld)
        if not base:
            return [CheckResult(
                severity=SEV_INFO,
                title_key="rdap.unavailable",
                evidence=f"No RDAP server published for .{tld} in IANA bootstrap.",
            )]

        url = f"{base}domain/{ctx.domain}"
        data = _fetch_json(url)
        if data is None:
            return [CheckResult(
                severity=SEV_INFO,
                title_key="rdap.unavailable",
                evidence=f"RDAP query to {url} failed or timed out.",
            )]

        events = data.get("events") or []
        registrar = _registrar_name(data.get("entities") or [])
        created = _parse_event_date(events, "registration")
        expires = _parse_event_date(events, "expiration")

        results: list[CheckResult] = []
        finding = {
            "registrar": registrar,
            "created_at": created.isoformat() if created else "",
            "expires_at": expires.isoformat() if expires else "",
        }

        now = datetime.now(timezone.utc)
        if expires:
            days_left = (expires - now).days
            if days_left < 0:
                results.append(CheckResult(
                    severity=SEV_HIGH,
                    title_key="rdap.expired",
                    fix_key="rdap.fix_renew",
                    finding={**finding, "days_left": days_left},
                    evidence=f"Domain expired {-days_left} day(s) ago ({expires.date()}).",
                ))
            elif days_left < 30:
                results.append(CheckResult(
                    severity=SEV_HIGH,
                    title_key="rdap.expiring_soon",
                    fix_key="rdap.fix_renew",
                    finding={**finding, "days_left": days_left},
                    evidence=f"Expires in {days_left} day(s) ({expires.date()}).",
                ))
            else:
                results.append(CheckResult(
                    severity=SEV_PASS,
                    title_key="rdap.expiry_ok",
                    finding=finding,
                    evidence=(
                        f"Registered with {registrar or 'unknown'}; "
                        f"expires {expires.date()} (~{days_left}d)."
                    ),
                ))

        if created:
            age_days = (now - created).days
            if age_days < 30:
                results.append(CheckResult(
                    severity=SEV_MEDIUM,
                    title_key="rdap.recently_registered",
                    fix_key="rdap.fix_recent",
                    finding={**finding, "age_days": age_days},
                    evidence=(
                        f"Domain created {age_days} day(s) ago ({created.date()}). "
                        "Common phishing fingerprint."
                    ),
                ))

        if not results:
            # No usable events. Surface what we got at INFO so we don't penalise.
            results.append(CheckResult(
                severity=SEV_INFO,
                title_key="rdap.partial",
                finding=finding,
                evidence="RDAP responded but did not provide registration or expiration dates.",
            ))

        return results
