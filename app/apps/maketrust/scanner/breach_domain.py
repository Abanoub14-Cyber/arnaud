"""Domain-level breach lookup via Have I Been Pwned.

The free HIBP endpoint at /api/v3/breaches?domain=<d> returns every public
breach that affected the domain. No API key needed. We cache responses for
24 hours to be polite to HIBP and to keep our scan fast.

Severity:

* No breach found            -> pass
* Old breach (>3 years)      -> info
* Breach within last 3 years -> medium
* Breach within last year    -> high
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from datetime import date, datetime
from typing import Any

from django.core.cache import cache

from .base import (
    CheckResult, Module, ScanContext,
    SEV_HIGH, SEV_INFO, SEV_MEDIUM, SEV_PASS,
)


HIBP_URL = "https://haveibeenpwned.com/api/v3/breaches"
USER_AGENT = "MakeTrustBot/1.0 (+https://makeset.be/tools/maketrust/)"
CACHE_PREFIX = "maketrust:hibp:"
CACHE_TTL = 60 * 60 * 24  # 24 hours


def _fetch_breaches(domain: str) -> list[dict] | None:
    """None means the API call failed; an empty list means no breaches."""
    cached = cache.get(CACHE_PREFIX + domain)
    if cached is not None:
        return cached

    qs = urllib.parse.urlencode({"domain": domain})
    req = urllib.request.Request(
        f"{HIBP_URL}?{qs}",
        headers={"User-Agent": USER_AGENT, "hibp-api-version": "3"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
    except Exception:
        return None

    cache.set(CACHE_PREFIX + domain, data, CACHE_TTL)
    return data


def _years_since(iso_date: str) -> float:
    try:
        d = datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
    except ValueError:
        try:
            d = datetime.combine(date.fromisoformat(iso_date), datetime.min.time())
        except ValueError:
            return 999.0
    return (datetime.now(d.tzinfo) - d).days / 365.0


class BreachDomainModule(Module):
    slug = "breach_domain"
    weight = 2

    def run(self, ctx: ScanContext) -> list[CheckResult]:
        breaches = _fetch_breaches(ctx.domain)

        if breaches is None:
            return [CheckResult(
                severity=SEV_INFO,
                title_key="breach.api_unavailable",
                evidence="HIBP API did not respond (rate limit or network).",
            )]

        if not breaches:
            return [CheckResult(
                severity=SEV_PASS,
                title_key="breach.none",
                evidence="No public breach references your domain.",
            )]

        most_recent_years = min(
            (_years_since(b.get("BreachDate", "")) for b in breaches),
            default=999.0,
        )
        if most_recent_years < 1:
            severity = SEV_HIGH
            title = "breach.recent"
        elif most_recent_years < 3:
            severity = SEV_MEDIUM
            title = "breach.medium"
        else:
            severity = SEV_INFO
            title = "breach.old"

        # Build a compact evidence string with the top 5 breaches.
        sorted_b = sorted(
            breaches, key=lambda b: b.get("BreachDate", ""), reverse=True
        )
        lines = [
            f"{b.get('BreachDate', '?')} {b.get('Title', b.get('Name', '?'))} "
            f"(~{b.get('PwnCount', 0):,} accounts)"
            for b in sorted_b[:5]
        ]
        if len(breaches) > 5:
            lines.append(f"... and {len(breaches) - 5} more")
        return [CheckResult(
            severity=severity,
            title_key=title,
            fix_key="breach.fix_followup",
            finding={
                "count": len(breaches),
                "most_recent_years": round(most_recent_years, 1),
            },
            evidence="\n".join(lines),
        )]
