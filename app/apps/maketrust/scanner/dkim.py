"""DKIM presence check (RFC 6376).

DKIM selectors aren't discoverable: each domain picks its own. We probe a
list of well-known selectors and report which ones exist. Absence of all
common selectors doesn't *prove* the domain has no DKIM (a custom selector
might be in use), but it's a strong signal a SME audit shouldn't skip.

If the form submitted extra selectors via ``ctx.dns_cache["EXTRA_DKIM_SELECTORS"]``,
we probe those too. That covers Mailcow/Postfix custom setups (ed1/ed2/rsa1/rsa2)
that no generic list can predict.
"""
from __future__ import annotations

import dns.resolver

from .base import (
    CheckResult, Module, ScanContext,
    SEV_HIGH, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_PASS,
)


# Common selectors across providers SMEs typically use. Ordered roughly by
# real-world frequency. Each entry costs one DNS TXT lookup; total worst-case
# wall time is well under 2s in practice because NXDOMAIN replies are fast.
COMMON_SELECTORS = (
    # Generic catch-alls
    "default", "mail", "dkim", "smtp",
    # Microsoft 365 / Exchange Online
    "selector1", "selector2",
    # Google Workspace
    "google",
    # Mailchimp / Mandrill
    "k1", "k2", "k3",
    # Mailgun & friends
    "mxvault", "mg", "mta",
    # Mailcow / Postfix dual-algo (RSA + Ed25519) — covers the user-reported
    # case that motivated this list expansion.
    "rsa", "rsa1", "rsa2",
    "ed", "ed1", "ed2", "ed25519",
    # ProtonMail / Proton Business
    "protonmail", "protonmail2", "protonmail3",
    # Fastmail
    "fm1", "fm2", "fm3",
    # SendGrid
    "s1", "s2",
    # Amazon SES
    "amazonses",
    # Brevo (formerly Sendinblue)
    "sib", "sib1", "sib2",
    # Postmark
    "pm", "pm-bounces",
    # Everlytic
    "everlytickey1", "everlytickey2",
    # Misc providers and minor players
    "mailo", "zoho", "loops", "resend", "tuta",
)


def _query_dkim(domain: str, selector: str) -> str:
    name = f"{selector}._domainkey.{domain}"
    try:
        ans = dns.resolver.resolve(name, "TXT", lifetime=3)
    except Exception:
        return ""
    for r in ans:
        joined = b"".join(r.strings).decode("utf-8", errors="replace")
        if "v=DKIM1" in joined or "k=" in joined or "p=" in joined:
            return joined
    return ""


class DkimModule(Module):
    slug = "dkim"
    weight = 3

    def run(self, ctx: ScanContext) -> list[CheckResult]:
        # Only meaningful when the domain receives/sends email.
        mx = ctx.dns_cache.get("MX", [])
        if not mx:
            ctx.dns_cache["DKIM_FOUND"] = False
            return [CheckResult(
                severity=SEV_INFO,
                title_key="dkim.skipped_no_mx",
                evidence="No MX configured, DKIM probe skipped.",
            )]

        # Combine the standard list with anything the user submitted via the
        # form. Dedupe while preserving insertion order so we probe common
        # ones first and user-supplied custom ones after.
        extra = ctx.dns_cache.get("EXTRA_DKIM_SELECTORS", []) or []
        seen: set[str] = set()
        selectors_to_probe: list[str] = []
        for sel in list(COMMON_SELECTORS) + list(extra):
            if sel and sel not in seen:
                seen.add(sel)
                selectors_to_probe.append(sel)

        found: list[tuple[str, str]] = []
        for selector in selectors_to_probe:
            record = _query_dkim(ctx.domain, selector)
            if record:
                found.append((selector, record))

        ctx.dns_cache["DKIM_FOUND"] = bool(found)

        if found:
            evidence_lines = [f"{s}._domainkey: {r[:120]}" for s, r in found[:3]]
            return [CheckResult(
                severity=SEV_PASS,
                title_key="dkim.found",
                finding={"selectors": [s for s, _ in found]},
                evidence="\n".join(evidence_lines),
            )]

        # Downgrade to MEDIUM: a DNS-only probe can't prove DKIM is absent —
        # the domain may sign with a selector we never tried. HIGH would
        # punish the score for what is technically an unknown, not a fact.
        # Users who know their selector can rescan with `extra_dkim_selectors`.
        return [CheckResult(
            severity=SEV_MEDIUM,
            title_key="dkim.none_common",
            fix_key="dkim.fix_setup",
            finding={"tried": len(selectors_to_probe), "extra_tried": list(extra)},
            evidence=(
                f"None of {len(selectors_to_probe)} probed selectors returned a "
                f"DKIM record. If your domain uses a non-standard selector, add "
                f"it as a custom selector and rescan."
            ),
        )]
