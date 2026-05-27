"""DMARC (RFC 7489) — checks _dmarc.<domain> TXT.

Reads the policy and reporting addresses, flags p=none / sp=none / no rua.
At the very end, after SPF/DKIM/DMARC have all run, synthesises a single
plain-language "Can someone spoof this domain?" verdict that the report
surfaces as the email-section headline.
"""
from __future__ import annotations

import dns.resolver

from .base import (
    CheckResult, Module, ScanContext,
    SEV_CRITICAL, SEV_HIGH, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_PASS,
)


def _parse_dmarc(record: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


def _txt(name: str) -> list[str]:
    try:
        ans = dns.resolver.resolve(name, "TXT", lifetime=4)
    except Exception:
        return []
    return [b"".join(r.strings).decode("utf-8", errors="replace") for r in ans]


def _spf_qualifier(records: list[str]) -> str:
    """Return 'fail' | 'softfail' | 'neutral' | 'permissive' | '' (missing/invalid)."""
    if not records:
        return ""
    lower = records[0].lower()
    if " -all" in lower or lower.endswith("-all"):
        return "fail"
    if " ~all" in lower or lower.endswith("~all"):
        return "softfail"
    if " ?all" in lower or lower.endswith("?all"):
        return "neutral"
    if " +all" in lower or lower.endswith("+all"):
        return "permissive"
    return ""


def _spoof_synthesis(ctx: ScanContext, dmarc_tags: dict[str, str]) -> CheckResult:
    """Combine SPF + DKIM + DMARC into a single grand-public verdict.

    Reads existing data from `ctx.dns_cache`:
      - "SPF"        : list of raw SPF records (may be empty)
      - "DKIM_FOUND" : bool (set by DkimModule)
      - "DMARC"      : parsed tags dict (may be empty if no DMARC)

    Returns one CheckResult whose severity matches the verdict so the report
    can rank it appropriately within the email category.
    """
    spf_records = ctx.dns_cache.get("SPF", []) or []
    spf_q = _spf_qualifier(spf_records)
    dkim_ok = bool(ctx.dns_cache.get("DKIM_FOUND", False))
    dmarc_p = (dmarc_tags.get("p", "") or "").lower()
    aspf = (dmarc_tags.get("aspf", "r") or "r").lower()
    adkim = (dmarc_tags.get("adkim", "r") or "r").lower()

    # Strict alignment + hard SPF + DKIM present + DMARC reject
    if (
        dmarc_p == "reject"
        and dkim_ok
        and spf_q == "fail"
        and aspf == "s"
        and adkim == "s"
    ):
        verdict = "spoof_resistant"
        severity = SEV_PASS
    elif dmarc_p == "reject" and dkim_ok and spf_q in ("fail", "softfail"):
        verdict = "moderate"
        severity = SEV_LOW
    elif dmarc_p == "quarantine" and (dkim_ok or spf_q == "fail"):
        verdict = "moderate"
        severity = SEV_MEDIUM
    elif dmarc_p == "none":
        verdict = "weak"
        severity = SEV_HIGH
    elif not dmarc_p:
        verdict = "spoofable"
        severity = SEV_CRITICAL
    elif spf_q in ("permissive", "neutral", "") and not dkim_ok:
        verdict = "spoofable"
        severity = SEV_CRITICAL
    else:
        verdict = "weak"
        severity = SEV_HIGH

    return CheckResult(
        severity=severity,
        title_key=f"email.synth_{verdict}",
        fix_key="" if verdict == "spoof_resistant" else "email.fix_synth",
        finding={
            "verdict": verdict,
            "spf_qualifier": spf_q,
            "dkim_found": dkim_ok,
            "dmarc_policy": dmarc_p,
            "aspf": aspf,
            "adkim": adkim,
        },
        evidence=(
            f"verdict={verdict} | "
            f"SPF={spf_q or 'missing'} DKIM={'yes' if dkim_ok else 'no'} "
            f"DMARC={dmarc_p or 'missing'} (aspf={aspf}, adkim={adkim})"
        ),
    )


class DmarcModule(Module):
    slug = "dmarc"
    weight = 4

    def run(self, ctx: ScanContext) -> list[CheckResult]:
        records = [r for r in _txt(f"_dmarc.{ctx.domain}") if r.lower().startswith("v=dmarc1")]

        if not records:
            ctx.dns_cache["DMARC"] = {}
            return [
                CheckResult(
                    severity=SEV_CRITICAL,
                    title_key="dmarc.missing",
                    fix_key="dmarc.fix_add_record",
                    evidence="No v=DMARC1 TXT record at _dmarc." + ctx.domain,
                ),
                _spoof_synthesis(ctx, {}),
            ]

        if len(records) > 1:
            ctx.dns_cache["DMARC"] = {}
            return [
                CheckResult(
                    severity=SEV_CRITICAL,
                    title_key="dmarc.multiple",
                    fix_key="dmarc.fix_multiple",
                    finding={"records": records},
                    evidence="\n".join(records),
                ),
                _spoof_synthesis(ctx, {}),
            ]

        record = records[0]
        tags = _parse_dmarc(record)
        ctx.dns_cache["DMARC"] = tags

        out: list[CheckResult] = [CheckResult(
            severity=SEV_PASS,
            title_key="dmarc.found",
            finding=tags,
            evidence=record,
        )]

        policy = tags.get("p", "").lower()
        sub_policy = tags.get("sp", policy).lower()

        if policy == "reject":
            out.append(CheckResult(severity=SEV_PASS, title_key="dmarc.policy_reject"))
        elif policy == "quarantine":
            out.append(CheckResult(
                severity=SEV_MEDIUM,
                title_key="dmarc.policy_quarantine",
                fix_key="dmarc.fix_move_to_reject",
                evidence="p=quarantine, spoofed mail goes to spam folder, not rejected.",
            ))
        elif policy == "none":
            out.append(CheckResult(
                severity=SEV_HIGH,
                title_key="dmarc.policy_none",
                fix_key="dmarc.fix_move_to_reject",
                evidence="p=none, DMARC is in monitor-only mode, no enforcement.",
            ))
        else:
            out.append(CheckResult(
                severity=SEV_HIGH,
                title_key="dmarc.policy_invalid",
                fix_key="dmarc.fix_set_policy",
                evidence=f"Unrecognised p={policy!r}",
            ))

        if sub_policy and sub_policy != policy:
            if sub_policy == "none":
                out.append(CheckResult(
                    severity=SEV_MEDIUM,
                    title_key="dmarc.subpolicy_none",
                    fix_key="dmarc.fix_subpolicy",
                    evidence=f"sp={sub_policy}, sub-domains are not protected.",
                ))

        if not tags.get("rua"):
            out.append(CheckResult(
                severity=SEV_LOW,
                title_key="dmarc.no_rua",
                fix_key="dmarc.fix_add_rua",
                evidence="No rua= aggregate-report address. You won't see who tries to spoof you.",
            ))

        # Always synth at the end so the report has a one-line headline.
        out.append(_spoof_synthesis(ctx, tags))
        return out
