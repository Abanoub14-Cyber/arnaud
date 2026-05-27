"""SPF (Sender Policy Framework) — RFC 7208.

We don't fully evaluate the policy (that needs a recursive lookup count and
mechanism resolution); we just check the structural properties that block
the most common spoofing scenarios.
"""
from __future__ import annotations

import dns.resolver

from .base import (
    CheckResult, Module, ScanContext,
    SEV_CRITICAL, SEV_HIGH, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_PASS,
)


def _txt_records(name: str) -> list[str]:
    try:
        ans = dns.resolver.resolve(name, "TXT", lifetime=4)
    except Exception:
        return []
    out = []
    for r in ans:
        # dnspython splits long TXTs into multiple strings; rejoin.
        joined = b"".join(r.strings).decode("utf-8", errors="replace")
        out.append(joined)
    return out


class SpfModule(Module):
    slug = "spf"
    weight = 4

    def run(self, ctx: ScanContext) -> list[CheckResult]:
        records = [r for r in _txt_records(ctx.domain) if r.lower().startswith("v=spf1")]
        ctx.dns_cache["SPF"] = records

        if len(records) > 1:
            return [CheckResult(
                severity=SEV_CRITICAL,
                title_key="spf.multiple",
                fix_key="spf.fix_multiple",
                finding={"records": records},
                evidence="\n".join(records),
            )]

        if not records:
            return [CheckResult(
                severity=SEV_CRITICAL,
                title_key="spf.missing",
                fix_key="spf.fix_add_record",
                evidence="No v=spf1 TXT record found on the apex.",
            )]

        record = records[0]
        out = [CheckResult(
            severity=SEV_PASS,
            title_key="spf.found",
            finding={"record": record},
            evidence=record,
        )]

        lower = record.lower()
        if " -all" in lower or lower.endswith("-all"):
            policy = "fail"
        elif " ~all" in lower or lower.endswith("~all"):
            policy = "softfail"
        elif " ?all" in lower or lower.endswith("?all"):
            policy = "neutral"
        elif " +all" in lower or lower.endswith("+all"):
            policy = "permissive"
        else:
            policy = "missing"

        if policy == "fail":
            out.append(CheckResult(
                severity=SEV_PASS,
                title_key="spf.policy_strict",
                evidence="Policy: -all (hard fail)",
            ))
        elif policy == "softfail":
            out.append(CheckResult(
                severity=SEV_LOW,
                title_key="spf.policy_soft",
                fix_key="spf.fix_tighten_policy",
                evidence="Policy: ~all (soft fail)",
            ))
        elif policy == "neutral":
            out.append(CheckResult(
                severity=SEV_HIGH,
                title_key="spf.policy_neutral",
                fix_key="spf.fix_tighten_policy",
                evidence="Policy: ?all (neutral), receivers will accept anything.",
            ))
        elif policy == "permissive":
            out.append(CheckResult(
                severity=SEV_CRITICAL,
                title_key="spf.policy_pass_all",
                fix_key="spf.fix_tighten_policy",
                evidence="Policy: +all, anyone can send mail as you.",
            ))
        else:
            out.append(CheckResult(
                severity=SEV_HIGH,
                title_key="spf.policy_missing",
                fix_key="spf.fix_tighten_policy",
                evidence="Record has no terminal -all/~all/?all/+all.",
            ))

        # 10-DNS-lookup limit (RFC 7208 §4.6.4) — count include/a/mx/ptr/exists/redirect
        token_count = sum(record.lower().count(t) for t in (
            "include:", "a:", "mx:", "ptr", "exists:", "redirect="
        ))
        if token_count > 10:
            out.append(CheckResult(
                severity=SEV_HIGH,
                title_key="spf.too_many_lookups",
                fix_key="spf.fix_flatten",
                finding={"count": token_count},
                evidence=f"Approx. {token_count} lookup-triggering mechanisms (max 10).",
            ))

        return out
