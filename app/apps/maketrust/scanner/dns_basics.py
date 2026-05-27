"""Resolve A/AAAA, NS, MX, CAA. Records used by other modules end up in
``ctx.dns_cache`` so we don't query the same name twice.
"""
from __future__ import annotations

import dns.resolver
import dns.rdatatype

from .base import (
    CheckResult, Module, ScanContext,
    SEV_HIGH, SEV_INFO, SEV_LOW, SEV_PASS,
)


def _query(name: str, rtype: str) -> list[str]:
    try:
        ans = dns.resolver.resolve(name, rtype, lifetime=4)
        return [r.to_text().strip('"') for r in ans]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


class DnsBasicsModule(Module):
    slug = "dns_basics"
    weight = 2

    def run(self, ctx: ScanContext) -> list[CheckResult]:
        out: list[CheckResult] = []

        a_records = _query(ctx.domain, "A")
        aaaa_records = _query(ctx.domain, "AAAA")
        ctx.dns_cache["A"] = a_records
        ctx.dns_cache["AAAA"] = aaaa_records

        if a_records or aaaa_records:
            out.append(CheckResult(
                severity=SEV_PASS,
                title_key="dns.resolves",
                finding={"a": a_records, "aaaa": aaaa_records},
                evidence=", ".join(a_records + aaaa_records),
            ))
        else:
            out.append(CheckResult(
                severity=SEV_HIGH,
                title_key="dns.no_records",
                fix_key="dns.fix_add_records",
                evidence="No A or AAAA record on the apex.",
            ))

        if not aaaa_records:
            out.append(CheckResult(
                severity=SEV_INFO,
                title_key="dns.no_ipv6",
                fix_key="dns.fix_add_ipv6",
            ))

        # MX — used by SPF/DMARC modules later via cache.
        mx = _query(ctx.domain, "MX")
        ctx.dns_cache["MX"] = mx
        if mx:
            out.append(CheckResult(
                severity=SEV_PASS,
                title_key="dns.has_mx",
                finding={"mx": mx},
                evidence="\n".join(mx),
            ))
        else:
            out.append(CheckResult(
                severity=SEV_INFO,
                title_key="dns.no_mx",
                evidence="No MX record, domain does not receive email.",
            ))

        # CAA — restricts which CAs can issue certs.
        caa = _query(ctx.domain, "CAA")
        if caa:
            out.append(CheckResult(
                severity=SEV_PASS,
                title_key="dns.has_caa",
                finding={"caa": caa},
                evidence="\n".join(caa),
            ))
        else:
            out.append(CheckResult(
                severity=SEV_LOW,
                title_key="dns.no_caa",
                fix_key="dns.fix_add_caa",
                evidence="No CAA record, any CA can issue a cert for this domain.",
            ))

        return out
