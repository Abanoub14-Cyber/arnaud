"""DNSSEC detection.

We try two independent signals:

1. The domain has DNSKEY records (it publishes its signing keys).
2. The parent zone has DS records for it (the chain of trust starts).

Either alone is not conclusive (a misconfigured zone has DNSKEY but no DS, or
vice versa). For a clean PASS we want both. Anything else is a warning.
"""
from __future__ import annotations

import dns.exception
import dns.resolver
import dns.rdatatype

from .base import (
    CheckResult, Module, ScanContext,
    SEV_INFO, SEV_LOW, SEV_PASS,
)


def _has_records(name: str, rtype: str) -> bool:
    try:
        ans = dns.resolver.resolve(name, rtype, lifetime=4)
        return any(True for _ in ans)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return False


class DnssecModule(Module):
    slug = "dnssec"
    weight = 2

    def run(self, ctx: ScanContext) -> list[CheckResult]:
        has_dnskey = _has_records(ctx.domain, "DNSKEY")
        has_ds = _has_records(ctx.domain, "DS")

        if has_dnskey and has_ds:
            return [CheckResult(
                severity=SEV_PASS,
                title_key="dnssec.signed",
                finding={"dnskey": True, "ds": True},
                evidence="DNSKEY and DS records both present.",
            )]

        if has_dnskey or has_ds:
            return [CheckResult(
                severity=SEV_LOW,
                title_key="dnssec.partial",
                fix_key="dnssec.fix_complete",
                finding={"dnskey": has_dnskey, "ds": has_ds},
                evidence=(
                    f"DNSKEY: {has_dnskey}, DS: {has_ds} — chain of trust incomplete."
                    .replace(" — ", ", ")
                ),
            )]

        return [CheckResult(
            severity=SEV_LOW,
            title_key="dnssec.unsigned",
            fix_key="dnssec.fix_enable",
            evidence="No DNSKEY nor DS records found.",
        )]
