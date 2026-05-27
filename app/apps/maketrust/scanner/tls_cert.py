"""TLS certificate inspection.

Connects on port 443 of the first public IP we resolved, fetches the leaf
certificate, parses it. We never disable verification — if the cert chain
is invalid, the socket layer raises and we report the failure.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509

from .base import (
    CheckResult, Module, ScanContext,
    SEV_CRITICAL, SEV_HIGH, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_PASS,
)
from .site_profile import CACHE_HOME_FAILED


def _fetch_cert(domain: str, ip: str, port: int = 443, timeout: int = 6) -> bytes | None:
    """Open a TLS connection (SNI=domain), pull the peer cert in DER form."""
    ctx_ssl = ssl.create_default_context()
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with ctx_ssl.wrap_socket(sock, server_hostname=domain) as tls:
            return tls.getpeercert(binary_form=True)


class TlsCertModule(Module):
    slug = "tls_cert"
    weight = 5

    def run(self, ctx: ScanContext) -> list[CheckResult]:
        # No website to inspect — skip without burning a 6s+ timeout.
        # site_profile already confirmed there's nothing on 443, so any TLS
        # attempt here would just fail again. We emit INFO so the score
        # isn't penalised for a missing web presence.
        if not ctx.public_ips or ctx.dns_cache.get(CACHE_HOME_FAILED):
            return [CheckResult(
                severity=SEV_INFO,
                title_key="web.skipped_no_homepage",
                evidence="No homepage to inspect — site is unreachable on port 443.",
            )]

        ip = ctx.public_ips[0]
        try:
            der = _fetch_cert(ctx.domain, ip)
        except ssl.SSLCertVerificationError as exc:
            return [CheckResult(
                severity=SEV_CRITICAL,
                title_key="tls.invalid_chain",
                fix_key="tls.fix_invalid_chain",
                evidence=f"{exc.__class__.__name__}: {exc}",
            )]
        except (socket.timeout, socket.gaierror, ConnectionError, ssl.SSLError) as exc:
            # Site responded to HTTPS earlier (site_profile didn't set the
            # home_failed flag) but TLS handshake fails standalone. That's
            # a real, distinct problem — keep HIGH.
            return [CheckResult(
                severity=SEV_HIGH,
                title_key="tls.connection_failed",
                fix_key="tls.fix_connection",
                evidence=f"{exc.__class__.__name__}: {exc}",
            )]

        if not der:
            return [CheckResult(
                severity=SEV_HIGH,
                title_key="tls.no_cert",
                evidence="TLS handshake completed but no certificate was returned.",
            )]

        cert = x509.load_der_x509_certificate(der)
        out: list[CheckResult] = [CheckResult(
            severity=SEV_PASS,
            title_key="tls.handshake_ok",
            evidence=f"Connected to {ip}:443, chain validates.",
        )]

        # Expiry
        not_after = cert.not_valid_after_utc
        days_left = (not_after - datetime.now(timezone.utc)).days
        if days_left < 0:
            out.append(CheckResult(
                severity=SEV_CRITICAL,
                title_key="tls.expired",
                fix_key="tls.fix_renew",
                finding={"not_after": not_after.isoformat(), "days_left": days_left},
                evidence=f"Expired {-days_left} day(s) ago ({not_after}).",
            ))
        elif days_left < 14:
            out.append(CheckResult(
                severity=SEV_HIGH,
                title_key="tls.expiring_soon",
                fix_key="tls.fix_renew",
                finding={"not_after": not_after.isoformat(), "days_left": days_left},
                evidence=f"Expires in {days_left} days.",
            ))
        elif days_left < 30:
            out.append(CheckResult(
                severity=SEV_MEDIUM,
                title_key="tls.expiring_soonish",
                fix_key="tls.fix_renew",
                finding={"not_after": not_after.isoformat(), "days_left": days_left},
                evidence=f"Expires in {days_left} days.",
            ))
        else:
            out.append(CheckResult(
                severity=SEV_PASS,
                title_key="tls.expiry_ok",
                evidence=f"Valid for {days_left} more days (until {not_after.date()}).",
            ))

        # SAN coverage
        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san = []
        covered = ctx.domain in san or f"*.{ctx.domain.split('.', 1)[-1]}" in san
        if san and not covered:
            out.append(CheckResult(
                severity=SEV_HIGH,
                title_key="tls.san_mismatch",
                fix_key="tls.fix_san",
                finding={"san": san},
                evidence=f"Certificate SAN: {', '.join(san[:10])}",
            ))

        return out
