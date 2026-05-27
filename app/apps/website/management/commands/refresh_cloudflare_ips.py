"""Rewrite the Cloudflare CIDR tuples in apps/website/middleware.py.

Cloudflare publishes its edge ranges at /ips-v4 and /ips-v6. They change
slowly (a couple of times a year). Run this monthly via cron, or manually
when you suspect drift:

    docker compose exec web python manage.py refresh_cloudflare_ips
"""
from __future__ import annotations

import re
import urllib.request
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand


IPV4_URL = "https://www.cloudflare.com/ips-v4"
IPV6_URL = "https://www.cloudflare.com/ips-v6"
UA = "MakesetBot/1.0 (+https://makeset.be)"


def _fetch(url: str) -> list[str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=20) as resp:
        text = resp.read().decode("utf-8")
    return [line.strip() for line in text.splitlines() if line.strip()]


def _format_tuple(name: str, cidrs: list[str], per_line: int = 4) -> str:
    quoted = [f'"{c}"' for c in cidrs]
    rows = [", ".join(quoted[i:i + per_line]) for i in range(0, len(quoted), per_line)]
    body = ",\n    ".join(rows)
    return f"{name} = (\n    {body},\n)"


class Command(BaseCommand):
    help = "Refresh the Cloudflare IPv4/IPv6 CIDR lists in apps/website/middleware.py."

    def handle(self, *args, **options):
        ipv4 = _fetch(IPV4_URL)
        ipv6 = _fetch(IPV6_URL)
        self.stdout.write(f"IPv4: {len(ipv4)} ranges, IPv6: {len(ipv6)} ranges")

        path = Path(settings.BASE_DIR) / "apps" / "website" / "middleware.py"
        text = path.read_text(encoding="utf-8")

        new_v4 = _format_tuple("CLOUDFLARE_IPV4", ipv4)
        new_v6 = _format_tuple("CLOUDFLARE_IPV6", ipv6)

        text, n4 = re.subn(
            r"CLOUDFLARE_IPV4 = \([^)]*\)", new_v4, text, count=1, flags=re.DOTALL
        )
        text, n6 = re.subn(
            r"CLOUDFLARE_IPV6 = \([^)]*\)", new_v6, text, count=1, flags=re.DOTALL
        )
        if not (n4 and n6):
            raise RuntimeError("Could not find CLOUDFLARE_IPV4/IPV6 markers in middleware.py")

        path.write_text(text, encoding="utf-8")
        self.stdout.write(self.style.SUCCESS(f"Wrote {path}"))
