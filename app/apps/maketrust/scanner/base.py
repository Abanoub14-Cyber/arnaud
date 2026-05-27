"""Shared scaffolding for scanner modules.

Every module subclasses ``Module`` and returns a list of ``CheckResult``s.
The orchestrator never inspects internals — it just instantiates, calls
``run(ctx)``, and persists what comes back.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# --- Severity / category constants (string literals match models.Check) ---

SEV_PASS = "pass"
SEV_INFO = "info"
SEV_LOW = "low"
SEV_MEDIUM = "medium"
SEV_HIGH = "high"
SEV_CRITICAL = "critical"

# Category routing lives in findings.MODULE_TO_CATEGORY now — modules
# don't declare their own category attribute any more.
CAT_TECH = "tech"          # CMS / framework freshness


@dataclass
class CheckResult:
    """One finding ready to persist as a row in ``Check``."""
    severity: str
    title_key: str
    fix_key: str = ""
    finding: dict[str, Any] = field(default_factory=dict)
    evidence: str = ""


@dataclass
class ScanContext:
    """Read-only context the orchestrator hands to every module.

    ``dns_cache`` is a per-scan dict so modules can share lookups without
    re-querying. Modules MUST treat it as append-only and never mutate
    values placed by another module.
    """
    domain: str
    public_ips: list[str]
    dns_cache: dict[str, Any] = field(default_factory=dict)


class Module:
    """Base class. Subclasses set ``slug`` and ``weight``."""

    slug: str = ""
    category: str = ""
    # Relative weight inside its category. Used by scoring.py.
    weight: int = 1

    def run(self, ctx: ScanContext) -> list[CheckResult]:
        raise NotImplementedError
