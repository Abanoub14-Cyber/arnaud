"""Turn ``Check`` rows into a 0-100 score and an A+/A/B/C/D/F grade.

The intent is *intelligibility*: a domain with no DMARC and no HSTS lands
mid-C, not pristine. We don't try to model everything — we punish the
real risks.

Algorithm:

1. Each finding has a severity-derived penalty and inherits its module's
   weight. Penalty = severity_weight * module_weight.
2. The maximum possible penalty is recomputed from the modules registered.
3. score = clamp(100 - 100 * (penalty / max_penalty)).
4. Grade: 95+ A+, 85+ A, 75+ B, 60+ C, 45+ D, else F.
5. ``compute_summary`` counts findings per severity for the dashboard.
"""
from __future__ import annotations

from collections import Counter
from typing import Iterable

from .scanner.base import Module


SEVERITY_WEIGHT = {
    "pass": 0,
    "info": 0,
    "low": 2,
    "medium": 5,
    "high": 9,
    "critical": 14,
}


def compute_summary(checks: Iterable) -> dict[str, int]:
    counts = Counter(c.severity for c in checks)
    return {sev: counts.get(sev, 0) for sev in SEVERITY_WEIGHT}


def compute_grade(checks: Iterable, modules: list[type[Module]]) -> tuple[int, str]:
    by_module = {cls.slug: cls.weight for cls in modules}

    # Bucket findings per module so we can apply a per-module cap before
    # summing. Without the cap, a module like ``http_headers`` (which can
    # legitimately emit 5-7 distinct findings on the same scan: missing
    # HSTS + clickjacking + Referrer-Policy + Permissions-Policy + …) ends
    # up contributing 4-5x more penalty than other modules, even though
    # they all stem from the same root cause ("the server has no security
    # headers"). The cap puts an upper bound on any single module so a
    # scan can't be tanked by a single category of issue.
    per_module_raw: dict[str, list[int]] = {}
    for c in checks:
        sev_w = SEVERITY_WEIGHT.get(c.severity, 0)
        if sev_w == 0:
            continue
        per_module_raw.setdefault(c.module, []).append(sev_w)

    high_w = SEVERITY_WEIGHT["high"]
    penalty = 0.0
    for module_slug, sev_weights in per_module_raw.items():
        weight = by_module.get(module_slug, 1)
        raw = sum(sev_weights) * weight
        # The cap is the larger of (a) the most severe finding in the
        # module (so a single critical is never softened) and (b) the
        # equivalent of one ``high`` finding (so a noisy module emitting
        # many lows still gets counted but capped at "one significant issue").
        cap = max(max(sev_weights), high_w) * weight
        penalty += min(raw, cap)

    # Reference penalty: each module contributes its weight × max severity once.
    # Tuned so a single critical in one module knocks ~10 points; an all-critical
    # site lands at 0.
    reference = sum(weight * SEVERITY_WEIGHT["high"] for weight in by_module.values()) or 1
    score = max(0, min(100, round(100 - 100 * (penalty / reference))))

    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 45:
        grade = "D"
    else:
        grade = "F"
    return score, grade
