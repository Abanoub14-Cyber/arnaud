"""Recompute ``overall_score`` / ``grade`` on every completed Scan.

Use when the scoring formula in ``scoring.py`` changes and we want the
existing scans (rendered in the report page + propagated to the prospect
CRM) to reflect the new formula instead of staying frozen on the old
score from when they were originally computed.

Default mode prints a per-scan diff and aborts without writing. Pass
``--apply`` to actually save the new values. The Check rows themselves
are never touched - the command only recomputes the derived score, grade
and summary from the existing checks.
"""
from __future__ import annotations

from django.core.management.base import BaseCommand

from apps.maketrust.models import Check, Scan
from apps.maketrust.scanner.orchestrator import _registered_modules
from apps.maketrust.scoring import compute_grade, compute_summary


class Command(BaseCommand):
    help = "Recompute overall_score and grade on every completed Scan."

    def add_arguments(self, parser):
        parser.add_argument(
            "--apply", action="store_true",
            help="Persist the new scores. Without this flag, prints a diff and exits.",
        )

    def handle(self, *args, **opts):
        modules = _registered_modules()
        apply = bool(opts["apply"])

        qs = Scan.objects.filter(status=Scan.Status.DONE).order_by("finished_at")
        total = qs.count()
        if total == 0:
            self.stdout.write("No completed scans to recompute.")
            return

        changed = 0
        unchanged = 0
        for scan in qs.iterator():
            checks = list(Check.objects.filter(scan=scan))
            if not checks:
                continue
            new_score, new_grade = compute_grade(checks, modules)
            new_summary = compute_summary(checks)
            if (
                new_score == scan.overall_score
                and new_grade == scan.grade
                and new_summary == scan.summary
            ):
                unchanged += 1
                continue

            self.stdout.write(
                f"  {scan.domain:<40} "
                f"{scan.overall_score}/{scan.grade or '-'} -> "
                f"{new_score}/{new_grade}"
            )
            changed += 1

            if apply:
                scan.overall_score = new_score
                scan.grade = new_grade
                scan.summary = new_summary
                scan.save(update_fields=["overall_score", "grade", "summary"])

        verb = "Updated" if apply else "Would update"
        self.stdout.write(self.style.SUCCESS(
            f"{verb} {changed} scan(s). {unchanged} unchanged. {total} total."
        ))
        if not apply and changed:
            self.stdout.write(self.style.WARNING(
                "Dry-run only. Re-run with --apply to persist."
            ))
