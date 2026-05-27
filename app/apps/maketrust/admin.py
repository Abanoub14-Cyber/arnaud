"""Django admin for MakeTrust models.

Visible at /admin/maketrust/. Lets us:
  * Audit every scan (IP hash prefix, email if provided, status, score, grade).
  * Filter our own dogfooding scans out of traction metrics via the
    `is_internal` boolean — set automatically when a logged-in admin scans,
    can also be toggled manually with the bulk action.
  * Drill into a single scan's findings (inline Checks).

We intentionally don't expose any "delete" or "rerun" actions here — those
are user-facing flows on the public site (rescan FAB, scan abort).
"""
from __future__ import annotations

from django.contrib import admin
from django.utils.html import format_html

from .models import Check, Scan


class CheckInline(admin.TabularInline):
    """Read-only listing of findings attached to a scan. Bulky on big scans
    (~15 rows per finished scan), but the admin user usually opens one
    Scan at a time so it's fine."""
    model = Check
    extra = 0
    fields = ("module", "severity", "title_key", "duration_ms")
    readonly_fields = fields
    can_delete = False

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = (
        "queued_at",
        "domain",
        "status",
        "grade",
        "overall_score",
        "is_internal",
        "requested_email",
        "ip_prefix",
        "duration",
    )
    list_filter = ("is_internal", "status", "grade", "locale")
    search_fields = ("domain", "requested_email", "requested_ip_hash")
    date_hierarchy = "queued_at"
    ordering = ("-queued_at",)
    readonly_fields = (
        "id", "queued_at", "started_at", "finished_at", "scheduled_for",
        "requested_ip_hash", "requested_email_hash", "summary",
        "preview_image_url", "preview_title", "error_message",
    )
    fieldsets = (
        (None, {
            "fields": ("id", "domain", "status", "is_internal"),
        }),
        ("Score", {
            "fields": ("grade", "overall_score", "summary"),
        }),
        ("Visitor", {
            "fields": ("requested_email", "requested_ip_hash",
                       "requested_email_hash", "locale"),
        }),
        ("Scan options", {
            "fields": ("extra_dkim_selectors", "scheduled_for"),
        }),
        ("Timings", {
            "fields": ("queued_at", "started_at", "finished_at"),
        }),
        ("Preview & errors", {
            "fields": ("preview_image_url", "preview_title", "error_message"),
            "classes": ("collapse",),
        }),
    )
    inlines = [CheckInline]

    actions = ["mark_as_internal", "unmark_as_internal"]

    @admin.display(description="IP (prefix)")
    def ip_prefix(self, obj: Scan) -> str:
        if not obj.requested_ip_hash:
            return "—"
        return obj.requested_ip_hash[:12] + "…"

    @admin.display(description="Duration")
    def duration(self, obj: Scan) -> str:
        if not obj.started_at or not obj.finished_at:
            return "—"
        secs = (obj.finished_at - obj.started_at).total_seconds()
        return f"{secs:.1f}s"

    @admin.action(description="Marquer comme scan interne (moi)")
    def mark_as_internal(self, request, queryset):
        updated = queryset.update(is_internal=True)
        self.message_user(request, f"{updated} scan(s) marqué(s) comme internes.")

    @admin.action(description="Démarquer scan interne")
    def unmark_as_internal(self, request, queryset):
        updated = queryset.update(is_internal=False)
        self.message_user(request, f"{updated} scan(s) démarqué(s).")
