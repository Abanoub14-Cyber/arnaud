from django.contrib import admin

from .models import ContactMessage


@admin.register(ContactMessage)
class ContactMessageAdmin(admin.ModelAdmin):
    list_display = ("created_at", "name", "email", "service", "company", "handled")
    list_filter = ("service", "handled", "created_at", "locale")
    search_fields = ("name", "email", "company", "message")
    readonly_fields = ("created_at", "ip", "user_agent", "referer", "locale")
    list_editable = ("handled",)
    fieldsets = (
        (None, {"fields": ("name", "email", "company", "service", "message", "handled")}),
        ("Metadata", {"fields": ("created_at", "ip", "user_agent", "referer", "locale"), "classes": ("collapse",)}),
    )
