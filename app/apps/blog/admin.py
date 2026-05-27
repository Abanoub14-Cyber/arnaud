from django.contrib import admin
from modeltranslation.admin import TranslationAdmin

from .models import Article, Tag


@admin.register(Article)
class ArticleAdmin(TranslationAdmin):
    list_display = ("title", "is_published", "published_at", "reading_time")
    list_filter = ("is_published", "published_at", "tags")
    search_fields = ("title", "slug", "excerpt", "body_html")
    prepopulated_fields = {"slug": ("title",)}
    filter_horizontal = ("tags",)
    fieldsets = (
        (None, {"fields": ("title", "slug", "excerpt", "body_html", "cover", "cover_alt", "meta_description")}),
        ("Publication", {"fields": ("is_published", "published_at", "reading_time", "tags")}),
    )
    date_hierarchy = "published_at"


@admin.register(Tag)
class TagAdmin(TranslationAdmin):
    list_display = ("name", "slug")
    prepopulated_fields = {"slug": ("name",)}
