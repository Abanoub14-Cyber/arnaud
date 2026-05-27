from datetime import date

from django.contrib.sitemaps import Sitemap
from django.urls import reverse

from apps.blog.models import Article

# Bump this when shipping non-trivial content changes to static pages so
# crawlers see a fresh <lastmod> in sitemap.xml. Honest lastmod > faked now().
STATIC_PAGES_LASTMOD = date(2026, 5, 17)


class StaticViewSitemap(Sitemap):
    """Static pages with fixed URL names. i18n=True emits hreflang per language."""

    i18n = True
    protocol = "https"
    changefreq = "monthly"

    def items(self):
        return [
            ("home", 1.0),
            ("services_index", 0.9),
            ("service_cyber", 0.8),
            ("service_web", 0.8),
            ("service_ia", 0.8),
            ("service_support", 0.8),
            ("blog_list", 0.8),
            ("about", 0.7),
            ("contact", 0.7),
            ("tools_index", 0.5),
            ("maketrust:landing", 0.8),
            ("legal_mentions", 0.3),
            ("legal_privacy", 0.3),
            ("legal_terms", 0.3),
            ("cookies", 0.3),
        ]

    def location(self, obj):
        return reverse(obj[0])

    def priority(self, obj):
        return obj[1]

    def lastmod(self, obj):
        return STATIC_PAGES_LASTMOD


class ArticleSitemap(Sitemap):
    """Blog articles. Single URL per article (slug), regardless of language."""

    protocol = "https"
    changefreq = "monthly"
    priority = 0.6

    def items(self):
        from django.utils import timezone

        return Article.objects.filter(is_published=True, published_at__lte=timezone.now())

    def lastmod(self, obj):
        return obj.updated_at


sitemaps_dict = {
    "static": StaticViewSitemap,
    "articles": ArticleSitemap,
}
