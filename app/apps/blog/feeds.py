from django.contrib.syndication.views import Feed
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .models import Article


class LatestArticlesFeed(Feed):
    title = _("Makeset - Blog")
    description = _("Derniers articles du blog Makeset.")

    def link(self):
        return reverse("blog_list")

    def items(self):
        return (
            Article.objects.filter(is_published=True, published_at__lte=timezone.now())
            .order_by("-published_at")[:20]
        )

    def item_title(self, item):
        return item.title

    def item_description(self, item):
        return item.excerpt

    def item_pubdate(self, item):
        return item.published_at
