from django.utils import timezone
from django.views.generic import TemplateView

from apps.blog.models import Article


class HomeView(TemplateView):
    template_name = "pages/home.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["latest_articles"] = (
            Article.objects
            .filter(is_published=True, published_at__lte=timezone.now())
            .order_by("-published_at")[:3]
        )
        return ctx


class AboutView(TemplateView):
    template_name = "pages/about.html"
