from django.http import Http404
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.generic import DetailView, ListView

from .models import Article


class ArticleListView(ListView):
    model = Article
    template_name = "pages/blog/list.html"
    context_object_name = "articles"
    paginate_by = 9

    def get_queryset(self):
        return Article.objects.filter(is_published=True, published_at__lte=timezone.now())


class ArticleDetailView(DetailView):
    model = Article
    template_name = "pages/blog/detail.html"
    context_object_name = "article"
    slug_url_kwarg = "slug"

    def get_object(self, queryset=None):
        obj = get_object_or_404(
            Article.objects.filter(is_published=True, published_at__lte=timezone.now()),
            slug=self.kwargs["slug"],
        )
        return obj

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["related"] = (
            Article.objects.filter(is_published=True, published_at__lte=timezone.now())
            .exclude(pk=self.object.pk)
            .order_by("-published_at")[:3]
        )
        return ctx
