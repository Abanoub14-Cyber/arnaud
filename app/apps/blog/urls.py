from django.urls import path
from django.utils.translation import gettext_lazy as _

from . import views
from .feeds import LatestArticlesFeed

urlpatterns = [
    path(_("blog/"), views.ArticleListView.as_view(), name="blog_list"),
    path(_("blog/") + "<slug:slug>/", views.ArticleDetailView.as_view(), name="blog_detail"),
    path(_("blog/") + "feed.xml", LatestArticlesFeed(), name="blog_feed"),
]
