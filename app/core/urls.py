"""Project URL configuration."""
from django.conf import settings
from django.conf.urls.i18n import i18n_patterns
from django.contrib import admin
from django.contrib.sitemaps.views import sitemap
from django.urls import include, path, re_path
from django.utils.translation import gettext_lazy as _
from django.views.generic import TemplateView
from django.views.static import serve as static_serve

from apps.website.sitemaps import sitemaps_dict

urlpatterns = [
    path("admin/", admin.site.urls),
    path("i18n/", include("django.conf.urls.i18n")),
    path("robots.txt", TemplateView.as_view(template_name="robots.txt", content_type="text/plain")),
    path("sitemap.xml", sitemap, {"sitemaps": sitemaps_dict}, name="django.contrib.sitemaps.views.sitemap"),
]

urlpatterns += i18n_patterns(
    path("", include("apps.website.urls")),
    path("", include("apps.services.urls")),
    path("", include("apps.blog.urls")),
    path("", include("apps.contact.urls")),
    path("", include("apps.tools.urls")),
    path(_("outils/maketrust/"), include("apps.maketrust.urls")),
    path("", include("apps.legal.urls")),
    prefix_default_language=False,  # FR (default) at root, EN under /en/. Faster for FR visitors, no redirect.
)

# Media files are served by Django (small site, low volume of uploads).
# Move to traefik static routing if /media/ traffic ever becomes significant.
# django.conf.urls.static.static() returns [] when DEBUG=False so we bypass it
# and call django.views.static.serve directly.
urlpatterns += [
    re_path(
        rf"^{settings.MEDIA_URL.lstrip('/')}(?P<path>.*)$",
        static_serve,
        {"document_root": settings.MEDIA_ROOT},
    ),
]

if settings.DEBUG:
    try:
        import debug_toolbar

        urlpatterns += [path("__debug__/", include(debug_toolbar.urls))]
    except ImportError:
        pass
