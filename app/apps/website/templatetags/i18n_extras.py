from django import template
from django.urls import resolve, reverse
from django.urls import translate_url as django_translate_url
from django.urls.exceptions import Resolver404
from django.utils import translation

register = template.Library()


@register.simple_tag
def translate_url(url: str, lang_code: str) -> str:
    """Translate a URL path to a target language.

    Falls back to django.urls.translate_url for routes whose slug doesn't
    change between languages. For routes with translatable slugs (currently
    blog_detail), this resolver-aware version looks up the corresponding
    object in the target language so the resulting URL stays valid.

    Example:
        translate_url('/blog/conformite-nis2-belgique-2026/', 'en')
        -> '/en/blog/nis2-compliance-belgium-2026/'
    """
    try:
        match = resolve(url)
    except Resolver404:
        return django_translate_url(url, lang_code)

    if match.url_name == "blog_detail":
        from apps.blog.models import Article

        current_slug = match.kwargs.get("slug", "")
        article = (
            Article.objects.filter(slug_fr=current_slug).first()
            or Article.objects.filter(slug_en=current_slug).first()
        )
        if article is not None:
            target_slug = article.slug_en if lang_code.startswith("en") else article.slug_fr
            if target_slug:
                with translation.override(lang_code):
                    return reverse("blog_detail", kwargs={"slug": target_slug})

    return django_translate_url(url, lang_code)
