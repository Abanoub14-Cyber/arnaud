from modeltranslation.translator import TranslationOptions, register

from .models import Article, Tag


@register(Article)
class ArticleTranslationOptions(TranslationOptions):
    fields = ("slug", "title", "excerpt", "body_html", "cover_alt", "meta_description")


@register(Tag)
class TagTranslationOptions(TranslationOptions):
    fields = ("name",)
