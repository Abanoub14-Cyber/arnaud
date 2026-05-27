from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _


class Tag(models.Model):
    slug = models.SlugField(unique=True, max_length=80)
    name = models.CharField(_("Nom"), max_length=80)

    class Meta:
        verbose_name = _("Tag")
        verbose_name_plural = _("Tags")
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class Article(models.Model):
    slug = models.SlugField(_("Slug"), unique=True, max_length=200)
    title = models.CharField(_("Titre"), max_length=200)
    excerpt = models.TextField(_("Extrait"), help_text=_("1 ou 2 phrases qui résument l'article."))
    body_html = models.TextField(_("Corps HTML"), help_text=_("Contenu de l'article en HTML."))
    cover = models.ImageField(_("Image de couverture"), upload_to="blog/", blank=True)
    cover_alt = models.CharField(_("Texte alternatif"), max_length=200, blank=True)
    meta_description = models.CharField(_("Meta description"), max_length=200, blank=True)
    reading_time = models.PositiveSmallIntegerField(_("Temps de lecture (min)"), default=5)

    tags = models.ManyToManyField(Tag, blank=True, related_name="articles", verbose_name=_("Tags"))

    published_at = models.DateTimeField(_("Date de publication"))
    is_published = models.BooleanField(_("Publié"), default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("Article")
        verbose_name_plural = _("Articles")
        ordering = ["-published_at"]
        indexes = [
            models.Index(fields=["-published_at", "is_published"]),
        ]

    def __str__(self) -> str:
        return self.title

    def get_absolute_url(self) -> str:
        return reverse("blog_detail", kwargs={"slug": self.slug})
