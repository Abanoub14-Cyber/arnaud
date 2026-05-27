"""Import the three legacy PHP articles into the new blog model."""
from __future__ import annotations

import re
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from textwrap import dedent

from django.core.files import File
from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.blog.models import Article


class _BodyExtractor(HTMLParser):
    """Capture everything inside <div class="article-body">...</div>."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.depth = 0
        self.capture = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if not self.capture and tag == "div" and "article-body" in (attrs_dict.get("class") or ""):
            self.capture = True
            self.depth = 1
            return
        if self.capture:
            self.depth += 1
            attrs_str = "".join(f' {k}="{v}"' for k, v in attrs if v is not None)
            self.parts.append(f"<{tag}{attrs_str}>")

    def handle_endtag(self, tag: str) -> None:
        if not self.capture:
            return
        self.depth -= 1
        if self.depth == 0:
            self.capture = False
            return
        self.parts.append(f"</{tag}>")

    def handle_startendtag(self, tag, attrs):
        if self.capture:
            attrs_str = "".join(f' {k}="{v}"' for k, v in attrs if v is not None)
            self.parts.append(f"<{tag}{attrs_str} />")

    def handle_data(self, data: str) -> None:
        if self.capture:
            self.parts.append(data)

    def handle_entityref(self, name: str) -> None:
        if self.capture:
            self.parts.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        if self.capture:
            self.parts.append(f"&#{name};")


def extract_body(html: str) -> str:
    parser = _BodyExtractor()
    parser.feed(html)
    return "".join(parser.parts).strip()


def first_match(pattern: str, text: str, default: str = "") -> str:
    m = re.search(pattern, text, flags=re.DOTALL)
    return (m.group(1) if m else default).strip()


def reading_time_minutes(html: str) -> int:
    text = re.sub(r"<[^>]+>", " ", html)
    words = len(text.split())
    return max(1, round(words / 220))


# ----------------------------------------------------------------------------
# One config per legacy article. The slug here is the new Django slug.
# ----------------------------------------------------------------------------
ARTICLES = [
    {
        "slug": "nis2-compliance-belgium-2026",
        "legacy_php": "articles/nis2-compliance-belgium-2026.php",
        "cover_src": "assets/images/blogs/NIS2_image.png",
        "published_at": "2026-02-15",
    },
    {
        "slug": "ai-agents-small-business-2026",
        "legacy_php": "articles/ai-agents-small-business-2026.php",
        "cover_src": "assets/images/blogs/automatisation_image.png",
        "published_at": "2026-03-10",
    },
    {
        "slug": "cybersecurity-framework-small-business",
        "legacy_php": "articles/cybersecurity-framework-small-business.php",
        "cover_src": "assets/images/blogs/cyfun_image.png",
        "published_at": "2026-01-20",
    },
]


class Command(BaseCommand):
    help = "Import the three legacy PHP articles into the new blog model."

    def add_arguments(self, parser):
        parser.add_argument(
            "--repo-root",
            default=str(Path("/var/www/makeset")),
            help="Path to the repo root (where assets/ and articles/ live).",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Overwrite an existing article with the same slug.",
        )

    def handle(self, *args, repo_root: str, force: bool, **options):
        root = Path(repo_root)
        for cfg in ARTICLES:
            self._import_one(root, cfg, force=force)

    def _import_one(self, root: Path, cfg: dict, force: bool) -> None:
        php_path = root / cfg["legacy_php"]
        cover_path = root / cfg["cover_src"]
        if not php_path.exists():
            self.stderr.write(f"  legacy file not found: {php_path}")
            return

        html = php_path.read_text(encoding="utf-8")
        title = first_match(r"<title>(.*?)\s*\|\s*Makeset</title>", html)
        if not title:
            title = first_match(r"<title>(.*?)</title>", html)
        meta_desc = first_match(r'<meta name="description" content="([^"]+)"', html)
        body = extract_body(html)

        if not body:
            self.stderr.write(f"  could not extract body from {php_path}")
            return

        # The first <p> in the article body is typically a strong intro - reuse as excerpt.
        first_p = first_match(r"<p[^>]*>(.+?)</p>", body)
        excerpt = re.sub(r"<[^>]+>", "", first_p)[:300].rstrip(" ,;.") + "..."

        published_at = timezone.make_aware(
            datetime.strptime(cfg["published_at"], "%Y-%m-%d"),
            timezone.get_current_timezone(),
        )

        existing = Article.objects.filter(slug=cfg["slug"]).first()
        if existing and not force:
            self.stdout.write(self.style.WARNING(f"  skip (exists): {cfg['slug']}"))
            return

        article = existing or Article(slug=cfg["slug"])
        article.title_en = title
        article.title_fr = title  # placeholder until a real FR translation is done
        article.excerpt_en = excerpt
        article.excerpt_fr = excerpt
        article.body_html_en = body
        article.body_html_fr = body
        article.cover_alt_en = title
        article.cover_alt_fr = title
        article.meta_description_en = meta_desc[:200]
        article.meta_description_fr = meta_desc[:200]
        article.reading_time = reading_time_minutes(body)
        article.published_at = published_at
        article.is_published = True
        article.save()

        if cover_path.exists():
            with cover_path.open("rb") as fh:
                article.cover.save(cover_path.name, File(fh), save=True)

        self.stdout.write(self.style.SUCCESS(f"  imported: {cfg['slug']}"))
