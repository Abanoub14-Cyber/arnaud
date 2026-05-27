"""
Regenerates the Material Symbols Outlined woff2 subset from the icons actually
used in templates and blog articles. Run after adding a new icon anywhere:

    docker compose exec web python manage.py rebuild_material_symbols
"""
from __future__ import annotations

import re
import urllib.request
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand


TEMPLATE_PATTERNS = [
    # Plain: <span class="material-symbols-outlined ...">icon_name<
    re.compile(r'class="[^"]*material-symbols-outlined[^"]*"[^>]*>([a-z0-9_]+)<'),
    # Alpine binding: x-text="open ? 'icon_a' : 'icon_b'"
    re.compile(r"x-text=\"[^\"]*?'([a-z0-9_]+)'\s*:\s*'([a-z0-9_]+)'\""),
    # Django template attribute: <c-button icon="shield_lock">
    re.compile(r'\bicon="([a-z0-9_]+)"'),
]

# Material-Symbols spans whose icon name lives inside `{% if %}` blocks
# (e.g. `>{% if email_only %}mail{% else %}info{% endif %}<`). The patterns
# above don't catch these because the content right after `>` is `{%` not
# the ligature itself. We scan the full span body and pull every bare
# identifier that isn't a Django template keyword. Yes this is heuristic —
# false positives stay small because the only words inside a span body are
# usually Django tag keywords (matched against `DJANGO_TEMPLATE_KEYWORDS`)
# plus icon names, so the noise floor is low.
SPAN_BODY_RE = re.compile(
    r'class="[^"]*material-symbols-outlined[^"]*"[^>]*>([^<]*)</span>',
    re.DOTALL,
)
IDENT_RE = re.compile(r'\b([a-z][a-z0-9_]+)\b')
DJANGO_TEMPLATE_KEYWORDS = {
    "if", "else", "elif", "endif",
    "with", "endwith",
    "for", "endfor", "empty",
    "comment", "endcomment",
    "trans", "blocktrans", "endblocktrans", "plural",
    "load", "i18n", "static", "url", "include",
    "block", "endblock", "extends",
    "spaceless", "endspaceless", "autoescape", "endautoescape",
    "verbatim", "endverbatim",
    "csrf_token", "now",
    "and", "or", "not", "in", "true", "false", "none",
    # Project-specific context variables that show up as bare tokens inside
    # material-symbols spans (e.g. `{% if email_only_domain %}…{% endif %}`).
    # Anything not in the Material Symbols catalogue is silently dropped by
    # the Google Fonts CSS endpoint, so this is purely about output noise.
    "email_only_domain", "scan", "profile", "form", "request",
    "user", "object", "ctx", "domain",
    # Bare attribute words that historically slipped through.
    "icon",
}
# Python sources (e.g. apps/maketrust/findings.py) expose icon names as values
# in `{"icon": "shield_lock"}` dicts. Pick those up so the scanner sees icons
# referenced from views or context, not only from raw template HTML.
PY_PATTERNS = [
    re.compile(r'["\']icon["\']\s*:\s*["\']([a-z0-9_]+)["\']'),
]
BODY_PATTERN = re.compile(
    r'class="[^"]*material-symbols-outlined[^"]*"[^>]*>([a-z0-9_]+)<'
)

CSS_URL_TEMPLATE = (
    "https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:"
    "opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200&icon_names={names}"
)
WOFF2_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


class Command(BaseCommand):
    help = "Rebuild the Material Symbols woff2 subset from icons used in the site."

    def handle(self, *args, **options):
        from apps.blog.models import Article

        base_dir = Path(settings.BASE_DIR)
        templates_dir = base_dir / "templates"
        out_path = base_dir / "static" / "fonts" / "material-symbols-outlined-subset.woff2"

        icons: set[str] = set()

        for tpl in templates_dir.rglob("*.html"):
            text = tpl.read_text(encoding="utf-8")
            for pat in TEMPLATE_PATTERNS:
                for m in pat.finditer(text):
                    icons.update(g for g in m.groups() if g)
            # Scan inside `<span class="material-symbols-outlined …">…</span>`
            # bodies for icon names hidden in {% if %}{% endif %} branches.
            for span in SPAN_BODY_RE.finditer(text):
                body = span.group(1)
                for tok in IDENT_RE.findall(body):
                    if tok not in DJANGO_TEMPLATE_KEYWORDS:
                        icons.add(tok)

        for py in (base_dir / "apps").rglob("*.py"):
            if "/migrations/" in str(py) or "__pycache__" in str(py):
                continue
            try:
                text = py.read_text(encoding="utf-8")
            except OSError:
                continue
            for pat in PY_PATTERNS:
                for m in pat.finditer(text):
                    icons.update(g for g in m.groups() if g)

        for article in Article.objects.all():
            for body in (article.body_html, getattr(article, "body_html_fr", "") or "",
                         getattr(article, "body_html_en", "") or ""):
                for m in BODY_PATTERN.finditer(body or ""):
                    icons.add(m.group(1))

        if not icons:
            self.stderr.write(self.style.WARNING("No icons detected — aborting."))
            return

        ordered = sorted(icons)
        self.stdout.write(f"Detected {len(ordered)} icons: {', '.join(ordered)}")

        css_url = CSS_URL_TEMPLATE.format(names=",".join(ordered))
        req = urllib.request.Request(css_url, headers={"User-Agent": WOFF2_UA})
        with urllib.request.urlopen(req, timeout=30) as resp:
            css = resp.read().decode("utf-8")

        match = re.search(r"url\((https://[^)]+)\)\s*format\('woff2'\)", css)
        if not match:
            raise RuntimeError(f"Could not find woff2 URL in CSS response:\n{css[:500]}")

        woff2_url = match.group(1)
        self.stdout.write(f"Fetching {woff2_url}")
        req = urllib.request.Request(woff2_url, headers={"User-Agent": WOFF2_UA})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(data)
        self.stdout.write(self.style.SUCCESS(
            f"Wrote {len(data):,} bytes to {out_path}"
        ))
