# Architecture (5-min tour)

> Reprends ce doc avant de toucher au code après une longue pause. Si quelque chose t'étonne ici, c'est probablement intentionnel.

## TL;DR

Site marketing Django pour Makeset (agence digitale belge). 6 apps, ~13 composants cotton, FR (source) + EN, hébergé sur le VPS derrière Traefik à `https://makeset.be/`. Une staging tourne en parallèle sur `https://new.makeset.be/` (même DB que la prod).

## Stack en une ligne

Django 6 (Python 3.13) · django-cotton (composants) · Tailwind v4 · HTMX · SQLite · Gunicorn + Whitenoise · Docker · Traefik (TLS Let's Encrypt + middlewares CrowdSec/security-headers/rate-limit).

---

## URL routing + i18n

`prefix_default_language=False` → **FR à la racine**, **EN sous `/en/`**.

```
GET /                     → home FR
GET /en/                  → home EN
GET /services/cybersecurite/  → service cyber FR
GET /en/services/cybersecurity/ → service cyber EN
```

Les slugs sont traduits via `gettext_lazy` dans chaque `urls.py` d'app. Voir `apps/services/urls.py` pour l'exemple type.

**Hors `i18n_patterns`** (servis tel quel à la racine) :
- `/admin/` (Django admin)
- `/robots.txt`
- `/sitemap.xml` (généré par `apps/website/sitemaps.py`)

**Redirections legacy** : tous les anciens chemins PHP (`/cybersecurity`, `/blogs`, `/articles/<slug>/`, etc.) sont redirigés en 301 par `apps/website/middleware.py:LegacyPhpRedirectMiddleware`. Cible déterminée par `request.LANGUAGE_CODE`.

## Apps Django

| App | Rôle | Modèles | Templates | URLs |
|---|---|---|---|---|
| `website` | home, about, sitemap, redirect middleware | — | `pages/home.html`, `pages/about.html` | `/`, `/a-propos/` |
| `services` | 4 pages services + index | — (statique) | `pages/services/*.html` | `/services/`, `/services/cybersecurite/`, `/services/web/`, `/services/ia-automation/`, `/services/support/` |
| `blog` | Articles + Tags, list + detail | `Article`, `Tag` | `pages/blog/list.html`, `pages/blog/detail.html` | `/blog/`, `/blog/<slug>/` |
| `contact` | Formulaire + envoi mail + storage | `ContactMessage` | `pages/contact.html`, `partials/contact_form.html`, `partials/contact_success.html` | `/contact/` |
| `legal` | Mentions, privacy, CGV, cookies | — | `pages/legal/*.html` | `/mentions-legales/`, `/confidentialite/`, `/cgv/`, `/cookies/` |
| `tools` | Placeholder Phase 2 (audit gratuit) | — | `pages/tools/index.html` | `/outils/` |

## Templates

```
app/templates/
├── base.html                # layout root : <head>, hreflang, JSON-LD, nav, footer
├── cotton/                  # ~13 composants réutilisables
│   ├── eyebrow.html         # <c-eyebrow>label</c-eyebrow>
│   ├── button.html          # <c-button variant="primary" size="lg">…</c-button>
│   ├── service_card.html    # <c-service-card icon="lock" title="…" href="…">…</c-service-card>
│   ├── feature_item.html, faq_item.html, stat_card.html, cta_banner.html, etc.
│   └── language_switcher.html
├── pages/                   # une par route
│   ├── home.html, about.html, contact.html
│   ├── services/, blog/, legal/, tools/
└── partials/                # bouts réutilisés non-cotton
    ├── nav.html, footer.html, hreflang.html
    ├── contact_form.html, contact_success.html, cookie_consent.html
└── emails/contact_notification.txt
```

## Design system

Tokens dans `app/tailwind_src/source.css` (`@theme`). À retenir :

- **Couleurs** : `primary` `#006ced` → gradient cyan `#03e0ff`. Les utilities clé : `bg-primary-gradient`, `text-primary-gradient`, `ring-primary-gradient`, `glass`, `ambient-shadow`, `radiant-glow`.
- **Surfaces** : `surface-lowest` (cards blanches), `surface-container-low` (sections gris très clair), `surface` (body).
- **Texte** : `on-surface` (titre principal), `on-surface-variant` (corps de texte gris).
- **Type** : `font-sans` = Plus Jakarta Sans. Tailles custom : `text-display-lg`, `text-headline-lg`.
- **Radius** : `rounded-md` (1.5rem), `rounded-xl` (3rem). Coins très arrondis = signature.
- **Italique gradient** : sur tout span `text-primary-gradient italic`, ajouter `pe-2 [-webkit-box-decoration-break:clone] [box-decoration-break:clone]` sinon le dernier caractère se fait clipper en mobile.

## Admin Django (`/admin/`)

Login : superuser créé via `python manage.py createsuperuser` (la première fois). URL : `https://makeset.be/admin/`.

| Section | Quoi | Comment |
|---|---|---|
| **Articles** (Blog) | Liste, ajout, édition d'articles. Champs traduits (FR/EN) via `modeltranslation`. | "Add article" → remplir titre FR + EN, slug auto-prepop, body HTML, image cover, tags, cocher "Publié" |
| **Tags** (Blog) | Catégories d'articles | "Add tag" |
| **Contact messages** (Contact) | Tous les soumissions du formulaire. Cocher "handled" quand traité. Metadata IP/UA/referer en read-only (collapsed) | À surveiller régulièrement |
| **Users / Groups** | Standard Django auth | |

Pour ajouter un champ traduit sur Article/Tag, modifier `apps/blog/translation.py` puis `makemigrations`.

## i18n workflow

Source = FR. Toute string user-visible va dans `{% trans "..." %}` ou `gettext_lazy(...)`.

**Extraire les nouvelles strings** (en local ou docker exec) :
```bash
python manage.py makemessages -l en -l fr --no-obsolete --ignore=staticfiles
```

→ remplit `app/locale/{en,fr}/LC_MESSAGES/django.po`. Editer les `msgstr` dans `en/django.po`. Le `compilemessages` tourne automatiquement au build du conteneur.

## Trois environnements

| Env | URL | Code | Container | DB |
|---|---|---|---|---|
| **Local dev** | `http://localhost:8000` | bind-mount `./app` | runserver via `docker-compose.override.yml` | SQLite locale |
| **Staging** | `https://new.makeset.be` | branche `staging`, dans `/var/www/makeset-staging/` | `makeset-staging` | **partagée avec prod** |
| **Prod** | `https://makeset.be` | branche `main`, dans `/var/www/makeset/` | `makeset` | `makeset_data` volume |

Staging tourne avec `SKIP_MIGRATIONS=1` → ne touche jamais le schéma. Toute migration : merger sur main, puis `migrate` depuis le container prod.

## Cookbook (tâches fréquentes)

### Ajouter une page statique
1. Créer `app/templates/pages/ma-page.html` (extends `base.html`)
2. Ajouter `MaPageView(TemplateView)` dans `apps/website/views.py`
3. Router dans `apps/website/urls.py` : `path(_("ma-page/"), views.MaPageView.as_view(), name="ma_page")`
4. Si i18n : ajouter le slug EN dans `locale/en/django.po` (`msgid "ma-page/"` → `msgstr "my-page/"`)
5. Ajouter au sitemap : entry dans `apps/website/sitemaps.py:StaticViewSitemap.items()`
6. Lancer `makemessages` pour les nouvelles strings, traduire, `compilemessages` (rebuild)

### Ajouter un article de blog
Tout via l'admin Django à `/admin/blog/article/add/`. Pas de code à toucher.

### Ajouter une langue (ex: NL)
1. `LANGUAGES += [("nl", _("Nederlands"))]` dans `core/settings/base.py`
2. `python manage.py makemessages -l nl --ignore=staticfiles`
3. Traduire `locale/nl/LC_MESSAGES/django.po`
4. Rebuild

### Changer une icône de service
Dans le template, l'attribut `icon="..."` du composant `<c-service-card>` ou `<c-feature-item>` prend un nom Material Symbols. Browse : https://fonts.google.com/icons.

### Ajouter une nouvelle redirection legacy
Append au dict `LEGACY_REDIRECTS` dans `apps/website/middleware.py`. Format : `"/old-path": "view_name"`.

## Gotchas (pièges connus)

- **`SKIP_MIGRATIONS=1`** sur staging : ne pas l'enlever sans réfléchir, sinon staging applique des migrations sur la DB prod partagée.
- **Sitemap** : le `META_SITE_DOMAIN` du `.env` détermine les URLs absolues. Doit être `makeset.be` en prod, `new.makeset.be` en staging.
- **CSRF** : si tu ajoutes un domaine, mettre dans `DJANGO_ALLOWED_HOSTS` ET `DJANGO_CSRF_TRUSTED_ORIGINS` (`.env`).
- **Tailwind v4** : pas de `tailwind.config.js`, tout est dans `tailwind_src/source.css` via `@theme`. Utility scan auto sur les templates au build.
- **Cotton** : composants en `kebab-case` dans le template (`<c-service-card>`), fichier en `snake_case` (`service_card.html`). Variables déclarées via `<c-vars name=default>`.
- **Italic + gradient** : voir Design system ci-dessus, fix obligatoire avec `box-decoration-break:clone`.
- **Cloudflare proxy ON** : SSL/TLS mode doit être "Full (strict)" dans Cloudflare. Cert origine = Let's Encrypt via Traefik.
- **MakeTrust : IP du VPS exposée aux cibles scannées**. Le scanner fait ses requêtes HTTPS sortantes directement depuis le VPS (Cloudflare n'agit qu'en entrée). Un attaquant qui scanne son propre domaine voit l'IP du VPS dans ses logs, plus le UA `MakeTrustBot/1.0 (+https://makeset.be/tools/maketrust/)`. C'est aussi l'IP origine derrière Cloudflare, donc DDoS/probe direct possible en bypass. Acceptable au lancement (volume bas, UA déjà self-identifying à la SSL Labs/Hardenize), à mitiger quand le trafic monte. Options dans l'ordre : publier un PTR `scanner.makeset.be` (zéro coût, transforme la "fuite" en identité documentée) → petit VPS proxy à part (Hetzner CX11, ~4 €/mois, ASN différent) → Cloudflare Workers comme proxy de fetch → séparer le `qcluster` sur son propre VPS.

## Pour aller plus loin

- Spec design détaillée (633 lignes) : [`docs/superpowers/specs/2026-05-01-makeset-redesign-design.md`](superpowers/specs/2026-05-01-makeset-redesign-design.md).
- Settings : `app/core/settings/base.py` (commun), `dev.py` (DEBUG=True, debug_toolbar), `prod.py` (DEBUG=False, secure cookies).
