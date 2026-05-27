# Makeset.be — Refonte 2026 (Django Stack)

**Date :** 2026-05-01
**Auteur :** Arnaud + Claude (brainstorming)
**Branche :** `redesign/django-2026`

---

## 1. Contexte & Objectifs

### Existant
- Site Makeset.be en **PHP vanilla + Bootstrap 5 + jQuery**, hébergé sur **One.com** (déploiement SFTP via GitHub Actions sur push `main`).
- Pages : `index`, `cybersecurity`, `websolutions`, `ai-automation`, `services`, `blogs`, `articles/`, `contact`, `support`, `legal`, `privacy`, `terms`, `subscribe`.
- Logo : `assets/images/logodegra.png` / `.svg` (à conserver).
- JSON-LD LocalBusiness déjà présent (à reprendre).
- Ahrefs Analytics installé (`data-key="55HGUtDfeHS17Scw3DZauQ"`).
- Contenu solide (NIS2, GDPR, audits, IA, blog) — à garder.

### Problèmes identifiés
- Stack vieillissante, code dupliqué (CSS/JS/PHP), pas de composants réutilisables.
- Le visuel "n'inspire pas confiance" (jugement utilisateur).
- Pas multilingue propre.
- Pas extensible pour intégrer un futur outil dynamique (scan).

### Objectifs de la refonte
1. Stack moderne, composants réutilisables, code maintenable.
2. Site **intuitif** : un visiteur comprend la value prop en **5 secondes** (inspiration Aikido Security).
3. Performance maximum (Lighthouse ≥ 95) + SEO 2026 best-practices (URL localisées, hreflang).
4. Multilingue **FR (défaut) + EN**.
5. Architecture extensible pour la **Phase 2** : ajout d'outil gratuit (scan cybersécurité / conformité) — même codebase.
6. Hébergement sur le **VPS perso** (Docker + traefik déjà en place), abandon One.com.
7. **Aucune régression de contenu** : tout l'existant migre.

### Stratégie de migration
- Branche `redesign/django-2026` → déploiement sur `new.makeset.be` (DNS déjà configuré).
- `main` reste intouché → continue à déployer le PHP existant sur One.com pendant la refonte.
- Quand tout est validé : merge `redesign` → `main`, suppression des fichiers PHP, mise à jour DNS pour pointer `makeset.be` vers le VPS, retrait du workflow SFTP.

---

## 2. Stack technique

### Backend
| Package | Version | Raison |
|---|---|---|
| **Python** | 3.13.13 | Mature, requis ≥3.12 par Django 6 |
| **Django** | 6.0.4 | Latest stable (avril 2026) |
| **django-cotton** | 2.6.2 | Composants HTML réutilisables (Vue-like syntax) |
| **django-distill** | 3.2.7 | Export SSG des pages vitrine en HTML pur |
| **django-modeltranslation** | 0.20.3 | Traduction des modèles (articles blog) |
| **django-meta** | 2.5.1 | Génération auto des meta SEO + OG |
| **django-debug-toolbar** | latest | Dev only |
| **gunicorn** | 23.x | WSGI prod |
| **whitenoise** | 6.x | Sert les statiques |
| **psycopg** | 3.x | Driver Postgres moderne |
| **Pillow** | 11.x | Images |
| **PostgreSQL** | 17 | Instance déjà sur le VPS (réutilisée) |

### Frontend (intégré aux templates)
| Outil | Version | Raison |
|---|---|---|
| **Tailwind CSS** | 4.2.0 | Latest, perfs build améliorées |
| **django-tailwind-cli** | latest | Intégration Django (pas de Node nécessaire en prod) |
| **HTMX** | 2.0.4 | Stable, supporté à perpétuité ; HTMX 4 en beta non utilisé |
| **Alpine.js** | 3.x | Mini-comportements client |
| **Plus Jakarta Sans** | Google Fonts | Typographie du DESIGN.md |
| **Material Symbols** | Google Fonts | Icônes (déjà dans le mockup) |

### Pas de Redis (décision)
- Cache : `LocMemCache` (dev), `FileBasedCache` ou `DatabaseCache` Postgres (prod).
- Tâches async (Phase 2) : `django-q2` ou `huey` avec backend Postgres.

### Infrastructure
- **Docker + docker-compose** (cohérent avec massotherapy)
- **traefik v3.6** (déjà en place sur le VPS) pour HTTPS + routage par domaine
- **PostgreSQL 17** (instance partagée du VPS, schéma dédié)

---

## 3. Architecture globale

```
                    ┌──────────────────────┐
                    │  traefik (HTTPS+DNS) │
                    └─────────┬────────────┘
                              │
                ┌─────────────▼────────────────┐
                │  makeset_web                 │
                │  (Django + gunicorn)         │
                │                              │
                │  apps/                       │
                │   ├─ core/      (home, i18n)│
                │   ├─ services/  (4 pages)   │
                │   ├─ blog/      (articles)  │
                │   ├─ contact/   (form+mail) │
                │   ├─ tools/     (placeholder)│
                │   └─ legal/     (mentions)  │
                │                              │
                │  templates/                  │
                │   ├─ base.html               │
                │   ├─ cotton/  (composants)   │
                │   └─ pages/                  │
                │                              │
                │  static/                     │
                │   ├─ css/  (Tailwind compilé)│
                │   ├─ js/   (HTMX + Alpine)   │
                │   └─ images/                 │
                └─────────┬────────────────────┘
                          │
                ┌─────────▼─────────┐
                │  postgres (existant)
                │  schéma "makeset" │
                └───────────────────┘
```

### Stratégie de rendu

| Type de page | Mode | TTFB cible |
|---|---|---|
| Home + Services + À propos + Légales | **SSG** via `django-distill` (HTML pur servi par traefik) | 5-10 ms |
| Blog (liste + articles) | **SSG** régénéré au déploiement (et au save admin via signal) | 5-10 ms |
| Contact (form GET) | SSG | 5-10 ms |
| Contact (form POST) | Dynamique Django | 50-100 ms |
| Outils / scan (Phase 2) | Dynamique Django + HTMX swaps | 50-200 ms |

---

## 4. Design System

### Source de vérité
`temp/DESIGN.md` ("Radiant Precision / Kinetic Architect") — à reprendre intégralement.

### Tokens Tailwind (`tailwind.config.js`)

**Couleurs** :
- `primary: #0049e6`, `primary-dim: #0040cb`, `primary-container: #829bff`
- `surface: #f8f5ff`, `surface-lowest: #ffffff`, plus 5 niveaux `surface-container-*`
- `on-surface: #2a2b51`, `on-surface-variant: #575881`
- `secondary: #4e4fb6`, `tertiary: #903985`
- `outline: #73739e`, `error: #b41340`

**Typographie** : Plus Jakarta Sans, sizes `display-lg` (3.5rem), `display-md` (2.75rem), `headline-lg` (2rem), `label-sm` (0.6875rem)

**Border radius** : `DEFAULT: 1rem`, `md: 1.5rem`, `lg: 2rem`, `xl: 3rem`, `full: 9999px`

**Utilities custom** : `.glass` (backdrop-blur 20px + bg blanc 70%), `.ambient-shadow` (shadow tinted on-surface), `.radiant-glow` (radial gradient primary)

### Règles
- **Pas de bordures 1px** (background shifts uniquement)
- **Pas de coins carrés** (au moins `md` ou `full`)
- **Pas de noir pur** (utiliser `on-surface`)
- **Spacing généreux** entre sections (≥ 7rem)

### Inventaire composants `cotton` (~26)

**Layout (3)** : `c-glass-nav`, `c-footer`, `c-language-switcher`
**Atomes (7)** : `c-button`, `c-eyebrow`, `c-icon`, `c-tag`, `c-link-arrow`, `c-section`, `c-radiant-bg`
**Cards (4)** : `c-service-card`, `c-feature-item`, `c-blog-card`, `c-testimonial-card`
**Sections (8)** : `c-hero`, `c-services-grid`, `c-why-block`, `c-trust-strip`, `c-faq-accordion`, `c-blog-strip`, `c-cta-banner`, `c-tool-teaser`
**Forms (4)** : `c-input`, `c-textarea`, `c-form-field`, `c-select`

Tous dans `templates/cotton/`.

---

## 5. Modèles de données & Apps Django

### App `core`
- Vue `home` (SSG)
- Vue `about` (SSG)
- Sitemaps automatiques (`django.contrib.sitemaps`)
- Settings i18n + URL `i18n_patterns`

### App `services`
Pages statiques majoritairement, avec URLs localisées :
- `/services/` (overview) ↔ `/en/services/`
- `/services/cybersecurite/` ↔ `/en/services/cybersecurity/`
- `/services/web/` ↔ `/en/services/web/`
- `/services/ia-automation/` ↔ `/en/services/ai-automation/`
- `/services/support/` ↔ `/en/services/support/`

Pas de modèle DB — contenu directement en templates (services peu changeants).

### App `blog`

```python
class Article(models.Model):
    slug = models.SlugField(unique=True)
    title = models.CharField(max_length=200)        # translated via modeltranslation
    excerpt = models.TextField()                    # translated
    body = models.TextField()                       # translated (Markdown)
    cover = models.ImageField(upload_to='blog/')
    cover_alt = models.CharField(max_length=200)    # translated
    published_at = models.DateTimeField()
    is_published = models.BooleanField(default=False)
    meta_description = models.CharField(max_length=180, blank=True)  # translated
    tags = models.ManyToManyField('Tag', blank=True)

    class Meta:
        ordering = ['-published_at']

class Tag(models.Model):
    slug = models.SlugField(unique=True)
    name = models.CharField(max_length=50)          # translated
```

**Admin Django** = CMS. Markdown rendu côté serveur via `markdown` lib. Reprise des 3 articles existants (`articles/nis2-compliance-belgium-2026/`, etc.) en migration de données.

### App `contact`

```python
class ContactMessage(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    phone = models.CharField(max_length=30, blank=True)
    company = models.CharField(max_length=100, blank=True)
    subject = models.CharField(max_length=200)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    handled = models.BooleanField(default=False)
```

- Formulaire HTMX (submit sans rechargement)
- Envoi mail SMTP vers `contact@makeset.be`
- Honeypot anti-bot + rate limiting (`django-ratelimit`)
- Captcha invisible (Cloudflare Turnstile, gratuit)

### App `tools` (Phase 2 — placeholder pour l'instant)

Structure préparée pour un futur scan cybersécurité/conformité :

```python
class Scan(models.Model):
    KIND_CHOICES = [('security', 'Security'), ('compliance', 'Compliance')]
    kind = models.CharField(max_length=20, choices=KIND_CHOICES)
    target_url = models.URLField()
    requested_email = models.EmailField()
    status = models.CharField(max_length=20)  # pending, running, done, failed
    results = models.JSONField(default=dict)
    started_at = models.DateTimeField(null=True)
    completed_at = models.DateTimeField(null=True)
    ip = models.GenericIPAddressField()
```

En Phase 1 : juste `/outils/` qui affiche "Bientôt disponible" + capture email pour notification.

### App `legal`
Pages statiques : `/mentions-legales/`, `/confidentialite/`, `/cgv/`. Pas de modèle.

---

## 6. SEO & i18n

### URL localisées
Avec `django.utils.translation.gettext_lazy` dans `urls.py` + `i18n_patterns`.

```python
# apps/services/urls.py
from django.urls import path
from django.utils.translation import gettext_lazy as _
from . import views

urlpatterns = [
    path(_('cybersecurite/'), views.cyber, name='service_cyber'),
    path(_('web/'), views.web, name='service_web'),
    path(_('ia-automation/'), views.ia, name='service_ia'),
    path(_('support/'), views.support, name='service_support'),
]
```

Avec les fichiers `.po` :
- FR : `cybersecurite/`
- EN : `cybersecurity/`

### Hreflang
Generation automatique dans `base.html` :

```html
{% for lang_code, lang_name in LANGUAGES %}
  <link rel="alternate" hreflang="{{ lang_code }}" href="{% absolute_url request lang_code %}" />
{% endfor %}
<link rel="alternate" hreflang="x-default" href="{% absolute_url request 'fr' %}" />
```

Helper `absolute_url` (template tag custom) — résout l'URL équivalente dans une autre langue via `translate_url()`.

### Canonical
Self-referencing automatique, géré par `django-meta`.

### Sitemap.xml
- `sitemap_index.xml` à la racine
- Un sitemap par section (pages, services, blog) × 2 langues = 6 sitemaps
- Référencé dans `robots.txt`

### JSON-LD
Reprise du LocalBusiness existant + ajout par page :
- Pages services : `Service`
- Articles blog : `Article`
- FAQ : `FAQPage`
- Breadcrumbs : `BreadcrumbList`

### `robots.txt`
```
User-agent: *
Allow: /
Disallow: /admin/
Disallow: /static/admin/
Sitemap: https://makeset.be/sitemap.xml
```

### Analytics
- Conserver Ahrefs Analytics (`data-key="55HGUtDfeHS17Scw3DZauQ"`)
- Ajout possible Plausible (self-hosté, RGPD-friendly) — à décider plus tard

---

## 7. Performance

### Cibles
| Métrique | Cible |
|---|---|
| Lighthouse Performance | ≥ 95 |
| Lighthouse SEO | 100 |
| Lighthouse Accessibility | ≥ 95 |
| Lighthouse Best Practices | ≥ 95 |
| TTFB (cache chaud) | < 50 ms |
| First Contentful Paint | < 0.5 s |
| JS expédié | < 30 KB total |
| CSS expédié | < 20 KB total (Tailwind purgé) |

### Leviers
1. **SSG via django-distill** sur toutes les pages possibles
2. **Tailwind purgé** (CSS minifié, ~10-15 KB)
3. **HTMX 2.0 + Alpine 3** (~15 KB total)
4. **Pas de framework JS** (pas de React, pas de hydration)
5. **Images** : WebP/AVIF + `loading="lazy"` + `<picture>` avec `srcset` responsive
6. **Fonts** : préchargées + `font-display: swap`
7. **Whitenoise** : compression gzip/brotli + cache long terme avec hash dans le nom de fichier
8. **Cache pages dynamiques** : `@cache_page(60*15)` pour vues non-personnalisées

### Build
```bash
python manage.py collectstatic
python manage.py compilemessages    # i18n
python manage.py distill-local --collectstatic dist/  # SSG
```

`dist/` → servi en statique par traefik (volume monté).

---

## 8. Sécurité

### Headers (via middleware)
- `Content-Security-Policy` (script-src self + ahrefs analytics)
- `Strict-Transport-Security` : `max-age=63072000; includeSubDomains; preload`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

### Django settings prod
- `DEBUG = False`
- `ALLOWED_HOSTS = ['makeset.be', 'www.makeset.be', 'new.makeset.be']`
- `SECURE_SSL_REDIRECT = True`
- `SESSION_COOKIE_SECURE = True`
- `CSRF_COOKIE_SECURE = True`
- `SECURE_HSTS_SECONDS = 63072000`

### Secrets
- Variables d'env via `.env` (jamais commit, dans `.gitignore`)
- Secrets GitHub Actions : `VPS_SSH_KEY`, `VPS_HOST`, `DATABASE_URL`, `DJANGO_SECRET_KEY`, `EMAIL_HOST_PASSWORD`
- `SECRET_KEY` : générée et stockée dans variable d'env

### Anti-abuse
- **CSRF** : actif partout
- **Rate limiting** : `django-ratelimit` sur formulaire contact (5/h par IP)
- **Honeypot** : champ caché dans le formulaire
- **Cloudflare Turnstile** : captcha invisible (gratuit)

### Crowdsec (déjà sur le VPS)
- Bouncer traefik existant → protection contre attaques connues automatique

---

## 9. Déploiement

### Architecture Docker

`Dockerfile` multi-stage :
```dockerfile
# Stage 1: build (Tailwind + collectstatic + distill)
FROM python:3.13-slim AS builder
WORKDIR /app
RUN pip install uv
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY . .
RUN uv run python manage.py tailwind build && \
    uv run python manage.py collectstatic --noinput && \
    uv run python manage.py compilemessages && \
    uv run python manage.py distill-local --collectstatic /app/dist

# Stage 2: runtime
FROM python:3.13-slim
WORKDIR /app
RUN pip install uv
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY --from=builder /app /app
USER nobody
EXPOSE 8000
CMD ["uv", "run", "gunicorn", "makeset.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]
```

### `docker-compose.yml`
```yaml
services:
  makeset_web:
    image: ghcr.io/<user>/makeset:latest
    container_name: makeset_web
    restart: unless-stopped
    env_file: .env
    networks:
      - traefik
      - postgres
    volumes:
      - makeset_media:/app/media
    labels:
      - traefik.enable=true
      - traefik.http.routers.makeset.rule=Host(`new.makeset.be`)
      - traefik.http.routers.makeset.entrypoints=websecure
      - traefik.http.routers.makeset.tls.certresolver=letsencrypt
      - traefik.http.services.makeset.loadbalancer.server.port=8000
    depends_on:
      - postgres

networks:
  traefik:
    external: true
  postgres:
    external: true

volumes:
  makeset_media:
```

(Pas de service `postgres` ici — utilise l'instance partagée existante via le réseau Docker `postgres`.)

### CI/CD GitHub Actions

`.github/workflows/deploy-vps.yml` (nouveau, branche `redesign/django-2026` puis `main` après merge) :

```yaml
name: Deploy to VPS

on:
  push:
    branches: [redesign/django-2026, main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: astral-sh/setup-uv@v3
      - run: uv sync
      - run: uv run ruff check
      - run: uv run pytest

  build-and-push:
    needs: test
    runs-on: ubuntu-latest
    permissions: { contents: read, packages: write }
    steps:
      - uses: actions/checkout@v5
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          push: true
          tags: |
            ghcr.io/${{ github.repository_owner }}/makeset:${{ github.sha }}
            ghcr.io/${{ github.repository_owner }}/makeset:latest

  deploy:
    needs: build-and-push
    runs-on: ubuntu-latest
    steps:
      - uses: appleboy/ssh-action@v1
        with:
          host: ${{ secrets.VPS_HOST }}
          username: ${{ secrets.VPS_USER }}
          key: ${{ secrets.VPS_SSH_KEY }}
          script: |
            cd /var/www/makeset/deploy
            docker compose pull
            docker compose up -d
            docker compose exec -T makeset_web python manage.py migrate --noinput
            docker compose exec -T makeset_web python manage.py collectstatic --noinput
```

**L'ancien `deploy.yml` (One.com SFTP) reste actif sur `main` jusqu'au cutover final.** Lors du cutover : on supprime cet ancien workflow.

### Migration finale (cutover)

**Ordre critique** : suppression PHP + suppression workflow One.com **doivent être dans le même commit que le merge** (sinon le workflow `deploy.yml` se déclenche sur `main` et déploie du code Django sur One.com → casse).

1. Validation complète sur `new.makeset.be` (Lighthouse, hreflang, contenu)
2. Sur la branche `redesign/django-2026` : supprimer fichiers PHP (`*.php`, `articles/`, `assets/` ancien, `vendor/`, `.htaccess`) + supprimer `.github/workflows/deploy.yml`
3. Squash-merge `redesign/django-2026` → `main` (ou fast-forward), un seul commit "feat: refonte Django 2026"
4. Sur le VPS : `git pull` + `docker compose pull` + `docker compose up -d`
5. Mise à jour `traefik` labels : `Host(\`makeset.be\`, \`www.makeset.be\`, \`new.makeset.be\`)`
6. Mise à jour DNS : `makeset.be` + `www.makeset.be` → IP VPS (TTL court préalable)
7. Redirection 301 `www` → apex (gérée par traefik ou middleware Django)
8. Redirections 301 des anciennes URLs PHP → nouvelles (table dans `urls.py` ou middleware dédié)
9. Vérif Search Console + soumission nouveaux sitemaps

### Redirections SEO (à gérer en Django middleware)
| Ancien | Nouveau |
|---|---|
| `/cybersecurity` | `/en/services/cybersecurity/` ou `/services/cybersecurite/` selon Accept-Language |
| `/websolutions` | `/services/web/` |
| `/ai-automation` | `/services/ia-automation/` |
| `/support` | `/services/support/` |
| `/services` | `/services/` |
| `/blogs` | `/blog/` |
| `/articles/<slug>` | `/blog/<slug>/` |
| `/contact` | `/contact/` |
| `/legal`, `/privacy`, `/terms` | `/mentions-legales/`, `/confidentialite/`, `/cgv/` |

---

## 10. Plan d'implémentation phasé

### Phase 1.0 — Fondation (priorité immédiate)
1. ✅ Branche `redesign/django-2026` créée
2. Spec écrit + commit
3. `pyproject.toml` avec uv (Python 3.13, deps figées)
4. Structure du projet Django (`makeset/`, `apps/core/`, `manage.py`)
5. Settings split (`base.py`, `dev.py`, `prod.py`)
6. `Dockerfile` + `docker-compose.yml` + `.dockerignore`
7. Tailwind config + base CSS
8. HTMX + Alpine bundles
9. `base.html` minimal qui charge tout

### Phase 1.1 — Design system
10. Composants cotton atomes (`c-button`, `c-icon`, `c-eyebrow`, `c-section`)
11. Layout components (`c-glass-nav`, `c-footer`, `c-language-switcher`)
12. Cards (`c-service-card`, `c-feature-item`, `c-blog-card`)
13. Sections (`c-hero`, `c-services-grid`, `c-why-block`, `c-cta-banner`, `c-faq-accordion`)
14. Forms (`c-input`, `c-form-field`)

### Phase 1.2 — Pages vitrine
15. `/` Home (FR + EN, traductions)
16. `/services/` overview
17. `/services/cybersecurite/`
18. `/services/web/`
19. `/services/ia-automation/`
20. `/services/support/`
21. `/a-propos/`
22. `/contact/` + formulaire HTMX + envoi mail
23. `/mentions-legales/`, `/confidentialite/`, `/cgv/`
24. `/outils/` (placeholder Phase 2)

### Phase 1.3 — Blog
25. Modèles `Article`, `Tag` + admin
26. Liste `/blog/` + pagination
27. Détail `/blog/<slug>/`
28. Migration des 3 articles existants depuis `articles/`
29. Markdown rendering + syntax highlighting

### Phase 1.4 — SEO / i18n / Perf
30. URL localisées (`.po`/`.mo` files)
31. Hreflang + canonical + sitemap.xml
32. JSON-LD par page
33. Meta tags via django-meta
34. `django-distill` config + génération
35. Redirections 301 anciennes URL

### Phase 1.5 — Déploiement
36. Workflow `deploy-vps.yml`
37. Configuration traefik labels
38. Tests E2E sur `new.makeset.be`
39. Lighthouse CI (≥ 95 partout)

### Phase 1.6 — Cutover (validation finale)
40. Snapshot dernier état One.com
41. Merge → `main`
42. DNS swap
43. Suppression PHP + ancien workflow
44. Vérif redirections + Search Console

### Phase 2 — Outil gratuit (futur)
45. Définir le scan (sécurité ou conformité ou les deux)
46. Implémenter (Python : `requests`, `dnspython`, `python-whois`, `playwright`...)
47. UI HTMX live progress
48. Capture email + notification

---

## 11. Critères de succès

- Lighthouse 4 catégories ≥ 95 sur 5 pages échantillons
- Site complet en FR + EN avec hreflang valide (vérifié via Search Console)
- Aucune régression de contenu (toutes les pages PHP existantes ont leur équivalent)
- Toutes les anciennes URL redirigent en 301
- Visiteur comprend la value prop **en 5 secondes** sur la home (test utilisateur informel)
- Footprint VPS : ≤ 200 MB RAM, ≤ 400 MB disque pour le container Makeset
- Build CI/CD < 5 min
- Deploy à zéro downtime (healthcheck Docker + traefik)

---

## 12. Risques & mitigations

| Risque | Mitigation |
|---|---|
| Push accidentel sur `main` → déploie code Django sur One.com (incompatible) | Travailler exclusivement sur `redesign/django-2026`. Le workflow One.com `deploy.yml` ne se déclenche que sur `main`. |
| Perte de SEO lors de la migration | Redirections 301 systématiques + Search Console suivi 4 semaines |
| Erreurs hreflang | Validation avec Screaming Frog + Search Console "International Targeting" report |
| Container trop lourd sur VPS | Image Docker multi-stage + base `python:3.13-slim` (cible : ≤ 250 MB) |
| Régression visuelle vs mockup | Audit composant par composant avec le PNG de référence |
| Outil de scan Phase 2 trop ambitieux | Phase 1 ne livre QU'UN placeholder. Pas de scan en Phase 1. |

---

**Fin du spec.**
