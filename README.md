# makeset.be

Site web de Makeset — Agence digitale à Bruxelles (Cybersécurité, App, IA).

> 🗺️ **Tour de 5 min** : [`docs/architecture.md`](docs/architecture.md) — la doc de reprise (URL routing, apps, design system, admin, cookbook, gotchas).

## Stack

- **Django 6** (Python 3.13) — backend, templates, i18n FR/EN
- **django-cotton** — composants HTML réutilisables
- **Tailwind CSS v4** (via `django-tailwind-cli`)
- **HTMX** — interactivité légère (formulaire contact, etc.)
- **Postgres** (sur le VPS) ou SQLite (par défaut)
- **Gunicorn + Whitenoise** — serveur app + statiques
- **Traefik** (sur le VPS) — TLS Let's Encrypt + middlewares (CrowdSec, security headers, rate limit)

## Structure

```
├── app/
│   ├── core/                    # Project Django (settings, urls, wsgi)
│   ├── apps/
│   │   ├── website/             # home, about, sitemap, redirect middleware
│   │   ├── services/            # 4 service pages
│   │   ├── blog/                # Article model + views
│   │   ├── contact/             # form + email send
│   │   ├── tools/               # placeholder (Phase 2)
│   │   └── legal/               # mentions, privacy, terms, cookies
│   ├── templates/
│   │   ├── cotton/              # ~13 reusable components
│   │   ├── pages/               # one per route
│   │   └── partials/            # form, success message, footer, nav
│   ├── locale/                  # FR (source) + EN translations
│   ├── static/                  # css, images, js
│   └── tailwind_src/source.css  # Tailwind v4 entry
├── docker/                      # Dockerfile + entrypoint
├── docker-compose.yml           # prod: gunicorn + traefik labels
├── docker-compose.override.yml  # dev: bind-mount + runserver
└── docs/                        # spec & internal docs
```

## Développement local

```bash
# 1. Crée le .env (copie .env.example, remplis les valeurs)
cp .env.example .env

# 2. Lance le stack en dev (l'override active le bind-mount + runserver)
docker compose up -d

# 3. (premier run) migrations + admin
docker compose exec web python manage.py migrate
docker compose exec web python manage.py createsuperuser
```

Le dev override monte `./app` dans le conteneur, donc les changements de code/templates sont live sans rebuild.

## Déploiement (production)

Le site tourne dans Docker derrière Traefik sur le VPS, en routage par labels (voir `docker-compose.yml`). Pour déployer :

```bash
# sur le VPS
git pull
docker compose -f docker-compose.yml build web
docker compose -f docker-compose.yml up -d web
```

Le build re-compile Tailwind, lance `collectstatic` et `compilemessages`. L'`entrypoint.sh` applique les migrations au démarrage.

## Staging (`new.makeset.be`)

Container parallèle qui partage la **même DB et le même `media/`** que la prod, sur la branche `staging`. Sert à valider une feature sur l'URL publique avant de la merger en prod.

### Setup initial (une fois)

```bash
# sur le VPS
cd /var/www
git clone git@github.com:aquerinj/makeset.git makeset-staging
cd makeset-staging
git checkout staging
cp /var/www/makeset/.env .env   # même config DB pour partager les données
# édite .env : DJANGO_ALLOWED_HOSTS=new.makeset.be ; META_SITE_DOMAIN=new.makeset.be
docker compose -f docker-compose.staging.yml build web-staging
docker compose -f docker-compose.staging.yml up -d web-staging
```

### Workflow quotidien

```bash
# en local : tu travailles sur la branche staging
git checkout staging
# ... tes modifs ...
git push

# sur le VPS
cd /var/www/makeset-staging
git pull
docker compose -f docker-compose.staging.yml up -d --build web-staging
# vérifier sur https://new.makeset.be/

# quand validé : merge staging → main sur GitHub (PR), puis :
cd /var/www/makeset
git pull
docker compose -f docker-compose.yml up -d --build web
# live sur https://makeset.be/
```

`SKIP_MIGRATIONS=1` est forcé sur le container staging pour éviter qu'il touche au schéma DB partagé. Si une feature de la branche staging ajoute une migration, **lance-la depuis le container prod** une fois mergée :

```bash
docker compose -f docker-compose.yml exec web python manage.py migrate
```

## i18n

- FR = langue source. `prefix_default_language=False` : FR à la racine, EN sous `/en/`.
- Strings extraites via `python manage.py makemessages -l en -l fr --no-obsolete`.
- Compilées au build du conteneur (`compilemessages`).

## Variables d'environnement

Voir `.env.example`. Les indispensables en prod :

| Variable | Note |
|---|---|
| `DJANGO_SECRET_KEY` | clé aléatoire 50+ chars |
| `DJANGO_ALLOWED_HOSTS` | domaines servis par le container |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | origines autorisées pour POST CSRF |
| `DATABASE_URL` | `sqlite:///...` ou `postgres://...` |
| `META_SITE_DOMAIN` | domaine canonique pour og:url, sitemap |
