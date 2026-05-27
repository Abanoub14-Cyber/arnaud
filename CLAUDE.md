# CLAUDE.md — instructions pour assistants codant ce repo

Ce fichier est lu à chaque session. Garde-le court et impératif.

## 🚨 RÈGLE #1 — Commentaires Django (a bité 6 fois)

**`{# … #}` NE SPAN PAS LES LIGNES.** Le parseur Django s'arrête au premier
`#}` de la même ligne. Tout ce qui est sur les lignes suivantes **fuit** dans
le HTML rendu, visible par l'utilisateur. Commits historiques où ça a mordu :
`384fea1`, `87e9b54`, `96ee2b1`, `2eb76fa`, `032feea` — toujours moi.

**RÈGLE DÉFINITIVE — TOUJOURS `{% comment %}{% endcomment %}` pour la
prose, MÊME single-line.** L'autodiscipline "single-line OK" n'a marché
qu'une fois sur sept dans ce repo. À partir de maintenant : `{# #}` est
RÉSERVÉ aux étiquettes mono-mot type `{# header #}`, `{# TODO #}`,
`{# hidden #}`. **Toute phrase avec verbe ou ponctuation → `{% comment %}`.**

Avant de save un template, scan visuellement chaque `{#` :
- Si ça ressemble à une phrase → convertis en `{% comment %}`
- Si c'est juste un mot ou deux → laisse mais vérifie que `#}` est sur la
  même ligne

```django
{# OK : reste sur une seule ligne — pas de fuite possible #}

{% comment %}
OK : multi-ligne, gérée correctement par le parseur Django.
Tout ce qui est entre comment et endcomment est ignoré.
{% endcomment %}

{# DANGER : ça compile mais
   la 2e ligne FUIT dans le HTML #}
```

## 🚨 RÈGLE #2 — Material Symbols cachées dans `{% if %}{% endif %}`

Le subset auto-généré scanne les templates pour les noms d'icônes. Sa
regex historique ne capturait que `>icon_name<` directement après le `>`
ouvrant — donc les icônes hidden dans `{% if x %}icon_a{% else %}icon_b{% endif %}`
**passaient sous le radar** et la ligature manquait dans la woff2, faisant
apparaître le texte brut (`info`, `nfo`, etc.) à l'écran.

Le script `apps/website/management/commands/rebuild_material_symbols.py`
a été corrigé pour scanner le body entier des spans `material-symbols-outlined`
et filtrer les keywords Django (if/else/endif/trans/…). Si tu ajoutes une
nouvelle icône conditionnelle, fais quand même tourner la rebuild pour
vérifier qu'elle est listée :

```bash
docker exec makeset-staging python manage.py rebuild_material_symbols
docker cp makeset-staging:/app/static/fonts/material-symbols-outlined-subset.woff2 \
  app/static/fonts/
```

Quand tu vois "Detected N icons: …" dans le log, **vérifie visuellement** que
la nouvelle icône est dedans. Si pas → la regex échoue → ajoute le nom à
la main dans le template hors `{% if %}` pour la forcer.

## 🚨 RÈGLE #3 — Pas de cadratin (em-dash `—`) en user-facing

Le `—` (em-dash, U+2014) fait "écrit par une IA" instantanément. Arnaud
l'a explicitement banni. Dans toute chaîne traduite, label, placeholder,
finding text, microcopie qui va à l'écran : **utilise une virgule ou un
trait d'union `-`** à la place. C'est OK dans les `{% comment %}` blocks
ou les commentaires Python (`#`) qui ne sortent jamais à l'écran.

Avant de save un fichier que tu as édité, scanne pour `—` (U+2014, pas
`-` U+002D) — si tu en trouves dans une `_("…")`, `{% trans "…" %}`,
`{% blocktrans %}` ou un attribut HTML visible, remplace.

## 🚨 RÈGLE #4 — Site profile types : couvre TOUS les branches

`scan_result.html` rend un bandeau quand `profile.type != "real_site"`.
Les types existants sont : `real_site`, `parked`, `for_sale`,
`registrar_default`, `non_html`, `redirects`, `unreachable`. Si tu ajoutes
un nouveau type dans `scanner/site_profile.py`, **ajoute la branche
correspondante dans le bandeau** (et l'autre conditionnel "Profil — X").
Sinon tu finis en fallback "Injoignable" pour un domaine qui n'est pas
injoignable du tout — bug réel reporté en prod.

## 🚨 RÈGLE #5 — DJANGO_SECRET_KEY doit être identique prod ↔ staging

Prod et staging partagent le volume SQLite, donc la même queue django-q.
django-q 1.x signe chaque tâche avec `settings.SECRET_KEY` en dur (pas
d'override possible via `Q_CLUSTER["secret_key"]` dans cette version).
Si les deux `.env` ont des clés différentes, chaque worker drop avec
`BadSignature` les tâches poussées par l'autre côté, et les `Scan`
restent bloqués en `queued` côté UI ("En file d'attente, position N"
qui ne descend jamais).

Si tu régénères `DJANGO_SECRET_KEY` d'un côté, **synchronise** l'autre,
puis `docker compose up -d --force-recreate` les deux qclusters. Vérif :

```bash
[ "$(grep '^DJANGO_SECRET_KEY=' /var/www/makeset/.env)" = "$(grep '^DJANGO_SECRET_KEY=' /var/www/makeset-staging/.env)" ] && echo OK || echo MISMATCH
```

## Setup rapide

- Repo Django 6 / Tailwind v4 / HTMX / Alpine / django-q2 / SQLite.
- Deux branches déployées : `main` → `makeset.be` (prod), `staging` → `new.makeset.be` (staging, DB partagée avec prod).
- Doc d'archi à jour : `docs/architecture.md` (5-min tour, lis-la après une pause longue).

## Workflow de déploiement (staging)

```bash
# Sur le VPS, /var/www/makeset-staging/
docker compose -f docker-compose.staging.yml build web-staging
docker compose -f docker-compose.staging.yml up -d web-staging qcluster-staging
```

Migrations : staging les joue au boot du container. Le schéma doit rester additif tant que prod n'a pas été redéployée avec le nouveau code (volumes partagés).

## Tests

Pytest n'est pas dans l'image (dev-only) ; pour le faire tourner dans le container staging :

```bash
docker exec makeset-staging pip install --no-deps --quiet pytest pytest-django iniconfig pluggy django-debug-toolbar
docker exec makeset-staging bash -c "cd /app && DJANGO_SETTINGS_MODULE=core.settings.dev python -m pytest apps/maketrust/tests/ -q --no-header"
```

⚠️ `pyproject.toml` épingle `pytest-django==5.0.0` qui **n'existe pas** sur PyPI (max = 4.12.0). Bug latent à fixer un jour.

## i18n / traductions

Source = FR. Après ajout de strings :
1. `docker exec makeset-staging python manage.py makemessages -l en -l fr --no-obsolete --ignore=staticfiles`
2. Copier `.po` host : `docker cp makeset-staging:/app/locale/en/LC_MESSAGES/django.po app/locale/en/LC_MESSAGES/django.po`
3. Éditer les msgstr EN, **retirer les `#, fuzzy` flags** sur les entrées corrigées (gettext ignore les fuzzy à l'exécution !)
4. Compiler : `docker exec makeset-staging python manage.py compilemessages -l en`

## Material Symbols

Subset auto-généré depuis l'usage réel. Si tu ajoutes une nouvelle icône :
```
docker exec makeset-staging python manage.py rebuild_material_symbols
docker cp makeset-staging:/app/static/fonts/material-symbols-outlined-subset.woff2 app/static/fonts/
```

## Permissions

Le dossier `app/apps/maketrust/migrations/` peut être owned par root (héritage Docker). Si écriture refusée :
```bash
sudo chown -R arnaud:arnaud app/apps/maketrust/migrations
```
