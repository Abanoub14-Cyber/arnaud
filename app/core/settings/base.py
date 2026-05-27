"""Base settings shared between dev and prod."""
from pathlib import Path

import environ

BASE_DIR = Path(__file__).resolve().parent.parent.parent

env = environ.Env(
    DJANGO_DEBUG=(bool, False),
    DJANGO_ALLOWED_HOSTS=(list, []),
    DJANGO_CSRF_TRUSTED_ORIGINS=(list, []),
)
environ.Env.read_env(BASE_DIR.parent / ".env")

SECRET_KEY = env("DJANGO_SECRET_KEY", default="dev-insecure-change-me-in-prod")
DEBUG = env("DJANGO_DEBUG")
ALLOWED_HOSTS = env("DJANGO_ALLOWED_HOSTS")
CSRF_TRUSTED_ORIGINS = env("DJANGO_CSRF_TRUSTED_ORIGINS")

INSTALLED_APPS = [
    # modeltranslation MUST come before django.contrib.admin so that its
    # translator autodiscover picks up <app>/translation.py before admin
    # registers TranslationAdmin instances.
    "modeltranslation",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sitemaps",
    "django_cotton",
    "django_tailwind_cli",
    "django_distill",
    "django_q",
    "meta",
    "apps.website",
    "apps.services",
    "apps.blog",
    "apps.contact",
    "apps.tools",
    "apps.maketrust",
    "apps.legal",
]

MIDDLEWARE = [
    # Must be first: every later middleware (rate-limit, logging, etc.) reads
    # request.real_ip and would see a Cloudflare edge IP without it.
    "apps.website.middleware.RealIPMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "apps.website.middleware.LegacyPhpRedirectMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # After AuthenticationMiddleware so it can let an already-logged-in
    # staff session through (e.g. operator traveling abroad).
    "apps.website.middleware.AdminGeoRestrictMiddleware",
]

# Countries (ISO 3166-1 alpha-2, upper-case) allowed to reach /admin/.
# Empty/None = disabled. Set in prod.py for production, kept open in dev.
ADMIN_ALLOWED_COUNTRIES: set[str] = set()

ROOT_URLCONF = "core.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "django.template.context_processors.i18n",
            ],
            "builtins": ["django_cotton.templatetags.cotton"],
        },
    },
]

WSGI_APPLICATION = "core.wsgi.application"

DATABASES = {
    "default": env.db_url(
        "DATABASE_URL",
        default="sqlite:///" + str(BASE_DIR / "data" / "db.sqlite3"),
    ),
}

# WAL keeps reads non-blocking while a writer (q_cluster scan worker, contact
# form save) holds a transaction. NORMAL synchronous trades a tiny durability
# window for ~10x write throughput — fine because we're not a bank.
if DATABASES["default"]["ENGINE"] == "django.db.backends.sqlite3":
    DATABASES["default"].setdefault("OPTIONS", {})
    DATABASES["default"]["OPTIONS"].setdefault(
        "init_command",
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;",
    )

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# i18n - FR default + EN
from django.utils.translation import gettext_lazy as _  # noqa: E402

LANGUAGE_CODE = "fr"
LANGUAGES = [
    ("fr", _("Français")),
    ("en", _("English")),
]
LOCALE_PATHS = [BASE_DIR / "locale"]
USE_I18N = True
USE_L10N = True
USE_TZ = True
TIME_ZONE = "Europe/Brussels"

# modeltranslation: EN content shows in EN locale, falls back to FR if missing,
# and vice versa. This way an article only filled in one language stays
# readable in the other instead of going blank.
MODELTRANSLATION_FALLBACK_LANGUAGES = ("fr", "en")
MODELTRANSLATION_DEFAULT_LANGUAGE = "fr"

# Static & media
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Email
EMAIL_BACKEND = env("EMAIL_BACKEND", default="django.core.mail.backends.console.EmailBackend")
EMAIL_HOST = env("EMAIL_HOST", default="")
EMAIL_PORT = env.int("EMAIL_PORT", default=587)
EMAIL_HOST_USER = env("EMAIL_HOST_USER", default="")
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD", default="")
EMAIL_USE_TLS = env.bool("EMAIL_USE_TLS", default=True)
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", default="contact@makeset.be")
CONTACT_EMAIL = env("CONTACT_EMAIL", default="contact@makeset.be")

# Tailwind CLI
TAILWIND_CLI_VERSION = "4.2.0"
TAILWIND_CLI_SRC_CSS = "tailwind_src/source.css"
TAILWIND_CLI_DIST_CSS = "css/tailwind.css"

# django-meta
META_SITE_PROTOCOL = "https"
META_SITE_DOMAIN = env("META_SITE_DOMAIN", default="new.makeset.be")
META_SITE_NAME = "Makeset"
META_USE_OG_PROPERTIES = True
META_USE_TWITTER_PROPERTIES = True
META_USE_SCHEMAORG_PROPERTIES = True
META_DEFAULT_IMAGE = "/static/images/logodegra.png"

# Cache (no Redis)
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "makeset",
    },
}

# Background scan queue (django-q2). The ORM broker stores tasks in the same
# DB — no Redis required at our scale. Two workers cap concurrent scans at 2,
# matching the VPS resource budget. Workers are recycled after 20 tasks to
# release memory accumulated by Playwright/etc. in later phases.
Q_CLUSTER = {
    "name": "maketrust",
    "label": "MakeTrust scan queue",
    "workers": 2,
    "timeout": 70,        # hard kill if a scan hangs
    "retry": 90,          # > timeout, so failed tasks aren't re-queued in flight
    "recycle": 20,
    "max_attempts": 1,    # don't retry: a failed scan returns a 'failed' status
    "queue_limit": 50,
    "save_limit": 250,
    "orm": "default",
    "catch_up": False,
}

# Logging. Single formatter, one handler. Scan-time events from the
# orchestrator pass key=val pairs in the message itself (`scan_done
# domain=… grade=A score=94`), greppable downstream without a custom
# formatter class.
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "{asctime} {levelname} {name}: {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "default"},
    },
    "root": {"handlers": ["console"], "level": "INFO"},
}
