"""Development settings."""
from .base import *  # noqa: F401,F403

DEBUG = True
ALLOWED_HOSTS = ["*"]
SECRET_KEY = "dev-insecure-key-replace-in-prod"  # noqa: S105

INSTALLED_APPS += ["debug_toolbar"]  # noqa: F405
MIDDLEWARE = [
    "debug_toolbar.middleware.DebugToolbarMiddleware",
    *MIDDLEWARE,  # noqa: F405
]
INTERNAL_IPS = ["127.0.0.1"]

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
