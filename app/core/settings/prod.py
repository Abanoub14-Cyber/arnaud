"""Production settings (VPS, behind traefik)."""
from .base import *  # noqa: F401,F403

DEBUG = False

# HTTPS / security headers
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 63072000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
X_FRAME_OPTIONS = "DENY"

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"

# Admin geofence. Cloudflare populates CF-IPCountry, RealIPMiddleware
# reads it (trusting it only on a CF-CIDR hop), AdminGeoRestrictMiddleware
# enforces the allowlist. Override via .env to widen (e.g. "BE,FR") or
# disable entirely (empty value). A logged-in staff session passes through
# regardless of country so an existing session isn't kicked out mid-task.
import os as _os
ADMIN_ALLOWED_COUNTRIES = {
    c.strip().upper()
    for c in _os.environ.get("ADMIN_ALLOWED_COUNTRIES", "BE").split(",")
    if c.strip()
}
