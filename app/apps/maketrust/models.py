from __future__ import annotations

import uuid

from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _


class Scan(models.Model):
    """A single scan run for a domain.

    The UUID primary key doubles as the public-facing handle: result URLs
    look like ``/outils/maketrust/scan/<uuid>/``. Unguessable, so anyone
    sharing a link can show their result without auth.
    """

    class Status(models.TextChoices):
        QUEUED = "queued", _("En file d'attente")
        RUNNING = "running", _("En cours")
        DONE = "done", _("Terminé")
        FAILED = "failed", _("Échec")
        ABORTED = "aborted", _("Annulé")

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    domain = models.CharField(_("Domaine"), max_length=253, db_index=True)
    status = models.CharField(
        _("Statut"), max_length=10, choices=Status.choices,
        default=Status.QUEUED, db_index=True,
    )

    queued_at = models.DateTimeField(_("Mis en file"), auto_now_add=True)
    # Set when progressive cooldown applies — the worker sleeps until this
    # moment before starting. None = no delay, run as soon as picked up.
    scheduled_for = models.DateTimeField(
        _("Démarrage planifié"), null=True, blank=True,
    )
    started_at = models.DateTimeField(_("Démarré"), null=True, blank=True)
    finished_at = models.DateTimeField(_("Terminé"), null=True, blank=True)

    overall_score = models.PositiveSmallIntegerField(
        _("Score global"), null=True, blank=True,
    )
    grade = models.CharField(_("Grade"), max_length=2, blank=True)
    summary = models.JSONField(_("Résumé sévérités"), default=dict)

    # The og:image URL we lift from the scanned site's homepage, used as a
    # visual confirmation in the report. Empty when the site has no og:image
    # tag or when the fetch failed.
    preview_image_url = models.URLField(_("Aperçu"), max_length=500, blank=True)
    preview_title = models.CharField(_("Titre de la page"), max_length=300, blank=True)

    requested_ip_hash = models.CharField(max_length=64, blank=True, db_index=True)
    requested_email = models.EmailField(_("Email"), blank=True)
    requested_email_hash = models.CharField(max_length=64, blank=True, db_index=True)
    locale = models.CharField(_("Locale"), max_length=5, default="fr")
    is_public = models.BooleanField(_("Rapport public"), default=True)

    error_message = models.TextField(_("Message d'erreur"), blank=True)

    # True when the scan was submitted by an authenticated Django admin (staff
    # session cookie present). Lets us filter our own dogfooding scans out
    # of traction metrics in the admin without relying on a fragile IP-hash
    # whitelist. Defaults to False for every visitor-driven scan.
    is_internal = models.BooleanField(
        _("Scan interne"), default=False, db_index=True,
        help_text=_("Coché automatiquement quand un admin connecté lance le scan."),
    )

    # Comma-separated list of DKIM selectors the user knows their domain uses
    # (e.g. "ed1,ed2,rsa1,rsa2" for Mailcow-style setups). Probed in addition
    # to our built-in COMMON_SELECTORS list. Stays empty for the vast majority
    # of scans — only filled when the user filled the optional form field.
    extra_dkim_selectors = models.CharField(
        _("Sélecteurs DKIM additionnels"), max_length=255, blank=True, default="",
    )

    class Meta:
        ordering = ["-queued_at"]
        indexes = [
            models.Index(fields=["status", "queued_at"]),
            models.Index(fields=["domain", "-queued_at"]),
        ]
        verbose_name = _("Scan")
        verbose_name_plural = _("Scans")

    def __str__(self) -> str:
        return f"{self.domain} ({self.status})"

    def get_absolute_url(self) -> str:
        return reverse("maketrust:scan_result", kwargs={"scan_id": self.id})

    @property
    def is_finished(self) -> bool:
        return self.status in (
            self.Status.DONE, self.Status.FAILED, self.Status.ABORTED,
        )


class Check(models.Model):
    """One finding produced by a scanner module during a scan."""

    class Severity(models.TextChoices):
        PASS = "pass", _("OK")
        INFO = "info", _("Info")
        LOW = "low", _("Faible")
        MEDIUM = "medium", _("Moyenne")
        HIGH = "high", _("Élevée")
        CRITICAL = "critical", _("Critique")

    SEVERITY_ORDER = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
        Severity.PASS: 5,
    }

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="checks")
    module = models.CharField(_("Module"), max_length=50, db_index=True)
    severity = models.CharField(
        _("Sévérité"), max_length=10, choices=Severity.choices, db_index=True,
    )
    title_key = models.CharField(_("Titre (clé i18n)"), max_length=100)
    fix_key = models.CharField(_("Correctif (clé i18n)"), max_length=100, blank=True)
    finding = models.JSONField(_("Données brutes"), default=dict)
    evidence = models.TextField(_("Preuve textuelle"), blank=True)
    duration_ms = models.PositiveIntegerField(_("Durée (ms)"), default=0)

    class Meta:
        ordering = ["module", "id"]
        verbose_name = _("Vérification")
        verbose_name_plural = _("Vérifications")

    def __str__(self) -> str:
        return f"{self.module}:{self.title_key} ({self.severity})"

    @property
    def display(self) -> dict:
        """Translated title, plain-language summary, and fix snippet for templates."""
        from .findings import get_finding
        f = get_finding(self.title_key)
        return {
            "title": f["title"],
            "summary_plain": f["summary_plain"],
            "fix_text": f["fix_text"],
        }


