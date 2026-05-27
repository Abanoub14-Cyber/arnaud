from django.db import models
from django.utils.translation import gettext_lazy as _


class ContactMessage(models.Model):
    SERVICE_CYBER = "cyber"
    SERVICE_WEB = "web"
    SERVICE_IA = "ia"
    SERVICE_SUPPORT = "support"
    SERVICE_OTHER = "other"
    SERVICE_CHOICES = [
        (SERVICE_CYBER, _("Cybersécurité")),
        (SERVICE_WEB, _("Web & Apps")),
        (SERVICE_IA, _("IA & Automatisation")),
        (SERVICE_SUPPORT, _("Support")),
        (SERVICE_OTHER, _("Autre")),
    ]

    name = models.CharField(_("Nom"), max_length=120)
    email = models.EmailField(_("Email"))
    company = models.CharField(_("Entreprise"), max_length=120, blank=True)
    service = models.CharField(_("Service"), max_length=20, choices=SERVICE_CHOICES, default=SERVICE_OTHER)
    message = models.TextField(_("Message"))

    created_at = models.DateTimeField(auto_now_add=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    referer = models.URLField(blank=True, max_length=500)
    locale = models.CharField(max_length=10, blank=True)
    handled = models.BooleanField(default=False)

    class Meta:
        verbose_name = _("Message de contact")
        verbose_name_plural = _("Messages de contact")
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.name} - {self.get_service_display()} ({self.created_at:%Y-%m-%d})"
