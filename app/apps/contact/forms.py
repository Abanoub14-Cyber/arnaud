import time

from django import forms
from django.core.signing import BadSignature, Signer
from django.utils.translation import gettext_lazy as _

from .models import ContactMessage

_signer = Signer(salt="contact-form")
MIN_FILL_SECONDS = 3
MAX_FORM_AGE_SECONDS = 4 * 60 * 60  # 4h — generous; rare humans take longer.


def make_form_token() -> str:
    """Signed timestamp issued on each form render. The view embeds it as a
    hidden input. clean() rejects POSTs that come back too fast (bot speed) or
    too late (stale form / replay)."""
    return _signer.sign(str(int(time.time())))


class ContactForm(forms.ModelForm):
    """Public contact form with honeypot + signed time-trap."""

    # Honeypot. Rendered off-screen + aria-hidden in the template. Renamed
    # away from the well-known "website" pattern — smart bots skip the famous
    # honeypot names but happily fill anything else.
    nickname = forms.CharField(required=False, widget=forms.TextInput(attrs={
        "tabindex": "-1",
        "autocomplete": "off",
    }))

    # Signed timestamp from form render. clean() validates age bounds.
    form_token = forms.CharField(widget=forms.HiddenInput, required=True)

    class Meta:
        model = ContactMessage
        fields = ["name", "email", "company", "service", "message"]
        widgets = {
            "name": forms.TextInput(attrs={"placeholder": _("Votre nom")}),
            "email": forms.EmailInput(attrs={"placeholder": "you@example.com"}),
            "company": forms.TextInput(attrs={"placeholder": _("Optionnel")}),
            "message": forms.Textarea(attrs={"rows": 6, "placeholder": _("Décrivez votre projet ou votre question.")}),
        }

    def clean_message(self) -> str:
        message = self.cleaned_data.get("message", "").strip()
        if len(message) < 20:
            raise forms.ValidationError(_("Décrivez un peu plus votre projet (au moins 20 caractères)."))
        return message

    def clean(self):
        cleaned = super().clean()

        # Honeypot — must be empty.
        if cleaned.get("nickname"):
            raise forms.ValidationError(_("Erreur de validation. Rechargez la page et réessayez."))

        # Time-trap — verify signature and age window.
        token = cleaned.get("form_token", "")
        try:
            issued_at = int(_signer.unsign(token))
        except (BadSignature, ValueError):
            raise forms.ValidationError(_("Erreur de validation. Rechargez la page et réessayez."))
        age = int(time.time()) - issued_at
        if age < MIN_FILL_SECONDS:
            raise forms.ValidationError(_("Erreur de validation. Rechargez la page et réessayez."))
        if age > MAX_FORM_AGE_SECONDS:
            raise forms.ValidationError(_("Le formulaire a expiré. Rechargez la page et réessayez."))

        return cleaned
