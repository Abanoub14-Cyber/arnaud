from django.conf import settings
from django.core.mail import EmailMessage
from django.shortcuts import render
from django.template.loader import render_to_string
from django.utils.translation import get_language, gettext as _
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit

from .forms import ContactForm, make_form_token
from .models import ContactMessage


def _empty_form(extra_initial: dict | None = None) -> ContactForm:
    """Return an unbound ContactForm with a fresh signed time-trap token."""
    initial = {"form_token": make_form_token()}
    if extra_initial:
        initial.update(extra_initial)
    return ContactForm(initial=initial)


def _real_ip_key(group, request):
    """django-ratelimit key callable. Uses RealIPMiddleware so the IP is the
    actual visitor (not Cloudflare's edge), with REMOTE_ADDR as a safety net."""
    return getattr(request, "real_ip", "") or request.META.get("REMOTE_ADDR", "")


def _send_notification_email(message: ContactMessage) -> None:
    subject = f"[Makeset] {message.get_service_display()} - {message.name}"
    body = render_to_string(
        "emails/contact_notification.txt",
        {"m": message, "site": settings.META_SITE_DOMAIN},
    )
    email = EmailMessage(
        subject=subject,
        body=body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[settings.CONTACT_EMAIL],
        reply_to=[message.email],
    )
    try:
        email.send(fail_silently=False)
    except Exception:
        # Mail failures must not break the contact form. The message is in the
        # DB and can be processed manually from /admin/.
        pass


@require_http_methods(["GET", "POST"])
@ratelimit(key=_real_ip_key, rate="5/h", method="POST", block=False)
def contact_view(request):
    is_htmx = request.headers.get("HX-Request") == "true"
    initial = {}
    service_param = request.GET.get("service")
    if service_param in dict(ContactMessage.SERVICE_CHOICES):
        initial["service"] = service_param

    if request.method == "POST":
        if getattr(request, "limited", False):
            ctx = {"error": _("Trop de soumissions. Réessayez dans une heure ou écrivez-nous directement à contact@makeset.be.")}
            template = "partials/contact_form.html" if is_htmx else "pages/contact.html"
            return render(request, template, {"form": _empty_form(), **ctx}, status=429)

        form = ContactForm(request.POST)
        if form.is_valid():
            message = form.save(commit=False)
            message.ip = getattr(request, "real_ip", "") or None
            message.user_agent = request.META.get("HTTP_USER_AGENT", "")[:1000]
            message.referer = request.META.get("HTTP_REFERER", "")[:500]
            message.locale = get_language() or ""
            message.save()
            _send_notification_email(message)

            if is_htmx:
                return render(request, "partials/contact_success.html", {"message": message})
            return render(request, "pages/contact.html", {"submitted": True, "form": _empty_form()})

        # invalid → re-render with errors
        if is_htmx:
            return render(request, "partials/contact_form.html", {"form": form}, status=400)
        return render(request, "pages/contact.html", {"form": form}, status=400)

    return render(request, "pages/contact.html", {"form": _empty_form(initial)})
