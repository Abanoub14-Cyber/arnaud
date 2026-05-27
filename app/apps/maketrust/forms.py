from datetime import timedelta

from django import forms
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .scanner.safety import DomainValidationError, validate_domain


# Domains we deliberately refuse to scan. Restricted to the IANA reserved
# example.* names (RFC 2606): they resolve, but the scan result is meaningless
# noise. Everything else, including our own makeset.be and big providers,
# is scannable on purpose - we want users to be able to benchmark against
# real public sites. SSRF guard lives in `safety.validate_domain`.
BLOCKLIST: frozenset[str] = frozenset({
    "example.com", "example.org", "example.net",
})


# Per-IP cap across ALL domains. Subsumes any per-(IP, domain) cap because
# hitting N scans on one domain implies N scans for the IP. Hit-rate-limited
# visitors get a clear message to contact us if they need more scans for a
# legitimate reason.
MAX_SCANS_PER_IP_24H = 10


# Small built-in fallback list (~80 most-common providers) used when the
# bundled disposable-email-domains data file isn't accessible — and never
# loses to disposable.github.io's much larger list when both are available.
# Kept tight: if loading from the file ever breaks at runtime, we still
# catch the bulk of real-world disposable traffic.
DISPOSABLE_EMAIL_DOMAINS_FALLBACK: frozenset[str] = frozenset({
    # Mailinator family
    "mailinator.com", "mailinator2.com", "mailinator.net", "binkmail.com",
    "bobmail.info", "chammy.info", "devnullmail.com",
    # 10-minute mail
    "10minutemail.com", "10minutemail.net", "10minutemail.org",
    "10minemail.com", "10minutesmail.com", "10minutemail.co.uk",
    # Guerrilla / Sharklasers
    "guerrillamail.com", "guerrillamail.org", "guerrillamail.biz",
    "guerrillamail.net", "guerrillamail.de", "guerrillamailblock.com",
    "sharklasers.com", "grr.la", "pokemail.net", "spam4.me",
    # YOPmail
    "yopmail.com", "yopmail.fr", "yopmail.net", "cool.fr.nf",
    "courriel.fr.nf", "jetable.fr.nf", "nospam.ze.tc", "yepmail.net",
    # Temp-mail / tempr / tempinbox / tmpmail
    "tempmail.com", "tempmail.io", "tempmail.dev", "tempmail.email",
    "tempmailo.com", "tempinbox.com", "tempr.email", "temp-mail.org",
    "tempmail.us.com", "tempmail.plus", "tmpmail.org", "tmpmailout.com",
    # Throwaway
    "throwawaymail.com", "throwawaymailaddress.com", "trashmail.com",
    "trashmail.de", "trashmail.io", "trashmail.net", "trashmail.ws",
    "trashmailer.com", "trashmail.fr", "dispostable.com",
    "mailcatch.com", "discard.email", "discardmail.com",
    # Maildrop / nada / getnada
    "maildrop.cc", "getnada.com", "nada.email", "moakt.com", "moakt.cc",
    # Fake mail
    "fake-email.com", "fakeinbox.com", "fakemailgenerator.com",
    "emailfake.com", "emailtemp.org", "fakemail.fr", "fakemail.net",
    # AirMail / Burner / Mintemail / Mohmal / Spambox
    "getairmail.com", "airmail.cc", "burnermail.io",
    "mintemail.com", "mohmal.com", "spambox.us", "spambox.me",
    "spambog.com", "spamavert.com", "filzmail.com",
    # 0-N + misc one-shots
    "0815.ru", "1secmail.com", "1secmail.org", "1secmail.net",
    "33mail.com", "anonbox.net", "anon.email", "anonymbox.com",
    "tempemail.net", "tempemail.co", "throaway.com",
    # E-mail / one-off services that come up
    "mailnesia.com", "mailnull.com", "mt2009.com", "spamgourmet.com",
    "tmail.ws", "wegwerfemail.de", "trash-mail.com",
})


def _load_disposable_domains() -> frozenset[str]:
    """Load the comprehensive disposable-email-domains list from disk.

    Sourced from https://disposable.github.io/disposable-email-domains/domains.txt
    (~72k entries). Bundled at build time so we don't hit GitHub at runtime.
    On any I/O failure we fall back to the small built-in set so the email
    gate keeps working.
    """
    from pathlib import Path
    data_path = Path(__file__).parent / "data" / "disposable_email_domains.txt"
    try:
        text = data_path.read_text(encoding="utf-8")
    except OSError:
        return DISPOSABLE_EMAIL_DOMAINS_FALLBACK
    seen = {
        line.strip().lower()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    }
    # Union with the fallback in case the community list is missing a niche one.
    return frozenset(seen | DISPOSABLE_EMAIL_DOMAINS_FALLBACK)


# Module-level cache. Populated on first access via `_get_disposable_domains`
# so we don't pay the file read until the form is actually used. ~1MB on disk,
# ~8MB resident as a frozenset — fine for one Python process.
_DISPOSABLE_CACHE: frozenset[str] | None = None


def _get_disposable_domains() -> frozenset[str]:
    global _DISPOSABLE_CACHE
    if _DISPOSABLE_CACHE is None:
        _DISPOSABLE_CACHE = _load_disposable_domains()
    return _DISPOSABLE_CACHE


def _is_disposable_email(address: str) -> bool:
    """True if the email domain (or any parent) is on the disposable list."""
    if "@" not in address:
        return False
    domain = address.rsplit("@", 1)[1].lower().strip(".")
    parts = domain.split(".")
    disposable = _get_disposable_domains()
    # Walk parents: foo.bar.mailinator.com -> bar.mailinator.com -> mailinator.com
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in disposable:
            return True
    return domain in disposable


class DomainBlockedError(forms.ValidationError):
    """Sentinel: kept distinct from generic ValidationError for tests."""


def _ip_overscanned(ip_hash: str) -> bool:
    """True iff THIS IP has already started 10+ scans today, all domains
    combined. Catches the spray-and-pray attacker scanning many targets
    from one IP — they'd dodge per-domain caps otherwise. Aborted scans
    don't count toward the limit (consistent with the cooldown counter).
    """
    if not ip_hash:
        return False
    from .models import Scan
    cutoff = timezone.now() - timedelta(hours=24)
    return Scan.objects.filter(
        requested_ip_hash=ip_hash, queued_at__gte=cutoff,
    ).exclude(status=Scan.Status.ABORTED).count() >= MAX_SCANS_PER_IP_24H


# Progressive cooldown: 0s for the first two scans/hour from a given IP or
# email, then quadratic growth capped at 5 minutes. Tuned so a real user
# iterating on DNS fixes (a scan every 5-10 minutes while waiting for
# propagation) never sees a wait, while a tight loop hits 5min after ~8
# attempts. Window is rolling (last 60 minutes).
COOLDOWN_WINDOW = timedelta(hours=1)
COOLDOWN_FREE_TIER = 2  # first N scans in the window have no delay
COOLDOWN_MAX_SECONDS = 300


def _progressive_cooldown_remaining(ip_hash: str, email_hash: str = "") -> int:
    """Seconds the visitor must still wait before their next scan is allowed.

    Counts non-aborted scans matching either identity (IP hash or email
    hash) in the last hour. If that count is over the free tier, applies
    a quadratic delay since the most recent scan: 5 * (count - 2) ** 2,
    clamped to COOLDOWN_MAX_SECONDS. Aborted scans don't burn the budget.

    Returns 0 when no wait is needed. The caller queues the scan anyway
    and sets `Scan.scheduled_for = now + N` so the worker delays execution
    while the progress page shows a live countdown.
    """
    if not ip_hash and not email_hash:
        return 0

    from django.db.models import Max, Q

    from .models import Scan

    identity = Q()
    if ip_hash:
        identity |= Q(requested_ip_hash=ip_hash)
    if email_hash:
        identity |= Q(requested_email_hash=email_hash)

    cutoff = timezone.now() - COOLDOWN_WINDOW
    recent = Scan.objects.filter(identity, queued_at__gte=cutoff).exclude(
        status=Scan.Status.ABORTED,
    )
    count = recent.count()
    if count <= COOLDOWN_FREE_TIER:
        return 0

    required = min(COOLDOWN_MAX_SECONDS, 5 * (count - COOLDOWN_FREE_TIER) ** 2)
    last_at = recent.aggregate(Max("queued_at"))["queued_at__max"]
    if last_at is None:
        return 0
    elapsed = (timezone.now() - last_at).total_seconds()
    remaining = required - elapsed
    return max(0, int(remaining))


class ScanForm(forms.Form):
    domain = forms.CharField(
        label=_("Domaine ou adresse email à scanner"),
        max_length=253,
        widget=forms.TextInput(attrs={
            "placeholder": _("votredomaine.be"),
            "autocomplete": "off",
            "autocapitalize": "none",
            "spellcheck": "false",
            "inputmode": "url",
            "class": "w-full px-5 py-4 rounded-md bg-surface-lowest border border-outline-variant focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none transition text-lg",
        }),
    )
    email = forms.EmailField(
        label=_("Email"),
        required=False,
        widget=forms.EmailInput(attrs={
            "placeholder": _("vous@entreprise.be"),
            "autocomplete": "email",
            "class": "w-full px-5 py-3 rounded-md bg-surface-lowest border border-outline-variant focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none transition",
        }),
    )
    # Hidden flag set when the visitor arrives from the result page's rescan
    # FAB. Forces the email-gate regardless of the IP's quota state: rescans
    # always need an email so we can follow up and so disposable accounts
    # can't spam the system. Round-trips through both GET (pre-fill via the
    # view) and POST submission.
    rescan = forms.BooleanField(
        required=False,
        widget=forms.HiddenInput(),
    )

    def __init__(self, *args, email_required: bool = False, ip_hash: str = "",
                 is_staff: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self.ip_hash = ip_hash
        # Authenticated Django admins (request.user.is_staff via the
        # AuthenticationMiddleware session cookie) bypass ALL rate-limits:
        # per-IP cap, per-domain cap, progressive cooldown, email-gate.
        # Replaces the previous static BYPASS_IP_HASHES / BYPASS_RATE_LIMIT_DOMAINS
        # lists — easier to manage (log in to /admin/) and tied to a session
        # cookie instead of a hash baked into the codebase.
        self.is_staff = is_staff
        # Detect the rescan flag at construction time.
        raw_rescan = False
        if self.is_bound:
            raw_rescan = bool(self.data.get("rescan"))
        else:
            raw_rescan = bool((kwargs.get("initial") or {}).get("rescan"))
        self.is_rescan = raw_rescan

        # Email gate doesn't apply to authenticated admins.
        self.email_required = (email_required or raw_rescan) and not is_staff
        if self.email_required:
            self.fields["email"].required = True

    def get_cooldown_delay(self) -> int:
        """Compute how many seconds the new scan should be scheduled in the future.

        Called by the view AFTER the form is validated. Returns 0 when the
        scan can run immediately, OR when the visitor is a logged-in admin.
        """
        if not self.is_valid() or self.is_staff:
            return 0
        from apps.website.middleware import hash_ip

        email = self.cleaned_data.get("email") or ""
        email_hash = hash_ip(email) if email else ""
        return _progressive_cooldown_remaining(self.ip_hash, email_hash)

    def clean_domain(self) -> str:
        raw = self.cleaned_data["domain"].strip()
        # Accept "user@domain.tld" syntax — common when the user wants to
        # check the email security of a domain that hosts no website.
        # rsplit so "a@b@example.com" still reduces to the tail "example.com".
        if "@" in raw:
            raw = raw.rsplit("@", 1)[-1]
        try:
            domain = validate_domain(raw)
        except DomainValidationError as exc:
            raise forms.ValidationError(
                _("Domaine invalide : %(reason)s"), params={"reason": str(exc)}
            ) from None

        if domain in BLOCKLIST:
            raise forms.ValidationError(
                _("Ce domaine ne peut pas être scanné publiquement.")
            )

        # Staff bypasses the cap.
        if self.is_staff:
            return domain

        if _ip_overscanned(self.ip_hash):
            raise forms.ValidationError(
                _("Vous avez atteint la limite de %(n)d scans par jour. "
                  "Contactez-nous à contact@makeset.be si vous avez un "
                  "besoin légitime de plus de scans."),
                params={"n": MAX_SCANS_PER_IP_24H},
            )

        return domain

    def clean_email(self) -> str:
        """Reject disposable / throwaway email providers.

        Django's EmailField already enforces RFC 5321 syntax. We layer on
        a domain check against our DISPOSABLE_EMAIL_DOMAINS set. Walks the
        domain's parents so `foo.mailinator.com` is rejected just like
        `mailinator.com`.

        An empty email is fine when the field isn't required (free first
        scan from a fresh IP). This method only runs after EmailField has
        already validated syntax and required-ness.
        """
        email = (self.cleaned_data.get("email") or "").strip().lower()
        if not email:
            return ""
        if _is_disposable_email(email):
            raise forms.ValidationError(
                _("Les adresses email jetables ne sont pas acceptées. "
                  "Utilisez une adresse de votre entreprise.")
            )
        return email

class RescanForm(forms.Form):
    """Smaller form for the in-modal "Relancer le scan" flow.

    Only asks for an email — the domain and DKIM selectors are carried over
    from the source scan server-side, so the user can't change those mid-
    rescan (that would be a "different scan", not a re-test). Email is
    always required here (the rescan FAB is the abuse-control choke point).
    """
    email = forms.EmailField(
        label=_("Votre email"),
        required=True,
        widget=forms.EmailInput(attrs={
            "placeholder": _("vous@entreprise.be"),
            "autocomplete": "email",
            "autofocus": "autofocus",
            "class": "w-full px-5 py-3 rounded-md bg-surface-lowest border border-outline-variant focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none transition",
        }),
    )

    def __init__(self, *args, ip_hash: str = "", is_staff: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self.ip_hash = ip_hash
        self.is_staff = is_staff
        if is_staff:
            # An authenticated admin doesn't need to retype their email for
            # the rescan; the form will accept an empty value.
            self.fields["email"].required = False

    def clean_email(self) -> str:
        email = (self.cleaned_data.get("email") or "").strip().lower()
        if not email:
            return ""
        if _is_disposable_email(email):
            raise forms.ValidationError(
                _("Les adresses email jetables ne sont pas acceptées. "
                  "Utilisez une adresse de votre entreprise.")
            )
        return email

    def get_cooldown_delay(self) -> int:
        """Same contract as ScanForm.get_cooldown_delay — staff bypass."""
        if not self.is_valid() or self.is_staff:
            return 0
        from apps.website.middleware import hash_ip

        email = self.cleaned_data.get("email") or ""
        email_hash = hash_ip(email) if email else ""
        return _progressive_cooldown_remaining(self.ip_hash, email_hash)
