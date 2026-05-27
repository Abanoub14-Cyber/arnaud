from django.urls import path
from django.utils.translation import gettext_lazy as _

from . import views

urlpatterns = [
    path(_("mentions-legales/"), views.MentionsView.as_view(), name="legal_mentions"),
    path(_("confidentialite/"), views.PrivacyView.as_view(), name="legal_privacy"),
    path(_("cgv/"), views.TermsView.as_view(), name="legal_terms"),
    path(_("cookies/"), views.CookiesView.as_view(), name="cookies"),
]
