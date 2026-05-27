from django.urls import path
from django.utils.translation import gettext_lazy as _

from . import views

urlpatterns = [
    path(_("contact/"), views.contact_view, name="contact"),
]
