from django.urls import path
from django.utils.translation import gettext_lazy as _

from . import views

urlpatterns = [
    path(_("services/"), views.ServicesIndexView.as_view(), name="services_index"),
    path(_("services/cybersecurite/"), views.CyberView.as_view(), name="service_cyber"),
    path(_("services/web/"), views.WebView.as_view(), name="service_web"),
    path(_("services/ia-automation/"), views.IAView.as_view(), name="service_ia"),
    path(_("services/support/"), views.SupportView.as_view(), name="service_support"),
]
