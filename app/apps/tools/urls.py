from django.urls import path
from django.utils.translation import gettext_lazy as _

from . import views

urlpatterns = [
    path(_("outils/"), views.ToolsIndexView.as_view(), name="tools_index"),
]
