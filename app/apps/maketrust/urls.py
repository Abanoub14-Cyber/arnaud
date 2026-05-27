from django.urls import path

from . import views


app_name = "maketrust"


urlpatterns = [
    path("", views.landing, name="landing"),
    path("scan/<uuid:scan_id>/", views.scan_result, name="scan_result"),
    path("scan/<uuid:scan_id>/progress/", views.scan_progress, name="scan_progress"),
    path("scan/<uuid:scan_id>/status/", views.scan_status_partial, name="scan_status_partial"),
    path("scan/<uuid:scan_id>/abort/", views.scan_abort, name="scan_abort"),
    path("scan/<uuid:scan_id>/rescan/", views.scan_rescan, name="scan_rescan"),
]
