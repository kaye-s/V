from django.contrib.auth import get_user
from django.urls import path
from .views import *

urlpatterns = [
    path("analysis/", AnalysisView.as_view(), name="analysis"),
    path("analysis/<uuid:task_id>/", StatusView.as_view(), name="analysis-status"),
]