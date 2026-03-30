from django.contrib.auth import get_user
from django.urls import path
from .views import *

urlpatterns = [
    # Login / Logout
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # Dashboard (default root)
    path('', views.dashboard_view, name='dashboard'),

    # Create a new code submission and run analysis
    path('submit-code/', SubmissionView.as_view(), name='create_submission'),

    # Check status / get results of a submission
    path('submission/<int:submission_id>/', SubmissionStatusView.as_view(), name='submission_status'),
]