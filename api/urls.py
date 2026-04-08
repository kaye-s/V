from django.urls import path
from . import views
from .views import login_view, SubmissionView, SubmissionStatusView, vulnerability_list

urlpatterns = [
    # Login / Logout
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # Dashboard (default root)
    path('', views.dashboard_view, name='dashboard'),

    path('submit/', views.submit_code, name='submit_code'),

    # Check status / get results of a submission
    path('submission/<int:submission_id>/', SubmissionStatusView.as_view(), name='submission_status'),

    path('vulnerabilities/', views.vulnerability_list, name='vulnerability_list'),
]