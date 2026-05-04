from django.urls import path
from . import views
from .views import login_view, SubmissionView, SubmissionStatusView, vulnerability_list

urlpatterns = [
    # Login / Logout
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # Register
    path('register/', views.register_view, name='register'),

    # Dashboard (default root)
    path('', views.dashboard_view, name='dashboard'),

    path('submit/', views.submit_code, name='submit_code'),
    path('scan/', views.start_scan_view, name='start_scan'),
    path('reports/', views.reports_view, name='reports'),
    path('targets/', views.targets_view, name='targets'),
    path('settings/', views.settings_view, name='settings'),
    path("personal/", views.personal_info_view, name="personal_info"),

    # Check status / get results of a submission
    path('submission/<int:submission_id>/', SubmissionStatusView.as_view(), name='submission_status'),

    path('vulnerabilities/', views.vulnerability_list, name='vulnerability_list'),
    path("approvals/", views.approval_queue_view, name="approval_queue"),

    path("report/<int:submission_id>/", views.report_detail_view, name="report_detail"),

    path("assistant/chat/", views.assistant_chat_view, name="assistant_chat"),
]