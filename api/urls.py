from django.urls import path
from .views import SubmissionView, SubmissionStatusView

urlpatterns = [
    # Create a new code submission and run analysis
    path('', SubmissionView.as_view(), name='create_submission'),

    # Check status / get results of a submission
    path('<int:submission_id>/', SubmissionStatusView.as_view(), name='submission_status'),
]