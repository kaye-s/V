from django.test import TestCase

# Create your tests here.
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
from rest_framework import status
from .models import CodeSubmission, File, Threat
from .tasks import run_analysis_sync

User = get_user_model()

class CodeSubmissionTests(APITestCase):

    def setUp(self):
        # create a test user
        self.user = User.objects.create(
            email="testuser@example.com",
            password_hash="hashedpassword"
        )
        # log in manually if using session auth, or skip if using token auth
        self.client.force_authenticate(user=self.user)

    def test_create_submission(self):
        response = self.client.post("/api/scanner/", {
            "submission_name": "hello.py",
            "code": "print('Hello World')"
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("submission_id", response.data)

    def test_workflow(self):
        # create submission
        submission = CodeSubmission.objects.create(
            user=self.user,
            submission_name="hello_again.py"
        )

        # create associated file
        File.objects.create(
            submission=submission,
            file_name="hello_again.py",
            file_path="",
            file_type="code"
        )

        # run dummy analysis
        run_analysis_sync(submission.submission_id)

        # refresh from DB
        submission.refresh_from_db()

        # confirm dummy analysis populated summaries
        self.assertTrue(submission.simplified_summary)
        self.assertTrue(submission.detailed_summary)

        # confirm threats created
        self.assertGreaterEqual(submission.threats.count(), 1)
