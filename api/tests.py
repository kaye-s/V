from rest_framework.test import APITestCase
from django.contrib.auth.models import User
from rest_framework import status
from .models import *
from uuid import uuid4


class InitialAnalysisTests(APITestCase):

    def setUp(self):
        #create user
        self.User = User.objects.create_user(
            username="username",
            password="password"
        )
        self.client.login(username="username", password="password")

    def test_create_analysisTask(self):

        response = self.client.post("/api/analysis/",{
            "code" : "print('Hello World')", #code to analyze
            "language" : "Python" #language of code
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("task_id", response.data) #task_id in data
        self.assertEqual(response.data["status"], "QUEUED")

class InitialWorkflowTest(APITestCase):

    def setUp(self):
        #create user
        self.User = User.objects.create_user(
            username="username",
            password="password"
        )
        self.client.login(username="username", password="password")

    def test_initial_workflow(self):
        response = self.client.post("/api/analysis/",{
            "code" : "print('Hello Again')", #code to analyze
            "language" : "Python" #language of code
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        task_id = response.data["task_id"]

        task = AnalysisTask.objects.get(id=task_id)

        #confirm that dummy ran
        self.assertEqual(task.status, "COMPLETED")

        result_response = self.client.get(f"/api/analysis/{task_id}/")

        #ensure task endpoint
        self.assertEqual(result_response.status_code, 200)



