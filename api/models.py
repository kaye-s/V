#all id related lines are noted and can be deleted or changed if user id is skipped or substituted
import uuid #for user ID
from django.db import models
from django.contrib.auth.models import User

class AnalysisTask(models.Model):
    #potential review request statuses
    STATUS_OPT = [
        ("QUEUED", "Queued"),
        ("RUNNING", "Running"),
        ("COMPLETED", "Completed"),
        ("FAILED", "Failed")
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4) #more user id
    user = models.ForeignKey(User, on_delete=models.CASCADE) #user id/user
    input_code = models.TextField() #user provided code
    language = models.CharField(max_length=50) #language of user provided code
    status = models.CharField(max_length=20, choices=STATUS_OPT) #status of review request
    results = models.JSONField(null=True, blank=True) #results of review
    created_at = models.DateTimeField(auto_now_add=True) #creation timestamp
