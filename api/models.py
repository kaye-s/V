from django.db import models

# -------------------
# Users
# -------------------
class User(models.Model):
    user_id = models.AutoField(primary_key=True)
    email = models.CharField(max_length=255, unique=True)
    password_hash = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email

    class Meta:
        db_table = "users"

# -------------------
# Code Submissions
# -------------------
class CodeSubmission(models.Model):
    submission_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='submissions')
    submission_name = models.CharField(max_length=255, null=True, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    overall_risk_score = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    simplified_summary = models.TextField(null=True, blank=True)
    detailed_summary = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"{self.submission_name} by {self.user.email}"

# -------------------
# Files
# -------------------
class File(models.Model):
    file_id = models.AutoField(primary_key=True)
    submission = models.ForeignKey(CodeSubmission, on_delete=models.CASCADE, related_name='files')
    file_name = models.CharField(max_length=255)
    file_path = models.TextField()
    file_type = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return self.file_name

# -------------------
# Threats
# -------------------
class Threat(models.Model):
    SEVERITY_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical'),
    ]

    threat_id = models.AutoField(primary_key=True)
    submission = models.ForeignKey(CodeSubmission, on_delete=models.CASCADE, related_name='threats')
    file = models.ForeignKey(File, on_delete=models.SET_NULL, null=True, blank=True, related_name='threats')
    title = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    severity_level = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    severity_score = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    recommendation = models.TextField(null=True, blank=True)
    line_number = models.IntegerField(null=True, blank=True)

    def __str__(self):
        return f"{self.title} ({self.severity_level})"

# -------------------
# CWE Reference
# -------------------
class CWE(models.Model):
    cwe_id = models.CharField(max_length=50, unique=True)
    name = models.TextField()
    description = models.TextField(null=True, blank=True)
    cvss_version = models.CharField(max_length=10, default='3.1')
    average_score = models.DecimalField(max_digits=5, decimal_places=2)
    severity = models.CharField(max_length=20, null=True, blank=True)
    categories = models.TextField(null=True, blank=True)

    class Meta:
                db_table = 'cwe'
                managed = False

    def __str__(self):
        return f"{self.cwe_id} - {self.name}"

