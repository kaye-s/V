from django.db import models

# -------------------
# Users
# -------------------
class User(models.Model):
    DEPARTMENT_FRONTEND = "frontend"
    DEPARTMENT_BACKEND = "backend"
    DEPARTMENT_DATABASE = "database"
    DEPARTMENT_CYBERSECURITY = "cybersecurity"
    DEPARTMENT_CHOICES = [
        (DEPARTMENT_FRONTEND, "Frontend Department"),
        (DEPARTMENT_BACKEND, "Backend Department"),
        (DEPARTMENT_DATABASE, "Database Department"),
        (DEPARTMENT_CYBERSECURITY, "Cybersecurity Department"),
    ]

    ROLE_MEMBER = "member"
    ROLE_MANAGER = "manager"
    ROLE_CHOICES = [
        (ROLE_MEMBER, "Member"),
        (ROLE_MANAGER, "Manager"),
    ]

    STATUS_PENDING = "pending"
    STATUS_ACTIVE = "active"
    STATUS_REJECTED = "rejected"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending approval"),
        (STATUS_ACTIVE, "Active"),
        (STATUS_REJECTED, "Rejected"),
    ]

    user_id = models.AutoField(primary_key=True)
    email = models.CharField(max_length=255, unique=True)
    password_hash = models.TextField()
    full_name = models.CharField(max_length=120, default="")
    department = models.CharField(max_length=32, choices=DEPARTMENT_CHOICES, default=DEPARTMENT_FRONTEND)
    role = models.CharField(max_length=16, choices=ROLE_CHOICES, default=ROLE_MEMBER)
    account_status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email

    class Meta:
        db_table = "users"

# -------------------
# Code Submissions
# -------------------
class CodeSubmission(models.Model):
    PRIORITY_LOW = "low"
    PRIORITY_MEDIUM = "medium"
    PRIORITY_URGENT = "urgent"
    PRIORITY_CHOICES = [
        (PRIORITY_LOW, "Low"),
        (PRIORITY_MEDIUM, "Medium"),
        (PRIORITY_URGENT, "Urgent"),
    ]

    INPUT_FILE = "file"
    INPUT_PASTE = "paste"
    INPUT_TEXT = "text"
    INPUT_CHOICES = [
        (INPUT_FILE, "File upload"),
        (INPUT_PASTE, "Pasted code"),
        (INPUT_TEXT, "Text question"),
    ]

    submission_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='submissions')
    submission_name = models.CharField(max_length=255, null=True, blank=True)
    report_title = models.CharField(
        max_length=200,
        blank=True,
        default="",
        help_text="User-facing name for this report (optional).",
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)

    overall_risk_score = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    simplified_summary = models.TextField(null=True, blank=True)
    detailed_summary = models.TextField(null=True, blank=True)

    scan_status = models.CharField(max_length=50, null=True, blank=True)
    risk_level = models.CharField(max_length=20, null=True, blank=True)
    incident_id = models.CharField(max_length=100, null=True, blank=True)
    report_html_path = models.TextField(null=True, blank=True)
    report_data = models.JSONField(null=True, blank=True)
    priority = models.CharField(max_length=16, choices=PRIORITY_CHOICES, default=PRIORITY_LOW)
    priority_updated_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="priority_updates"
    )
    priority_updated_at = models.DateTimeField(null=True, blank=True)
    scan_input_type = models.CharField(max_length=16, choices=INPUT_CHOICES, default=INPUT_FILE)
    focus_start_line = models.PositiveIntegerField(null=True, blank=True)
    focus_end_line = models.PositiveIntegerField(null=True, blank=True)

    def __str__(self):
        return f"{self.submission_name} by {self.user.email}"

    class Meta:
        db_table = "code_submissions"

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


class DepartmentJoinRequest(models.Model):
    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_REJECTED, "Rejected"),
    ]

    request_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="join_requests")
    requested_department = models.CharField(max_length=32, choices=User.DEPARTMENT_CHOICES)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING)
    reviewed_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="reviewed_join_requests"
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_note = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "department_join_requests"

    def __str__(self):
        return f"{self.user.email} -> {self.requested_department} ({self.status})"


class ReportComment(models.Model):
    comment_id = models.AutoField(primary_key=True)
    submission = models.ForeignKey(CodeSubmission, on_delete=models.CASCADE, related_name="comments")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="report_comments")
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "report_comments"
        ordering = ["created_at"]

    def __str__(self):
        return f"{self.user.email} on {self.submission_id}"


class UserSetting(models.Model):
    THEME_DARK = "dark"
    THEME_PURPLE = "purple"
    THEME_BLUE = "blue"
    THEME_CHOICES = [
        (THEME_DARK, "Dark"),
        (THEME_PURPLE, "Purple"),
        (THEME_BLUE, "Blue"),
    ]

    setting_id = models.AutoField(primary_key=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="settings")
    theme = models.CharField(max_length=20, choices=THEME_CHOICES, default=THEME_DARK)
    ai_model = models.CharField(max_length=120, blank=True, default="")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "user_settings"

    def __str__(self):
        return f"Settings for {self.user.email}"

