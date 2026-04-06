from django.contrib.auth.hashers import make_password, check_password
from django.shortcuts import render, redirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .serializers import CodeSubmissionSerializer
from .tasks import run_analysis_sync
from django.http import JsonResponse
import json
from .services.ai_service import ask_ai
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from .models import CodeSubmission, File, Threat, User

def ask_ai_view(request):
    if request.method == "POST":
        data = json.loads(request.body)
        user_text = data.get("message")

        response = ask_ai(user_text)

        return JsonResponse({"response": response})

def scan_view(request):
    target_path = "/path/to/code"  # you could get this from request.POST
    report = {
        "input_path": str(Path(target_path).resolve()),
        "semgrep": run_semgrep(target_path),
        "gitleaks": run_gitleaks(target_path),
    }
    return JsonResponse(report)

# -------------------
# Create a new code submission and run analysis
# -------------------
class SubmissionView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = CodeSubmissionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # create submission
        submission = serializer.save(user=request.user)

        # run analysis (sync for now)
        run_analysis_sync(submission.submission_id)

        return Response({
            "submission_id": submission.submission_id,
            "simplified_summary": submission.simplified_summary
        }, status=201)

# -------------------
# Check status and results of a submission
# -------------------
class SubmissionStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, submission_id):
        try:
            submission = CodeSubmission.objects.get(submission_id=submission_id, user=request.user)
        except CodeSubmission.DoesNotExist:
            return Response({"error": "Submission not found"}, status=404)

        # If threats exist, include them in the response
        threats = [
            {
                "title": t.title,
                "severity": t.severity_level,
                "recommendation": t.recommendation
            }
            for t in submission.threats.all()
        ]

        return Response({
            "submission_id": submission.submission_id,
            "simplified_summary": submission.simplified_summary,
            "threats": threats
        })

# -------------------
# Login / Logout
# -------------------
def login_view(request):
    error = None
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        if not email or not password:
            error = "Enter Email and Password"
        else:
            try:
                user = User.objects.get(email=email)

                if check_password(password, user.password_hash):
                    request.session["user_id"] = user.user_id
                    request.session["user_email"] = user.email
                    return redirect("dashboard")
                else:
                    error = "Invalid Email or Password"
            except User.DoesNotExist:
                error = "Invalid Email or Password"
    return render(request, 'login.html', {'error': error})

def logout_view(request):
    request.session.flush()
    return redirect('login')

# -------------------
# Dashboard
# -------------------
def dashboard_view(request):
    if "user_id" not in request.session:
        return redirect("/login/")
    return render(request, 'index.html')

# -------------------
# Dummy Code Submission
# -------------------
@login_required
def submit_code(request):
    print("HIT SUBMIT VIEW")
    result = None

    if request.method == "POST":
        code = request.POST.get("code", "")

        print("CODE:", code)  # debug

        if not code.strip():
            result = "No code submitted."
        else:
            result = f"Received {len(code.splitlines())} lines of code. Dummy analysis: All good!"

    return render(request, 'index.html', {'result': result})

# -----------------
# User Registration
# -----------------
def register_view(request):
    error = None

    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        if not email or not password:
            error = "Enter Email and Password"

        elif User.objects.filter(email=email).exists():
            error = "Email Already in Use"

        else:
            hashed_pass = make_password(password)

            user = User.objects.create(email=email, password_hash=hashed_pass)
            request.session["user_id"] = user.user_id
            return redirect('dashboard')

    return render(request, 'register.html', {'error': error})
