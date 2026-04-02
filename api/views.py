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
from .models import CodeSubmission, File, Threat
from pathlib import Path
import tempfile
import shutil
from .utils.prescan import run_semgrep, run_gitleaks

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
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('dashboard')
        else:
            error = "Invalid username or password"
    return render(request, 'login.html', {'error': error})

def logout_view(request):
    logout(request)
    return redirect('login')

# -------------------
# Dashboard
# -------------------
@login_required(login_url='/login/')  # Redirects to login if not logged in
def dashboard_view(request):
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
            # Create an isolated temp directory so semgrep/gitleaks can scan it safely.
            tmp_dir_path = Path(tempfile.mkdtemp(prefix="autopen_"))
            try:
                target_file_path = tmp_dir_path / "target.py"
                target_file_path.write_text(code, encoding="utf-8")

                # Pre-process: run semgrep + gitleaks against the temporary file.
                semgrep_report = run_semgrep(str(target_file_path))
                gitleaks_report = run_gitleaks(str(target_file_path))

                # Keep the prompt size bounded.
                max_code_chars = 8000
                truncated = code[:max_code_chars]
                trunc_note = ""
                if len(code) > max_code_chars:
                    trunc_note = f"\n\n[NOTE] Code was truncated to the first {max_code_chars} characters."

                # Keep tool findings compact to reduce token usage.
                semgrep_results = semgrep_report.get("results", []) or []
                gitleaks_results = gitleaks_report.get("results", []) or []
                semgrep_results = semgrep_results[:20]
                gitleaks_results = gitleaks_results[:20]

                # Assemble a single "passage" for OpenAI analysis.
                passage = {
                    "user_code": truncated + trunc_note,
                    "semgrep": {
                        "error": semgrep_report.get("error"),
                        "results": semgrep_results,
                    },
                    "gitleaks": {
                        "error": gitleaks_report.get("error"),
                        "results": gitleaks_results,
                    },
                }

                prompt = (
                    "You are a security analysis assistant.\n\n"
                    "Analyze this passage and tell me the consequences of following up and not following up.\n\n"
                    "## Passage (code + tool findings)\n"
                    f"{json.dumps(passage, ensure_ascii=False, indent=2)}\n\n"
                    "## Output requirements\n"
                    "1. Provide a clear overall risk summary (1-2 sentences).\n"
                    "2. Provide 'Consequences if following up' and 'Consequences if not following up'.\n"
                    "3. For each consequence, include which tool finding(s) it is based on.\n"
                    "4. End with 'Recommended next steps' (3-5 bullet points) focusing on practical remediation.\n"
                    "5. Do not invent findings that are not supported by the passage.\n"
                )

                result = ask_ai(prompt)
            except Exception as e:
                # Return an error string so the front-end still shows something useful.
                result = f"Analysis failed: {type(e).__name__}: {e}"
            finally:
                # Best-effort cleanup of temporary files.
                shutil.rmtree(tmp_dir_path, ignore_errors=True)

    return render(request, 'index.html', {'result': result})
