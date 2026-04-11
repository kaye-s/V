from django.shortcuts import render, redirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .serializers import CodeSubmissionSerializer
from .tasks import run_analysis_sync
from django.http import JsonResponse
import json
from .services.ai_service import ask_ai
from .services.incident_report_ai import generate_incident_report_ai_payload
from .utils.incident_report import (
    DISCLAIMER_TEXT,
    merge_incident_report_context,
    parse_llm_json,
)
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from .models import CodeSubmission, File, Threat
from pathlib import Path
import re
import tempfile
import shutil
from .utils.prescan import run_semgrep, run_gitleaks

# Max upload size for scan (bytes).
MAX_UPLOAD_BYTES = 2 * 1024 * 1024


def _safe_upload_basename(original_name: str) -> str:
    """Return a single path segment safe for writing under a temp directory."""
    base = Path(original_name).name
    if not base or base in {".", ".."}:
        return "upload.txt"
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", base)
    if len(safe) > 200:
        stem = Path(safe).stem[:150]
        suffix = Path(safe).suffix[:20]
        safe = stem + suffix
    return safe or "upload.txt"


def _read_uploaded_text(uploaded) -> str:
    """Read uploaded file as text with a hard size cap."""
    chunk = uploaded.read(MAX_UPLOAD_BYTES + 1)
    if len(chunk) > MAX_UPLOAD_BYTES:
        raise ValueError(
            f"File is too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB)."
        )
    return chunk.decode("utf-8", errors="replace")


def _run_incident_scan(request, code: str, source: dict):
    """
    Shared pipeline: write code to a temp file, pre-scan, call OpenAI JSON report, render HTML.
    source: {"origin": "upload"|"paste", "filename": str}
    """
    tmp_dir_path = Path(tempfile.mkdtemp(prefix="autopen_"))
    try:
        if source.get("origin") == "upload":
            fname = _safe_upload_basename(source.get("filename") or "upload.txt")
        else:
            fname = "pasted_code.py"
        target_file_path = tmp_dir_path / fname
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
            "source": source,
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

        raw_json = generate_incident_report_ai_payload(passage)
        ai_data = parse_llm_json(raw_json)
        parse_error = None
        if not ai_data:
            parse_error = (
                "The model returned empty or non-JSON output; placeholder values are shown where needed."
            )

        ctx = merge_incident_report_context(
            request=request,
            ai=ai_data,
            parse_error=parse_error,
        )
        ctx["disclaimer"] = DISCLAIMER_TEXT
        return render(request, "incident_report.html", ctx)
    except Exception as e:
        return render(
            request,
            "index.html",
            {"result": f"Analysis failed: {type(e).__name__}: {e}"},
        )
    finally:
        # Best-effort cleanup of temporary files.
        shutil.rmtree(tmp_dir_path, ignore_errors=True)

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
    if request.method != "POST":
        return redirect("dashboard")

    uploaded = request.FILES.get("file")
    code_paste = request.POST.get("code", "").strip()

    # Prefer a non-empty file upload over pasted text when both are present.
    if uploaded is not None and getattr(uploaded, "size", 0) > 0:
        try:
            code = _read_uploaded_text(uploaded)
        except ValueError as e:
            return render(request, "index.html", {"result": str(e)})
        if not code.strip():
            return render(
                request,
                "index.html",
                {"result": "Uploaded file is empty."},
            )
        source = {
            "origin": "upload",
            "filename": uploaded.name or "upload.txt",
        }
        return _run_incident_scan(request, code, source)

    if code_paste:
        return _run_incident_scan(
            request,
            code_paste,
            {"origin": "paste", "filename": "pasted_code.py"},
        )

    return render(
        request,
        "index.html",
        {"result": "No code submitted. Upload a file or paste code."},
    )
