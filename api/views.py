from django.contrib.auth.hashers import make_password, check_password
from django.shortcuts import render, redirect, get_object_or_404
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
from .models import CodeSubmission, File, Threat, CWE, User
from django.db.models import Q
from pathlib import Path
import re
import tempfile
import shutil
from .utils.prescan import run_semgrep, run_gitleaks
from django.shortcuts import render, redirect
from django.contrib.auth.hashers import check_password, make_password

# Max upload size for scan (bytes).
MAX_UPLOAD_BYTES = 2 * 1024 * 1024

def require_login(request):
    if "user_id" not in request.session:
        return redirect("login")
    return None

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

        # Create submission record early
        user_id = request.session.get("user_id")
        if not user_id:
            return render(
                request,
                "index.html",
                {"result": "You must be logged in to run a scan."},
            )

        user = User.objects.get(user_id=user_id)

        submission = CodeSubmission.objects.create(
            user=user,
            submission_name=fname,
            scan_status="Running",
        )

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
            ai_data = {}

        # Build simple incident ID
        incident_id = f"CYB-{submission.uploaded_at.year}-{submission.submission_id}"

        # If you later save a real HTML file, replace this with the actual path
        report_path = f"reports/{incident_id}.html"

        # Safely convert score
        base_score_raw = (
            ai_data.get("cvss", {}).get("base")
            if isinstance(ai_data.get("cvss"), dict)
            else None
        )

        base_score = None
        try:
            if base_score_raw not in (None, "", "N/A"):
                base_score = Decimal(str(base_score_raw))
        except Exception:
            base_score = None

        # Update dashboard/report fields
        submission.submission_name = fname
        submission.risk_level = ai_data.get("severity_level", "Informational")
        submission.scan_status = "Completed"
        submission.overall_risk_score = base_score
        submission.simplified_summary = ai_data.get(
            "status",
            "No findings evidenced"
        )
        submission.detailed_summary = ai_data.get(
            "what_happened",
            "No additional analysis details available."
        )
        submission.incident_id = incident_id
        submission.report_html_path = report_path
        submission.save()

        ctx = merge_incident_report_context(
            request=request,
            ai=ai_data,
            parse_error=parse_error,
        )
        ctx["disclaimer"] = DISCLAIMER_TEXT
        ctx["submission_id"] = submission.submission_id
        ctx["incident_id"] = incident_id

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
    if require_login(request):
        return require_login(request)

    scans = CodeSubmission.objects.filter(
        user_id=request.session["user_id"]
    ).order_by("-uploaded_at")[:10]

    return render(request, "index.html", {"scans": scans})

# -------------------
# Dummy Code Submission
# -------------------
def submit_code(request):
    if require_login(request):
            return require_login(request)
    print("HIT SUBMIT VIEW")
    result = None

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

def vulnerability_list(request):
    query = request.GET.get('q', '').strip()
    severity = request.GET.get('severity', '').strip()

    vulnerabilities = CWE.objects.all()

    # ONLY apply search if actually typed
    if query:
        vulnerabilities = vulnerabilities.filter(
            Q(name__icontains=query) |
            Q(description__icontains=query) |
            Q(cwe_id__icontains=query)
        )

    # Apply severity filter independently
    if severity:
        vulnerabilities = vulnerabilities.filter(severity=severity)

    context = {
        'vulnerabilities': vulnerabilities,
        'query': query,
        'selected_severity': severity,
    }

    return render(request, 'vulnerabilities.html', context)
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
            request.session["user_email"] = user.email
            return redirect('dashboard')

    return render(request, 'register.html', {'error': error})

def report_detail_view(request, submission_id):
    user_id = request.session.get("user_id")
    if not user_id:
        return redirect("/login/")

    submission = get_object_or_404(
        CodeSubmission,
        submission_id=submission_id,
        user_id=user_id
    )

    ai_data = submission.report_data or {}

    ctx = merge_incident_report_context(
        request=request,
        ai=ai_data,
        parse_error=None,
    )

    ctx["disclaimer"] = DISCLAIMER_TEXT
    ctx["submission"] = submission

    return render(request, "incident_report.html", ctx)