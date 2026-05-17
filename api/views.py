from decimal import Decimal
from django.contrib.auth.hashers import make_password, check_password
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from django.utils.safestring import mark_safe
from decouple import config
from rest_framework.views import APIView
from rest_framework.response import Response
from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_http_methods
from django.db.models import Case, IntegerField, Q, When
from pathlib import Path
from typing import Optional
import json
import re
import tempfile
import shutil

from .services.ai_service import ask_ai
from .services.incident_report_ai import generate_incident_report_ai_payload
from .utils.incident_report import (
    DISCLAIMER_TEXT,
    format_report_datetime_chicago,
    merge_incident_report_context,
    parse_llm_json,
)
from .utils.openai_usage import record_openai_usage_for_user
from .utils.prescan import run_semgrep, run_gitleaks

from .models import CodeSubmission, CWE, User, DepartmentJoinRequest, ReportComment, UserSetting

# Max upload size for scan (bytes).
MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MANAGER_SETUP_CODE = config("MANAGER_SETUP_CODE", default="")
DEFAULT_AI_MODEL = config("OPENAI_REPORT_MODEL", default="gpt-4.1-mini")

def require_login(request):
    if "user_id" not in request.session:
        return redirect("login")
    return None


def _get_session_user(request):
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    try:
        return User.objects.get(user_id=user_id)
    except User.DoesNotExist:
        return None


def _department_scans_queryset(user):
    return CodeSubmission.objects.filter(user__department=user.department)


def _my_reports_queryset(user):
    return CodeSubmission.objects.filter(user=user)


def _active_user_or_redirect(request):
    auth_redirect = require_login(request)
    if auth_redirect:
        return None, auth_redirect
    current_user = _get_session_user(request)
    if not current_user or current_user.account_status != User.STATUS_ACTIVE:
        request.session.flush()
        return None, redirect("login")
    return current_user, None


def _get_or_create_settings(user):
    settings, _ = UserSetting.objects.get_or_create(user=user, defaults={"ai_model": DEFAULT_AI_MODEL})
    if not settings.ai_model:
        settings.ai_model = DEFAULT_AI_MODEL
        settings.save(update_fields=["ai_model", "updated_at"])
    return settings


def _available_ai_models():
    raw = config("OPENAI_MODEL_CHOICES", default="")
    models = [item.strip() for item in raw.split(",") if item.strip()]
    if DEFAULT_AI_MODEL not in models:
        models.insert(0, DEFAULT_AI_MODEL)
    return models


# Left → right: faster / lighter vs slower / more precise (see Settings UI).
_AI_MODEL_SPEED_ORDER = ["gpt-5.4-mini", "gpt-5.4", "gpt-5.5"]


def _ai_models_spectrum():
    """Same models as env allows, ordered for the speed ↔ precision slider."""
    available = _available_ai_models()
    avail_set = set(available)
    ordered = [m for m in _AI_MODEL_SPEED_ORDER if m in avail_set]
    remainder = sorted(m for m in available if m not in ordered)
    return ordered + remainder


def _ai_slider_index(spectrum, saved_model: str) -> int:
    if not spectrum:
        return 0
    if saved_model in spectrum:
        return spectrum.index(saved_model)
    if DEFAULT_AI_MODEL in spectrum:
        return spectrum.index(DEFAULT_AI_MODEL)
    return 0


def _parse_focus_lines(request):
    start_raw = request.POST.get("focus_start_line", "").strip()
    end_raw = request.POST.get("focus_end_line", "").strip()
    if not start_raw and not end_raw:
        return None, None, None
    try:
        start = int(start_raw)
        end = int(end_raw)
    except ValueError:
        return None, None, "Line range must use numbers."
    if start < 1 or end < start:
        return None, None, "Line range must start at 1 and end after the start line."
    return start, end, None


def _user_can_update_priority(user, submission):
    return submission.user_id == user.user_id or (
        user.role == User.ROLE_MANAGER and submission.user.department == user.department
    )


def _user_can_rename_report(user, submission):
    return submission.user_id == user.user_id


def _clean_report_title(request) -> str:
    title = (request.POST.get("report_title") or "").strip()
    return title[:200]

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


def _run_incident_scan(
    request,
    code: str,
    source: dict,
    *,
    scan_input_type: str = CodeSubmission.INPUT_FILE,
    focus_start_line: Optional[int] = None,
    focus_end_line: Optional[int] = None,
    report_title: str = "",
):
    """
    Shared pipeline: write code to a temp file, pre-scan, call OpenAI JSON report, render HTML.
    source: {"origin": "upload"|"paste", "filename": str}
    """
    tmp_dir_path = Path(tempfile.mkdtemp(prefix="autopen_"))

    try:
        if source.get("origin") == "upload":
            fname = _safe_upload_basename(source.get("filename") or "upload.txt")
        elif source.get("origin") == "text":
            fname = _safe_upload_basename(source.get("filename") or "security_question.txt")
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
        user_settings = _get_or_create_settings(user)

        submission = CodeSubmission.objects.create(
            user=user,
            submission_name=fname,
            report_title=report_title[:200] if report_title else "",
            scan_status="Running",
            scan_input_type=scan_input_type,
            focus_start_line=focus_start_line,
            focus_end_line=focus_end_line,
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
        focus_code = ""
        if focus_start_line and focus_end_line:
            lines = code.splitlines()
            focus_code = "\n".join(lines[focus_start_line - 1:focus_end_line])

        # Keep tool findings compact to reduce token usage.
        semgrep_results = semgrep_report.get("results", []) or []
        gitleaks_results = gitleaks_report.get("results", []) or []
        semgrep_results = semgrep_results[:20]
        gitleaks_results = gitleaks_results[:20]

        # Assemble a single "passage" for OpenAI analysis.
        passage = {
            "source": source,
            "user_code": truncated + trunc_note,
            "focus_lines": {
                "start": focus_start_line,
                "end": focus_end_line,
                "code": focus_code,
            },
            "semgrep": {
                "error": semgrep_report.get("error"),
                "results": semgrep_results,
            },
            "gitleaks": {
                "error": gitleaks_report.get("error"),
                "results": gitleaks_results,
            },
        }

        raw_json, llm_usage = generate_incident_report_ai_payload(passage, model=user_settings.ai_model)

        record_openai_usage_for_user(user_id, llm_usage)

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
        submission.report_data = ai_data
        submission.save()

        if parse_error:
            messages.warning(request, parse_error)
        return redirect("report_detail", submission_id=submission.submission_id)

    except Exception as e:
        return render(
            request,
            "index.html",
            {"result": f"Analysis failed: {type(e).__name__}: {e}"},
        )
    finally:
        # Best-effort cleanup of temporary files.
        shutil.rmtree(tmp_dir_path, ignore_errors=True)

@require_POST
def assistant_chat_view(request):
    """JSON chat for the floating assistant (session auth)."""
    if not request.session.get("user_id"):
        return JsonResponse({"error": "Authentication required"}, status=401)
    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    user_text = (data.get("message") or "").strip()
    if not user_text:
        return JsonResponse({"error": "Message is required"}, status=400)
    try:
        user = User.objects.get(user_id=request.session["user_id"])
        user_settings = _get_or_create_settings(user)
        model = user_settings.ai_model or None
        reply, usage = ask_ai(user_text, model=model)
        record_openai_usage_for_user(request.session.get("user_id"), usage)
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=502)
    return JsonResponse({"reply": reply or ""})


class SubmissionStatusView(APIView):

    def get(self, request, submission_id):
        current_user = _get_session_user(request)
        if not current_user:
            return Response({"error": "Authentication required"}, status=401)

        try:
            submission = CodeSubmission.objects.get(
                submission_id=submission_id,
                user__department=current_user.department,
            )
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
                    if user.account_status == User.STATUS_PENDING:
                        error = "Account is pending manager approval."
                        return render(request, 'login.html', {'error': error})
                    if user.account_status == User.STATUS_REJECTED:
                        error = "Account request was rejected. Contact your manager."
                        return render(request, 'login.html', {'error': error})
                    request.session["user_id"] = user.user_id
                    request.session["user_email"] = user.email
                    request.session["user_name"] = user.full_name
                    request.session["department"] = user.department
                    request.session["user_role"] = user.role
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
    current_user, auth_redirect = _active_user_or_redirect(request)
    if auth_redirect:
        return auth_redirect

    department_scans = _department_scans_queryset(current_user)
    scans = department_scans.select_related("user").order_by("-uploaded_at")[:5]
    urgent_count = department_scans.filter(priority=CodeSubmission.PRIORITY_URGENT).count()
    my_count = department_scans.filter(user=current_user).count()

    return render(
        request,
        "index.html",
        {
            "scans": scans,
            "total_scans": department_scans.count(),
            "urgent_count": urgent_count,
            "my_count": my_count,
        },
    )

# -------------------
# Dummy Code Submission
# -------------------
def submit_code(request):
    current_user, auth_redirect = _active_user_or_redirect(request)
    if auth_redirect:
        return auth_redirect

    if request.method != "POST":
        return redirect("dashboard")

    uploaded = request.FILES.get("file")
    code_paste = request.POST.get("code", "").strip()
    report_title = _clean_report_title(request)
    focus_start, focus_end, line_error = _parse_focus_lines(request)
    if line_error:
        return render(request, "scan.html", {"result": line_error})

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
        return _run_incident_scan(
            request,
            code,
            source,
            scan_input_type=CodeSubmission.INPUT_FILE,
            focus_start_line=focus_start,
            focus_end_line=focus_end,
            report_title=report_title,
        )

    if code_paste:
        return _run_incident_scan(
            request,
            code_paste,
            {"origin": "paste", "filename": "pasted_code.py"},
            scan_input_type=CodeSubmission.INPUT_PASTE,
            focus_start_line=focus_start,
            focus_end_line=focus_end,
            report_title=report_title,
        )

    return render(
        request,
        "scan.html",
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


def start_scan_view(request):
    current_user, auth_redirect = _active_user_or_redirect(request)
    if auth_redirect:
        return auth_redirect
    if request.method == "POST":
        return submit_code(request)
    return render(request, "scan.html")


def reports_view(request):
    current_user, auth_redirect = _active_user_or_redirect(request)
    if auth_redirect:
        return auth_redirect

    if request.method == "POST":
        submission = get_object_or_404(
            CodeSubmission,
            submission_id=request.POST.get("submission_id"),
            user=current_user,
        )
        action = request.POST.get("action")
        if action == "priority":
            priority = request.POST.get("priority")
            valid_priorities = {value for value, _ in CodeSubmission.PRIORITY_CHOICES}
            if priority in valid_priorities and _user_can_update_priority(current_user, submission):
                submission.priority = priority
                submission.priority_updated_by = current_user
                submission.priority_updated_at = timezone.now()
                submission.save(update_fields=["priority", "priority_updated_by", "priority_updated_at"])
        elif action == "comment":
            comment = request.POST.get("comment", "").strip()
            if comment:
                ReportComment.objects.create(submission=submission, user=current_user, comment=comment)
        elif action == "rename":
            if _user_can_rename_report(current_user, submission):
                submission.report_title = _clean_report_title(request)
                submission.save(update_fields=["report_title"])
        return redirect("reports")

    reports = (
        _my_reports_queryset(current_user)
        .select_related("user", "priority_updated_by")
        .prefetch_related("comments__user")
        .order_by("-uploaded_at")
    )
    return render(
        request,
        "reports.html",
        {
            "reports": reports,
            "priority_choices": CodeSubmission.PRIORITY_CHOICES,
            "current_user": current_user,
        },
    )


def targets_view(request):
    current_user, auth_redirect = _active_user_or_redirect(request)
    if auth_redirect:
        return auth_redirect

    if request.method == "POST":
        submission = get_object_or_404(
            CodeSubmission,
            submission_id=request.POST.get("submission_id"),
            user__department=current_user.department,
        )
        action = request.POST.get("action")
        if action == "priority":
            priority = request.POST.get("priority")
            valid_priorities = {value for value, _ in CodeSubmission.PRIORITY_CHOICES}
            if priority in valid_priorities and _user_can_update_priority(current_user, submission):
                submission.priority = priority
                submission.priority_updated_by = current_user
                submission.priority_updated_at = timezone.now()
                submission.save(update_fields=["priority", "priority_updated_by", "priority_updated_at"])
        elif action == "comment":
            comment = request.POST.get("comment", "").strip()
            if comment:
                ReportComment.objects.create(submission=submission, user=current_user, comment=comment)
        return redirect("targets")

    priority_rank = Case(
        When(priority=CodeSubmission.PRIORITY_URGENT, then=0),
        When(priority=CodeSubmission.PRIORITY_MEDIUM, then=1),
        When(priority=CodeSubmission.PRIORITY_LOW, then=2),
        default=99,
        output_field=IntegerField(),
    )
    reports = (
        _department_scans_queryset(current_user)
        .select_related("user", "priority_updated_by")
        .prefetch_related("comments__user")
        .annotate(priority_rank=priority_rank)
        .order_by("priority_rank", "-uploaded_at")
    )
    return render(
        request,
        "targets.html",
        {
            "reports": reports,
            "priority_choices": CodeSubmission.PRIORITY_CHOICES,
            "current_user": current_user,
        },
    )


def settings_view(request):
    current_user, auth_redirect = _active_user_or_redirect(request)
    if auth_redirect:
        return auth_redirect

    settings = _get_or_create_settings(current_user)
    if request.method == "POST":
        theme = request.POST.get("theme", "").strip()
        ai_model = request.POST.get("ai_model", "").strip()
        valid_themes = {value for value, _ in UserSetting.THEME_CHOICES}
        if theme in valid_themes:
            settings.theme = theme
        if ai_model in _available_ai_models():
            settings.ai_model = ai_model
        settings.save()
        messages.success(request, "Settings saved.")
        return redirect("settings")

    spectrum = _ai_models_spectrum()
    slider_index = _ai_slider_index(spectrum, settings.ai_model or "")
    slider_max = max(len(spectrum) - 1, 0)

    return render(
        request,
        "settings.html",
        {
            "settings": settings,
            "theme_choices": UserSetting.THEME_CHOICES,
            "ai_models_spectrum": spectrum,
            "ai_models_spectrum_json": mark_safe(json.dumps(spectrum)),
            "ai_slider_index": slider_index,
            "ai_slider_max": slider_max,
        },
    )


def personal_info_view(request):
    """Display name, password change, and accumulated OpenAI token usage."""
    current_user, auth_redirect = _active_user_or_redirect(request)
    if auth_redirect:
        return auth_redirect

    if request.method == "POST":
        action = request.POST.get("action", "").strip()
        if action == "profile":
            full_name = request.POST.get("full_name", "").strip()
            if not full_name:
                messages.error(request, "Display name cannot be empty.")
            elif len(full_name) > 120:
                messages.error(request, "Display name is too long (max 120 characters).")
            else:
                current_user.full_name = full_name
                current_user.save(update_fields=["full_name"])
                request.session["user_name"] = full_name
                messages.success(request, "Display name updated.")
            return redirect("personal_info")
        if action == "password":
            current_pw = request.POST.get("current_password", "")
            new_pw = request.POST.get("new_password", "")
            confirm_pw = request.POST.get("confirm_password", "")
            if not check_password(current_pw, current_user.password_hash):
                messages.error(request, "Current password is incorrect.")
            elif len(new_pw) < 8:
                messages.error(request, "New password must be at least 8 characters.")
            elif new_pw != confirm_pw:
                messages.error(request, "New password and confirmation do not match.")
            else:
                current_user.password_hash = make_password(new_pw)
                current_user.save(update_fields=["password_hash"])
                messages.success(request, "Password changed.")
            return redirect("personal_info")
        return redirect("personal_info")

    db_user = User.objects.get(user_id=current_user.user_id)
    p = int(db_user.total_llm_prompt_tokens or 0)
    c = int(db_user.total_llm_completion_tokens or 0)
    return render(
        request,
        "personal_info.html",
        {
            "profile_user": db_user,
            "llm_prompt_tokens": p,
            "llm_completion_tokens": c,
            "llm_total_tokens": p + c,
        },
    )


# -----------------
# User Registration
# -----------------
def register_view(request):
    error = None
    department_choices = User.DEPARTMENT_CHOICES

    if request.method == "POST":
        full_name = request.POST.get("full_name", "").strip()
        email = request.POST.get("email")
        password = request.POST.get("password")
        department = request.POST.get("department", "").strip()
        manager_code = request.POST.get("manager_code", "").strip()
        valid_departments = {value for value, _ in User.DEPARTMENT_CHOICES}

        if not full_name or not email or not password or not department:
            error = "Please fill in name, email, password, and department."
        elif department not in valid_departments:
            error = "Invalid department selected."

        elif User.objects.filter(email=email).exists():
            error = "Email Already in Use"

        else:
            hashed_pass = make_password(password)
            is_manager = bool(MANAGER_SETUP_CODE) and manager_code == MANAGER_SETUP_CODE
            user = User.objects.create(
                full_name=full_name,
                email=email,
                password_hash=hashed_pass,
                department=department,
                role=User.ROLE_MANAGER if is_manager else User.ROLE_MEMBER,
                account_status=User.STATUS_ACTIVE if is_manager else User.STATUS_PENDING,
            )
            if not is_manager:
                DepartmentJoinRequest.objects.create(
                    user=user,
                    requested_department=department,
                    status=DepartmentJoinRequest.STATUS_PENDING,
                )
                return render(
                    request,
                    'register.html',
                    {
                        'error': None,
                        'success': "Account created. Waiting for department manager approval.",
                        'department_choices': department_choices,
                    },
                )
            request.session["user_id"] = user.user_id
            request.session["user_email"] = user.email
            request.session["user_name"] = user.full_name
            request.session["department"] = user.department
            request.session["user_role"] = user.role
            return redirect('dashboard')

    return render(request, 'register.html', {'error': error, 'department_choices': department_choices})

@require_http_methods(["GET", "HEAD"])
def report_detail_view(request, submission_id):
    current_user = _get_session_user(request)
    if not current_user:
        return redirect("/login/")

    submission = get_object_or_404(
        CodeSubmission.objects.select_related("user"),
        submission_id=submission_id,
        user__department=current_user.department
    )

    ai_data = submission.report_data or {}

    ctx = merge_incident_report_context(
        request=request,
        ai=ai_data,
        parse_error=None,
    )

    submitter = submission.user
    ctx["reported_by"] = (submitter.full_name or "").strip() or submitter.email or "Unknown"
    ctx["report_datetime"] = format_report_datetime_chicago(submission.uploaded_at)
    if submission.incident_id:
        ctx["incident_id"] = submission.incident_id

    ctx["disclaimer"] = DISCLAIMER_TEXT
    ctx["submission"] = submission

    return render(request, "incident_report.html", ctx)


def approval_queue_view(request):
    current_user = _get_session_user(request)
    if not current_user:
        return redirect("login")
    if current_user.role != User.ROLE_MANAGER:
        return redirect("dashboard")

    if request.method == "POST":
        request_id = request.POST.get("request_id")
        action = request.POST.get("action")
        join_req = get_object_or_404(
            DepartmentJoinRequest,
            request_id=request_id,
            requested_department=current_user.department,
            status=DepartmentJoinRequest.STATUS_PENDING,
        )
        if action == "approve":
            join_req.status = DepartmentJoinRequest.STATUS_APPROVED
            join_req.reviewed_by = current_user
            join_req.reviewed_at = timezone.now()
            join_req.save()
            join_req.user.account_status = User.STATUS_ACTIVE
            join_req.user.department = join_req.requested_department
            join_req.user.save()
        elif action == "reject":
            join_req.status = DepartmentJoinRequest.STATUS_REJECTED
            join_req.reviewed_by = current_user
            join_req.reviewed_at = timezone.now()
            join_req.save()
            join_req.user.account_status = User.STATUS_REJECTED
            join_req.user.save()
        return redirect("approval_queue")

    pending_requests = DepartmentJoinRequest.objects.filter(
        requested_department=current_user.department,
        status=DepartmentJoinRequest.STATUS_PENDING,
    ).select_related("user").order_by("-created_at")
    return render(
        request,
        "approval_queue.html",
        {
            "pending_requests": pending_requests,
            "department_label": current_user.get_department_display(),
        },
    )