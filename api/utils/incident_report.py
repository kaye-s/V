"""
Helpers to parse LLM JSON output and merge backend-filled fields for incident reports.
"""
from __future__ import annotations

import json
import re
import uuid
from typing import Any

from django.utils import timezone


def parse_llm_json(raw: str) -> dict[str, Any]:
    """
    Parse JSON from model output. Strips optional ```json ... ``` fences.
    """
    text = (raw or "").strip()
    if not text:
        return {}

    fence = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if fence:
        text = fence.group(1).strip()

    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def _as_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return str(value)


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            s = _as_str(item).strip()
            if s:
                out.append(s)
        return out
    return []


def _normalize_cvss(ai: dict[str, Any]) -> dict[str, str]:
    raw = ai.get("cvss")
    if not isinstance(raw, dict):
        raw = {}
    return {
        "base": _as_str(raw.get("base"), "N/A"),
        "threat": _as_str(raw.get("threat"), "N/A"),
        "environmental": _as_str(raw.get("environmental"), "N/A"),
        "supplemental": _as_str(raw.get("supplemental"), "N/A"),
    }


def _normalize_response_actions(ai: dict[str, Any]) -> list[dict[str, str]]:
    rows = ai.get("response_actions")
    if not isinstance(rows, list):
        return []
    out: list[dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        action = _as_str(row.get("action")).strip()
        details = _as_str(row.get("details")).strip()
        if action or details:
            out.append({"action": action or "—", "details": details or "—"})
    return out


def merge_incident_report_context(
    *,
    request,
    ai: dict[str, Any],
    parse_error: str | None = None,
) -> dict[str, Any]:
    """
    Backend-owned fields + normalized AI fields for template rendering.
    """
    now = timezone.now()
    incident_id = f"CYB-{now.year}-{uuid.uuid4().hex[:4].upper()}"
    dt_display = now.strftime("%d %B %Y, %H:%M %Z").strip() or now.isoformat()

    user = getattr(request, "user", None)
    if user is not None and getattr(user, "is_authenticated", False):
        reported_by = user.get_username() or _as_str(getattr(user, "email", ""), "Unknown")
    else:
        reported_by = "Unknown"

    cvss = _normalize_cvss(ai)
    impact = _as_str_list(ai.get("impact"))
    response_actions = _normalize_response_actions(ai)

    return {
        "report_kicker": "Cybersecurity",
        "report_title": "Incident Report",
        "report_subtitle": "CODE SECURITY ANALYSIS",
        "incident_id": incident_id,
        "report_datetime": dt_display,
        "reported_by": reported_by,
        "severity_level": _as_str(ai.get("severity_level"), "Unknown"),
        "incident_type": _as_str(ai.get("incident_type"), "Code security review"),
        "systems_affected": _as_str(ai.get("systems_affected"), "Submitted code artifact"),
        "discovery_method": _as_str(
            ai.get("discovery_method"),
            "Automated static analysis (semgrep) and secret scanning (gitleaks)",
        ),
        "status": _as_str(ai.get("status"), "Analysis complete"),
        "cvss_base": cvss["base"],
        "cvss_threat": cvss["threat"],
        "cvss_environmental": cvss["environmental"],
        "cvss_supplemental": cvss["supplemental"],
        "what_happened": _as_str(
            ai.get("what_happened"),
            "No narrative could be generated from the model output.",
        ),
        "impact_items": impact,
        "follow_up_consequences": _as_str(ai.get("follow_up_consequences"), ""),
        "no_follow_up_consequences": _as_str(ai.get("no_follow_up_consequences"), ""),
        "response_actions": response_actions,
        "parse_error": parse_error or "",
    }


DISCLAIMER_TEXT = (
    "This report is partially generated with the assistance of automated code pre-processing "
    "and OpenAI-based report generation. It should not be treated as a substitute for manual "
    "security review, professional judgment, or formal penetration testing validation. Any "
    "findings, risk ratings, and recommendations should be independently verified before use."
)
