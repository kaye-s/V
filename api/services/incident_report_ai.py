"""
OpenAI call for structured incident report JSON (template is rendered server-side).
"""
from __future__ import annotations

import json
from typing import Any

from openai import OpenAI
from decouple import config

client = OpenAI(api_key=config("OPENAI_API_KEY"))

# System message: enforce JSON-only output for downstream parsing.
_SYSTEM = (
    "You are a senior cybersecurity analyst. "
    "You must respond with a single valid JSON object only (no markdown, no prose outside JSON). "
    "Base every field strictly on the provided passage (user code + tool outputs). "
    "If information is missing, use concise placeholders like \"N/A\" or \"Not evidenced in scan data\". "
    "Do not fabricate CVEs, exploits, or incidents not supported by the passage."
)


def build_incident_report_user_prompt(passage: dict[str, Any]) -> str:
    passage_json = json.dumps(passage, ensure_ascii=False, indent=2)
    schema = """
Return a JSON object with exactly these keys (all string values unless noted):

- severity_level: short label (e.g. "Low", "Medium", "High", "Critical", or "Informational")
- incident_type: short type based on findings (e.g. "Secret exposure", "Injection risk", "Misconfiguration")
- systems_affected: what is at risk in plain language (the analyzed code context)
- discovery_method: how issues were found (mention semgrep/gitleaks only if present in passage)
- status: short status string suitable for an executive summary table
- cvss: object with keys base, threat, environmental, supplemental — each a string score "0.0"-"10.0" or "N/A"
- what_happened: 2-5 sentences describing the situation for a non-technical reader
- impact: array of strings; each item one concrete impact statement
- follow_up_consequences: 2-4 sentences on consequences if the organization follows up on recommendations
- no_follow_up_consequences: 2-4 sentences on consequences if recommendations are not followed
- response_actions: array of objects { "action": string, "details": string } with 4-8 practical remediation steps

Also incorporate this analytical requirement into the narrative fields (what_happened, impact, follow_up_consequences, no_follow_up_consequences):
Analyze this passage and tell me the consequences of following up and not following up.

Passage (JSON):
"""
    return schema.strip() + "\n" + passage_json


def generate_incident_report_ai_payload(
    passage: dict[str, Any], model: str | None = None
) -> tuple[str, Any]:
    """
    Calls the chat completion API and returns (message content, usage or None).
    """
    user_prompt = build_incident_report_user_prompt(passage)
    kwargs: dict[str, Any] = {
        "model": model or config("OPENAI_REPORT_MODEL", default="gpt-4.1-mini"),
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {"type": "json_object"},
    }
    try:
        resp = client.chat.completions.create(**kwargs)
    except Exception:
        # Some deployments/models may reject response_format; retry without it.
        kwargs.pop("response_format", None)
        resp = client.chat.completions.create(**kwargs)

    content = (resp.choices[0].message.content or "").strip()
    usage = getattr(resp, "usage", None)
    return content, usage
