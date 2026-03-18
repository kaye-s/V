"""
Regex-based security signals and risk_hints from source text.
"""

import re
from typing import Dict, List, Set

# Patterns -> signal category
PATTERNS = [
    (r"\bsubprocess\.(run|Popen|call)\b", "command_execution"),
    (r"\bos\.system\s*\(", "command_execution"),
    (r"\bexec\s*\(", "command_execution"),
    (r"\beval\s*\(", "command_execution"),
    (r"\.execute\s*\(\s*[\"']", "sql_execution"),
    (r"\bcursor\.execute\s*\(", "sql_execution"),
    (r"\btext\s*\(\s*[\"'].*SELECT|INSERT|UPDATE|DELETE", "sql_execution"),
    (r"\bopen\s*\(", "file_access"),
    (r"\bPath\s*\([^)]*\)\.(read|write)", "file_access"),
    (r"\binput\s*\(", "user_input_source"),
    (r"\brequest\.(args|form|json|get)\b", "user_input_source"),
    (r"\bargv\b|\bsys\.argv\b", "user_input_source"),
    (r"\bhashlib\.|bcrypt\.|crypto\.|jwt\.|openssl\b", "crypto_usage"),
    (r"\bprint\s*\(", "debug_output"),
    (r"\bconsole\.log\s*\(", "debug_output"),
    (r"\bexcept\s+Exception\b|\bexcept\s*:", "broad_except"),
    (r"(?i)(password|secret|api_key|apikey|token)\s*=\s*['\"][^'\"]{8,}", "possible_hardcoded_secret"),
    (r"(?i)\b(auth|login|session|oauth|bearer)\b", "auth_keyword"),
]


def extract_signals(content: str) -> Dict[str, List[Dict]]:
    """
    Returns dict with keys: imports (from regex), function_calls, user_input_sources,
    database_access, sql_execution, command_execution, file_access, crypto_usage,
    debug_output, error_handling, possible_hardcoded_secrets, auth_related_keywords.
    Each value is a list of { "line", "match", "category" }.
    """
    lines = content.splitlines()
    by_category: Dict[str, List[Dict]] = {
        "imports": [],
        "function_calls": [],
        "user_input_sources": [],
        "database_access": [],
        "sql_execution": [],
        "command_execution": [],
        "file_access": [],
        "crypto_usage": [],
        "debug_output": [],
        "error_handling": [],
        "possible_hardcoded_secrets": [],
        "auth_related_keywords": [],
    }
    category_map = {
        "command_execution": "command_execution",
        "sql_execution": "sql_execution",
        "file_access": "file_access",
        "user_input_source": "user_input_sources",
        "crypto_usage": "crypto_usage",
        "debug_output": "debug_output",
        "broad_except": "error_handling",
        "possible_hardcoded_secret": "possible_hardcoded_secrets",
        "auth_keyword": "auth_related_keywords",
    }
    for i, line in enumerate(lines, start=1):
        for pattern, cat in PATTERNS:
            if re.search(pattern, line):
                key = category_map.get(cat, cat)
                if key not in by_category:
                    by_category[key] = []
                by_category[key].append({"line": i, "match": line.strip()[:200], "category": cat})
    # DB access heuristic
    if re.search(r"\bengine\.connect\b|\bconnection\b|\bdatabase\b", content, re.I):
        by_category["database_access"].append({"line": 0, "match": "heuristic", "category": "database_access"})
    return by_category


def risk_hints_from_signals(signals: Dict[str, List]) -> List[str]:
    hints: Set[str] = set()
    if signals.get("sql_execution"):
        hints.add("sql_execution_present")
    if signals.get("command_execution"):
        hints.add("command_execution_present")
    if signals.get("possible_hardcoded_secrets"):
        hints.add("possible_hardcoded_secret")
    if signals.get("user_input_sources"):
        hints.add("user_input_flow")
    if signals.get("file_access"):
        hints.add("file_io")
    if signals.get("broad_except") or signals.get("error_handling"):
        hints.add("error_handling_review")
    if signals.get("auth_related_keywords"):
        hints.add("auth_surface")
    return sorted(hints)
