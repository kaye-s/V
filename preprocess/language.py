"""
Language detection: extension first, then shebang/keywords/patterns.
"""

import re
from pathlib import Path
from typing import Dict, Optional

EXT_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".sql": "sql",
    ".sh": "shell",
    ".bash": "shell",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".html": "html",
    ".css": "css",
}

SHEBANG_PATTERN = re.compile(r"^#!\s*/usr/bin/env\s+(\w+)|^#!\s*/.*\b(python|node|ruby)\b", re.MULTILINE)

KEYWORD_HINTS = [
    (r"\bdef\s+\w+\s*\(", "python"),
    (r"\bimport\s+\w+", "python"),
    (r"\bfrom\s+\w+\s+import\b", "python"),
    (r"\bfunction\s+\w+\s*\(", "javascript"),
    (r"\bconst\s+\w+\s*=\s*\(", "javascript"),
    (r"\brequire\s*\(", "javascript"),
    (r"\bpublic\s+class\s+\w+", "java"),
    (r"\bpackage\s+main\b", "go"),
    (r"\bfn\s+main\s*\(", "rust"),
]


def detect_language(path: Optional[Path], content: str, hint: Optional[str] = None) -> Dict:
    """
    Returns { "language", "confidence": high|medium|low|unknown, "reason": str }.
    """
    reasons = []
    lang_from_ext = None
    if path and path.suffix:
        lang_from_ext = EXT_TO_LANGUAGE.get(path.suffix.lower())
        if lang_from_ext:
            reasons.append(f"extension:{path.suffix}")

    if hint:
        h = hint.strip().lower()
        if h in ("py", "python"):
            lang_from_ext = lang_from_ext or "python"
            reasons.append("hint:python")
        elif h in ("js", "javascript"):
            lang_from_ext = lang_from_ext or "javascript"
            reasons.append("hint:javascript")

    lang_from_content = None
    first_lines = "\n".join(content.splitlines()[:30])
    m = SHEBANG_PATTERN.search(first_lines)
    if m:
        g = (m.group(1) or m.group(2) or "").lower()
        if "python" in g:
            lang_from_content = "python"
        elif "node" in g:
            lang_from_content = "javascript"
        elif "ruby" in g:
            lang_from_content = "ruby"
        if lang_from_content:
            reasons.append("shebang")

    if not lang_from_content:
        for pattern, lang in KEYWORD_HINTS:
            if re.search(pattern, first_lines):
                lang_from_content = lang
                reasons.append(f"keyword:{pattern[:20]}")
                break

    if lang_from_ext and lang_from_content:
        if lang_from_ext == lang_from_content:
            return {"language": lang_from_ext, "confidence": "high", "reason": ";".join(reasons)}
        return {
            "language": lang_from_ext,
            "confidence": "medium",
            "reason": f"extension_vs_content_conflict;{';'.join(reasons)}",
        }
    if lang_from_ext:
        return {"language": lang_from_ext, "confidence": "medium", "reason": ";".join(reasons)}
    if lang_from_content:
        return {"language": lang_from_content, "confidence": "medium", "reason": ";".join(reasons)}
    if path and path.suffix:
        return {"language": "unknown", "confidence": "low", "reason": f"unknown_ext:{path.suffix}"}
    return {"language": "unknown", "confidence": "unknown", "reason": "no_extension_no_keywords"}
