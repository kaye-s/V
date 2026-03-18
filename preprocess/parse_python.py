"""
Extract imports, functions, classes from Python source via ast.
On failure returns empty structure for fallback chunking.
"""

import ast
from typing import Any, Dict, List, Optional


def parse_python_structure(source: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "parse_ok": False,
        "imports": [],
        "functions": [],
        "classes": [],
        "calls": [],  # simplified: names only, from ast.Call if possible
    }
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return out
    out["parse_ok"] = True
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out["imports"].append({
                    "line": node.lineno,
                    "end_line": getattr(node, "end_lineno", node.lineno),
                    "name": alias.name,
                    "alias": alias.asname,
                })
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                out["imports"].append({
                    "line": node.lineno,
                    "end_line": getattr(node, "end_lineno", node.lineno),
                    "name": f"{mod}.{alias.name}" if mod else alias.name,
                    "alias": alias.asname,
                })
        elif isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            end = getattr(node, "end_lineno", node.lineno)
            out["functions"].append({
                "name": node.name,
                "line": node.lineno,
                "end_line": end,
            })
        elif isinstance(node, ast.ClassDef):
            end = getattr(node, "end_lineno", node.lineno)
            out["classes"].append({
                "name": node.name,
                "line": node.lineno,
                "end_line": end,
            })
        elif isinstance(node, ast.Call):
            name = _call_name(node)
            if name:
                out["calls"].append({"line": node.lineno, "name": name})
    return out


def _call_name(node: ast.Call) -> Optional[str]:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts: List[str] = []
        cur = node.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            return ".".join(reversed(parts))
    return None
