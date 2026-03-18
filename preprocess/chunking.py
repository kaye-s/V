"""
Build chunks: whole file, or per function/class, or line-based fallback.
"""

from typing import Any, Dict, List

MAX_LINES_WHOLE_CHUNK = 200
LINE_CHUNK_SIZE = 120
LINE_CHUNK_OVERLAP = 10


def lines_to_content(lines: List[str], start: int, end: int) -> str:
    """start/end are 1-based inclusive line numbers."""
    if start < 1:
        start = 1
    if end > len(lines):
        end = len(lines)
    return "\n".join(lines[start - 1 : end])


def build_chunks(
    file_id: str,
    content: str,
    language: str,
    structure: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Returns list of chunk dicts with chunk_id, file_id, start_line, end_line, type, symbol, content.
    chunk_id filled by caller after content_hash.
    """
    lines = content.splitlines()
    n = len(lines)
    chunks: List[Dict[str, Any]] = []

    if language == "python" and structure.get("parse_ok"):
        # Prefer function/class spans
        spans = []
        for f in structure.get("functions", []):
            spans.append(("function", f["name"], f["line"], f.get("end_line", f["line"])))
        for c in structure.get("classes", []):
            spans.append(("class", c["name"], c["line"], c.get("end_line", c["line"])))
        spans.sort(key=lambda x: x[2])
        if spans and n > MAX_LINES_WHOLE_CHUNK:
            covered = set()
            for typ, sym, start, end in spans:
                if end < start:
                    end = start
                chunk_content = lines_to_content(lines, start, end)
                if not chunk_content.strip():
                    continue
                chunks.append({
                    "file_id": file_id,
                    "start_line": start,
                    "end_line": end,
                    "type": typ,
                    "symbol": sym,
                    "content": chunk_content,
                })
                for ln in range(start, end + 1):
                    covered.add(ln)
            # Optional: add line-based for uncovered regions — keep simple: if no spans cover whole file, fallback
            if not chunks:
                pass
        if not chunks and n <= MAX_LINES_WHOLE_CHUNK:
            chunks.append({
                "file_id": file_id,
                "start_line": 1,
                "end_line": n,
                "type": "file",
                "symbol": None,
                "content": content,
            })
        elif not chunks:
            chunks.extend(_line_chunks(file_id, lines))
    else:
        if n <= MAX_LINES_WHOLE_CHUNK:
            chunks.append({
                "file_id": file_id,
                "start_line": 1,
                "end_line": n,
                "type": "file",
                "symbol": None,
                "content": content,
            })
        else:
            chunks.extend(_line_chunks(file_id, lines))

    if not chunks and content.strip():
        chunks.append({
            "file_id": file_id,
            "start_line": 1,
            "end_line": max(n, 1),
            "type": "file",
            "symbol": None,
            "content": content,
        })
    return chunks


def _line_chunks(file_id: str, lines: List[str]) -> List[Dict[str, Any]]:
    out = []
    n = len(lines)
    i = 0
    while i < n:
        start = i + 1
        end = min(i + LINE_CHUNK_SIZE, n)
        block = "\n".join(lines[i:end])
        out.append({
            "file_id": file_id,
            "start_line": start,
            "end_line": end,
            "type": "lines",
            "symbol": None,
            "content": block,
        })
        i = end - LINE_CHUNK_OVERLAP if end - LINE_CHUNK_OVERLAP > i else end
        if i >= n:
            break
    return out
