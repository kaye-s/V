"""
Orchestrates preprocessing: file or snippet -> structured JSON.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union

from preprocess.chunking import build_chunks
from preprocess.filters import should_skip_path, path_has_skip_segment
from preprocess.hashing import sha256_text
from preprocess.io_read import read_text_with_fallback, is_probably_text
from preprocess.language import detect_language
from preprocess.parse_python import parse_python_structure
from preprocess.signals import extract_signals, risk_hints_from_signals

PIPELINE_VERSION = "1.0.0"


def _file_id(project_id: str, rel_path: str, content: str) -> str:
    return sha256_text(f"{project_id}:{rel_path}:{sha256_text(content)}")


def _chunk_id(file_id: str, start: int, end: int, content: str) -> str:
    return sha256_text(f"{file_id}:{start}:{end}:{sha256_text(content)}")


def run_file(
    path: Union[str, Path],
    language_hint: Optional[str] = None,
    max_file_bytes: int = 512 * 1024,
) -> Dict[str, Any]:
    path = Path(path).resolve()
    skip, reason = should_skip_path(path, max_bytes=max_file_bytes)
    project_id = sha256_text(str(path))
    if skip:
        return {
            "pipeline_version": PIPELINE_VERSION,
            "project_id": project_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "input_type": "file",
            "input_path": str(path),
            "files": [],
            "files_skipped": [{"path": str(path), "reason": reason}],
            "chunks": [],
        }
    if path_has_skip_segment(path):
        return {
            "pipeline_version": PIPELINE_VERSION,
            "project_id": project_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "input_type": "file",
            "input_path": str(path),
            "files": [],
            "files_skipped": [{"path": str(path), "reason": "path_in_skip_dir"}],
            "chunks": [],
        }

    text, encoding, err = read_text_with_fallback(path)
    if text is None or err:
        return {
            "pipeline_version": PIPELINE_VERSION,
            "project_id": project_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "input_type": "file",
            "input_path": str(path),
            "files": [],
            "files_skipped": [{"path": str(path), "reason": err or "read_failed"}],
            "chunks": [],
        }
    if not is_probably_text(text):
        return {
            "pipeline_version": PIPELINE_VERSION,
            "project_id": project_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "input_type": "file",
            "input_path": str(path),
            "files": [],
            "files_skipped": [{"path": str(path), "reason": "not_probably_text"}],
            "chunks": [],
        }

    rel_path = path.name
    lang_info = detect_language(path, text, language_hint)
    structure: Dict[str, Any] = {}
    if lang_info["language"] == "python":
        structure = parse_python_structure(text)

    file_id = _file_id(project_id, rel_path, text)
    content_hash = sha256_text(text)

    raw_chunks = build_chunks(file_id, text, lang_info["language"], structure)
    chunks_out = []
    signals_full = extract_signals(text)
    risk_hints_file = risk_hints_from_signals(signals_full)

    for ch in raw_chunks:
        cid = _chunk_id(file_id, ch["start_line"], ch["end_line"], ch["content"])
        chunk_signals = extract_signals(ch["content"])
        chunks_out.append({
            "chunk_id": cid,
            "file_id": file_id,
            "start_line": ch["start_line"],
            "end_line": ch["end_line"],
            "type": ch["type"],
            "symbol": ch["symbol"],
            "content": ch["content"],
            "content_hash": sha256_text(ch["content"]),
            "signals": {k: v for k, v in chunk_signals.items() if v},
            "risk_hints": risk_hints_from_signals(chunk_signals),
        })

    file_record = {
        "file_id": file_id,
        "path": rel_path,
        "language": lang_info["language"],
        "language_confidence": lang_info["confidence"],
        "language_reason": lang_info["reason"],
        "encoding_used": encoding,
        "line_count": len(text.splitlines()),
        "byte_size": path.stat().st_size,
        "content_hash": content_hash,
        "parse_ok": structure.get("parse_ok", False),
        "imports": structure.get("imports", []),
        "functions": structure.get("functions", []),
        "classes": structure.get("classes", []),
        "calls_sample": structure.get("calls", [])[:50],
        "signals": {k: v for k, v in signals_full.items() if v},
        "risk_hints": risk_hints_file,
    }

    return {
        "pipeline_version": PIPELINE_VERSION,
        "project_id": project_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "input_type": "file",
        "input_path": str(path),
        "files": [file_record],
        "files_skipped": [],
        "chunks": chunks_out,
    }


def run_snippet(
    content: str,
    virtual_name: str = "snippet.py",
    language_hint: Optional[str] = None,
) -> Dict[str, Any]:
    """Treat snippet as a single virtual file."""
    path = Path(virtual_name)
    project_id = sha256_text(content[:5000] + virtual_name)
    lang_info = detect_language(path, content, language_hint)
    structure = {}
    if lang_info["language"] == "python":
        structure = parse_python_structure(content)
    file_id = _file_id(project_id, virtual_name, content)
    raw_chunks = build_chunks(file_id, content, lang_info["language"], structure)
    signals_full = extract_signals(content)
    chunks_out = []
    for ch in raw_chunks:
        cid = _chunk_id(file_id, ch["start_line"], ch["end_line"], ch["content"])
        chunk_signals = extract_signals(ch["content"])
        chunks_out.append({
            "chunk_id": cid,
            "file_id": file_id,
            "start_line": ch["start_line"],
            "end_line": ch["end_line"],
            "type": ch["type"],
            "symbol": ch["symbol"],
            "content": ch["content"],
            "content_hash": sha256_text(ch["content"]),
            "signals": {k: v for k, v in chunk_signals.items() if v},
            "risk_hints": risk_hints_from_signals(chunk_signals),
        })
    file_record = {
        "file_id": file_id,
        "path": virtual_name,
        "language": lang_info["language"],
        "language_confidence": lang_info["confidence"],
        "language_reason": lang_info["reason"],
        "encoding_used": "utf-8",
        "line_count": len(content.splitlines()),
        "byte_size": len(content.encode("utf-8")),
        "content_hash": sha256_text(content),
        "parse_ok": structure.get("parse_ok", False),
        "imports": structure.get("imports", []),
        "functions": structure.get("functions", []),
        "classes": structure.get("classes", []),
        "calls_sample": structure.get("calls", [])[:50],
        "signals": {k: v for k, v in signals_full.items() if v},
        "risk_hints": risk_hints_from_signals(signals_full),
    }
    return {
        "pipeline_version": PIPELINE_VERSION,
        "project_id": project_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "input_type": "snippet",
        "input_path": virtual_name,
        "files": [file_record],
        "files_skipped": [],
        "chunks": chunks_out,
    }


def run_file_to_json(path: Union[str, Path], out_path: Optional[str] = None) -> str:
    data = run_file(path)
    s = json.dumps(data, ensure_ascii=False, indent=2)
    if out_path:
        Path(out_path).write_text(s, encoding="utf-8")
    return s
