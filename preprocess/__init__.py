"""
Backend preprocessing pipeline for secure code review.
Produces structured JSON (project/file/chunk) without frontend.
"""

from preprocess.pipeline import run_file, run_snippet, PIPELINE_VERSION
from preprocess.normalized_findings import (
    normalize_preprocess_output,
    normalize_file_findings,
    run_file_with_findings,
    export_ai_payload,
    run_file_ai_payload,
    slim_finding_for_ai,
)

__all__ = [
    "run_file",
    "run_snippet",
    "PIPELINE_VERSION",
    "normalize_preprocess_output",
    "normalize_file_findings",
    "run_file_with_findings",
    "export_ai_payload",
    "run_file_ai_payload",
    "slim_finding_for_ai",
]
