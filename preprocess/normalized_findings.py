"""
Normalize preprocess signals into structured findings for AI / report stage.
No human layer: finding_status is review_needed; confidence reflects heuristic only.
"""

from typing import Any, Dict, List, Optional

# Signal bucket key (as in file_record["signals"]) -> default issue template
# category inside each item is the regex category e.g. broad_except, debug_output
SIGNAL_BUCKET_META = {
    "error_handling": {
        "issue_type": "broad_exception_handling",
        "title": "Broad Exception Handling",
        "affected_component": ["backend", "error_handling"],
        "confidence": "medium",
        "severity": "low",
        "remediation_keywords": [
            "catch specific exceptions",
            "structured logging",
            "safer exception handling",
        ],
        "possible_impact": [
            "reduced error observability",
            "generic failure handling may hide root causes",
        ],
    },
    "debug_output": {
        "issue_type": "potential_sensitive_data_exposure_via_debug_output",
        "title": "Potential Sensitive Data Exposure via Debug Output",
        "affected_component": ["backend", "logging"],
        "confidence": "medium",
        "severity": "medium",
        "remediation_keywords": [
            "remove debug prints",
            "sanitize logs",
            "avoid dumping full query results",
        ],
        "possible_impact": [
            "internal data may appear in console or logs",
            "debug output could leak in production",
        ],
        "analysis_limitations": [
            "Cannot determine if printed data contains sensitive fields without data flow analysis.",
        ],
    },
    "sql_execution": {
        "issue_type": "sql_execution_review",
        "title": "SQL Execution Present — Review for Injection / Unsafe Queries",
        "affected_component": ["backend", "database"],
        "confidence": "medium",
        "severity": "medium",
        "remediation_keywords": [
            "parameterized queries",
            "prepared statements",
            "avoid string concatenation in SQL",
        ],
        "possible_impact": [
            "SQL injection if input is concatenated into queries",
            "unsafe query patterns",
        ],
    },
    "command_execution": {
        "issue_type": "command_execution_surface",
        "title": "Command Execution or Dynamic Evaluation",
        "affected_component": ["backend", "process"],
        "confidence": "high",
        "severity": "high",
        "remediation_keywords": [
            "avoid eval/exec",
            "sanitize subprocess arguments",
            "use allowlists for shell commands",
        ],
        "possible_impact": [
            "command injection",
            "arbitrary code execution",
        ],
    },
    "file_access": {
        "issue_type": "file_io_review",
        "title": "File Access — Review Path Handling",
        "affected_component": ["backend", "filesystem"],
        "confidence": "low",
        "severity": "low",
        "remediation_keywords": [
            "validate paths",
            "avoid path traversal",
        ],
        "possible_impact": [
            "path traversal if paths are user-controlled",
        ],
    },
    "user_input_sources": {
        "issue_type": "user_input_flow",
        "title": "User-Controlled Input Source",
        "affected_component": ["backend", "input"],
        "confidence": "medium",
        "severity": "medium",
        "remediation_keywords": [
            "validate and sanitize input",
            "use safe APIs",
        ],
        "possible_impact": [
            "injection or logic flaws if input reaches sensitive sinks",
        ],
    },
    "possible_hardcoded_secrets": {
        "issue_type": "possible_hardcoded_secret",
        "title": "Possible Hardcoded Secret",
        "affected_component": ["backend", "secrets"],
        "confidence": "low",
        "severity": "high",
        "remediation_keywords": [
            "use environment variables or secret manager",
            "rotate credentials",
        ],
        "possible_impact": [
            "credential leak if committed or logged",
        ],
        "analysis_limitations": [
            "May be test data or placeholders; verify context.",
        ],
    },
    "auth_related_keywords": {
        "issue_type": "auth_surface_keyword",
        "title": "Auth-Related Keyword Present",
        "affected_component": ["backend", "auth"],
        "confidence": "low",
        "severity": "low",
        "remediation_keywords": [
            "review auth flow",
            "session handling",
        ],
        "possible_impact": [
            "auth logic may need manual review",
        ],
    },
    "database_access": {
        "issue_type": "database_access_heuristic",
        "title": "Database Access Pattern Detected",
        "affected_component": ["backend", "database"],
        "confidence": "low",
        "severity": "low",
        "remediation_keywords": [
            "least privilege",
            "connection pooling security",
        ],
        "possible_impact": [
            "review how connections and queries are used",
        ],
        "analysis_limitations": [
            "Heuristic only; line may be 0 when matched on whole file.",
        ],
    },
    "crypto_usage": {
        "issue_type": "crypto_usage_review",
        "title": "Cryptographic API Usage",
        "affected_component": ["backend", "crypto"],
        "confidence": "low",
        "severity": "medium",
        "remediation_keywords": [
            "use vetted libraries",
            "avoid weak algorithms",
        ],
        "possible_impact": [
            "misuse may weaken security",
        ],
    },
}


def _evidence_from_signal_item(signal_key: str, index: int, item: Dict[str, Any]) -> Dict[str, Any]:
    line = item.get("line", 0)
    category = item.get("category", signal_key)
    text = item.get("match", "")
    if len(text) > 500:
        text = text[:500] + "..."
    return {
        "line": line,
        "signal": signal_key,
        "category": category,
        "text": text,
    }


def _refs_for_bucket(signal_key: str, indices: List[int]) -> List[str]:
    return [f"signals.{signal_key}[{i}]" for i in indices]


def normalize_file_findings(
    file_record: Dict[str, Any],
    file_index: int = 0,
    starting_f_index: int = 1,
) -> List[Dict[str, Any]]:
    """
    Build normalized_findings from a single preprocess file_record.
    One finding per signal bucket that has entries (evidence = all items in bucket).
    """
    signals = file_record.get("signals") or {}
    path = file_record.get("path", f"file_{file_index}")
    findings: List[Dict[str, Any]] = []
    f_num = starting_f_index

    for signal_key, items in signals.items():
        if not items:
            continue
        meta = SIGNAL_BUCKET_META.get(signal_key)
        if not meta:
            # Unknown bucket: generic finding
            meta = {
                "issue_type": f"heuristic_{signal_key}",
                "title": f"Signal: {signal_key}",
                "affected_component": ["backend"],
                "confidence": "low",
                "severity": "low",
                "remediation_keywords": ["manual review"],
                "possible_impact": ["pattern matched; context unknown"],
            }
        evidence = []
        refs = []
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            evidence.append(_evidence_from_signal_item(signal_key, i, item))
            refs.append(f"signals.{signal_key}[{i}]")

        if not evidence:
            continue

        finding = {
            "finding_id": f"F-{f_num:03d}",
            "issue_type": meta["issue_type"],
            "title": meta["title"],
            "affected_component": list(meta["affected_component"]),
            "confidence": meta["confidence"],
            "severity": meta["severity"],
            "finding_status": "review_needed",
            "verification_method": "automated_heuristic",
            "source_file": path,
            "file_id": file_record.get("file_id"),
            "possible_impact": list(meta.get("possible_impact", [])),
            "evidence": evidence,
            "remediation_keywords": list(meta.get("remediation_keywords", [])),
            "source_signal_refs": refs,
        }
        if meta.get("analysis_limitations"):
            finding["analysis_limitations"] = list(meta["analysis_limitations"])
        findings.append(finding)
        f_num += 1

    return findings


def normalize_preprocess_output(preprocess_output: Dict[str, Any]) -> Dict[str, Any]:
    """
    Attach normalized_findings to full preprocess pipeline output.
    """
    all_findings: List[Dict[str, Any]] = []
    f_num = 1
    for idx, file_record in enumerate(preprocess_output.get("files") or []):
        batch = normalize_file_findings(file_record, file_index=idx, starting_f_index=f_num)
        all_findings.extend(batch)
        f_num += len(batch)

    return {
        "pipeline_version": preprocess_output.get("pipeline_version"),
        "project_id": preprocess_output.get("project_id"),
        "created_at": preprocess_output.get("created_at"),
        "input_type": preprocess_output.get("input_type"),
        "input_path": preprocess_output.get("input_path"),
        "normalized_findings": all_findings,
        "normalized_findings_meta": {
            "count": len(all_findings),
            "generator": "preprocess.normalized_findings",
            "note": "All findings are heuristic; finding_status is review_needed unless overridden downstream.",
        },
    }


def slim_finding_for_ai(
    finding: Dict[str, Any],
    max_evidence_snippet: int = 120,
    include_remediation: bool = False,
) -> Dict[str, Any]:
    """
    Shrink one finding for LLM context: drop long text, optional remediation lists.
    """
    out = {
        "finding_id": finding.get("finding_id"),
        "issue_type": finding.get("issue_type"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "confidence": finding.get("confidence"),
        "finding_status": finding.get("finding_status"),
        "source_file": finding.get("source_file"),
    }
    slim_evidence = []
    for ev in finding.get("evidence") or []:
        text = ev.get("text") or ""
        if len(text) > max_evidence_snippet:
            text = text[:max_evidence_snippet].rstrip() + "..."
        slim_evidence.append({
            "line": ev.get("line"),
            "category": ev.get("category"),
            "snippet": text if text else None,
        })
    out["evidence"] = slim_evidence
    if include_remediation and finding.get("remediation_keywords"):
        out["remediation_keywords"] = finding.get("remediation_keywords")
    if finding.get("analysis_limitations"):
        # Keep one line each to save tokens
        out["analysis_limitations"] = [
            (s[:150] + "...") if len(s) > 150 else s
            for s in finding.get("analysis_limitations", [])[:2]
        ]
    return out


def export_ai_payload(
    preprocess_output: Dict[str, Any],
    max_evidence_snippet: int = 120,
) -> Dict[str, Any]:
    """
    Compact payload for AI only — no chunk content, no raw signals.
    Preprocess full JSON stays separate (long); this is short for token budget.
    """
    normalized = normalize_preprocess_output(preprocess_output)
    slim_findings = [
        slim_finding_for_ai(f, max_evidence_snippet=max_evidence_snippet)
        for f in normalized.get("normalized_findings") or []
    ]
    return {
        "schema": "ai_payload_v1",
        "project_id": preprocess_output.get("project_id"),
        "input_path": preprocess_output.get("input_path"),
        "input_type": preprocess_output.get("input_type"),
        "pipeline_version": preprocess_output.get("pipeline_version"),
        "normalized_findings": slim_findings,
        "meta": {
            "finding_count": len(slim_findings),
            "note": "Full source lives in preprocess output only; fetch by file_id/chunk_id if needed.",
        },
    }


def run_file_ai_payload(path: str, max_evidence_snippet: int = 120) -> Dict[str, Any]:
    """Preprocess then return only slim AI payload (no chunks, no duplicate signals)."""
    from preprocess.pipeline import run_file

    pre = run_file(path)
    if not pre.get("files"):
        return {
            "schema": "ai_payload_v1",
            "project_id": pre.get("project_id"),
            "input_path": pre.get("input_path"),
            "normalized_findings": [],
            "meta": {"finding_count": 0, "reason": "no files processed"},
        }
    return export_ai_payload(pre, max_evidence_snippet=max_evidence_snippet)


def run_file_with_findings(path: str) -> Dict[str, Any]:
    """Convenience: preprocess file then normalize (single import for CLI)."""
    from preprocess.pipeline import run_file

    pre = run_file(path)
    if not pre.get("files"):
        return {
            **pre,
            "normalized_findings": [],
            "normalized_findings_meta": {"count": 0, "reason": "no files processed"},
        }
    normalized = normalize_preprocess_output(pre)
    # Merge: keep full preprocess payload + normalized_findings at top level for AI
    out = dict(pre)
    out["normalized_findings"] = normalized["normalized_findings"]
    out["normalized_findings_meta"] = normalized["normalized_findings_meta"]
    return out
