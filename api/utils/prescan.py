#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def run_semgrep(target_path: str) -> dict:
   
    path = Path(target_path).resolve()
    if not path.exists():
        return {"tool": "semgrep", "error": f"path not found: {target_path}", "results": []}
    try:
        cmd = [
            sys.executable, "-m", "semgrep", "scan",
            "--config", "auto",
            "--json",
            "--quiet",
            str(path),
        ]
        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            cwd=os.getcwd(),
        )
        if out.returncode != 0 and not out.stdout.strip():
            return {
                "tool": "semgrep",
                "error": out.stderr.strip() or f"exit code {out.returncode}",
                "results": [],
            }
        data = json.loads(out.stdout) if out.stdout.strip() else {}
        return {"tool": "semgrep", "error": None, "results": data.get("results", data)}
    except FileNotFoundError:
        return {"tool": "semgrep", "error": "semgrep not installed (pip install semgrep)", "results": []}
    except subprocess.TimeoutExpired:
        return {"tool": "semgrep", "error": "timeout", "results": []}
    except json.JSONDecodeError as e:
        return {"tool": "semgrep", "error": str(e), "results": []}


def run_gitleaks(target_path: str) -> dict:
    """Run gitleaks detect on target_path and return JSON results. Empty structure if unavailable."""
    path = Path(target_path).resolve()
    if not path.exists():
        return {"tool": "gitleaks", "error": f"path not found: {target_path}", "results": []}
    source = str(path) if path.is_dir() else str(path.parent)
    try:
        cmd = [
            "gitleaks", "detect",
            "--source", source,
            "--no-git",
            "--report-format", "json",
            "--report-path", "-",  # write JSON to stdout
        ]
        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        # when gitleaks finds secrets exit code may be 1, but stdout still contains JSON
        raw = out.stdout.strip()
        if not raw:
            return {"tool": "gitleaks", "error": None, "results": []}
        try:
            data = json.loads(raw)
            results = data if isinstance(data, list) else data.get("findings", data.get("results", []))
        except json.JSONDecodeError:
            results = []
        return {"tool": "gitleaks", "error": None, "results": results}
    except FileNotFoundError:
        return {"tool": "gitleaks", "error": "gitleaks not installed", "results": []}
    except subprocess.TimeoutExpired:
        return {"tool": "gitleaks", "error": "timeout", "results": []}


def main():
    parser = argparse.ArgumentParser(description="Pre-scan: semgrep + gitleaks -> JSON report")
    parser.add_argument(
        "input_path",
        nargs="?",
        default=".",
        help="File or directory path to scan (default: current directory)",
    )
    parser.add_argument(
        "-o", "--output",
        default="prescan_report.json",
        help="Output JSON file path (default: prescan_report.json)",
    )
    args = parser.parse_args()

    input_path = os.path.normpath(args.input_path)
    if not os.path.exists(input_path):
        print(f"Error: path not found {input_path}", file=sys.stderr)
        sys.exit(1)

    report = {
        "input_path": os.path.abspath(input_path),
        "semgrep": run_semgrep(input_path),
        "gitleaks": run_gitleaks(input_path),
    }

    out_path = args.output
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"Report written to: {out_path}")


if __name__ == "__main__":
    main()
