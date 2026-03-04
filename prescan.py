#!/usr/bin/env python3
"""
Pre-scan 模組：對指定檔案或目錄執行 semgrep 與 gitleaks，輸出合併的 JSON 報告。
使用方式：
  python prescan.py [輸入路徑] [-o 輸出.json]
  不給路徑時預設掃描當前目錄。
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def run_semgrep(target_path: str) -> dict:
    """對 target_path 執行 semgrep，回傳 JSON 結果。失敗或未安裝則回傳空結構。"""
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
    """對 target_path 執行 gitleaks detect，回傳 JSON 結果。未安裝則回傳空結構。"""
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
            "--report-path", "-",  # 將 JSON 輸出到 stdout
        ]
        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        # gitleaks 找到 secret 時 exit code 可能為 1，但 stdout 仍有 JSON
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
        help="要掃描的檔案或目錄路徑（預設: 當前目錄）",
    )
    parser.add_argument(
        "-o", "--output",
        default="prescan_report.json",
        help="輸出的 JSON 檔案路徑（預設: prescan_report.json）",
    )
    args = parser.parse_args()

    input_path = os.path.normpath(args.input_path)
    if not os.path.exists(input_path):
        print(f"錯誤：找不到路徑 {input_path}", file=sys.stderr)
        sys.exit(1)

    report = {
        "input_path": os.path.abspath(input_path),
        "semgrep": run_semgrep(input_path),
        "gitleaks": run_gitleaks(input_path),
    }

    out_path = args.output
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"已寫入: {out_path}")


if __name__ == "__main__":
    main()
