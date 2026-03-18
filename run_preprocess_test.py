#!/usr/bin/env python3
"""
Run preprocessing and write JSON.

By default writes the LLM-friendly payload only (compact, no chunk content).
Use --full for complete preprocess output (scanners / cache).

Usage:
  python3 run_preprocess_test.py                    # -> ai_payload.json (LLM)
  python3 run_preprocess_test.py -o out.json        # LLM payload to out.json
  python3 run_preprocess_test.py --full             # full preprocess JSON
  python3 run_preprocess_test.py --full -o pre.json
  python3 run_preprocess_test.py other.py -o x.json
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from preprocess.pipeline import run_file  # noqa: E402
from preprocess.normalized_findings import run_file_ai_payload  # noqa: E402

DEFAULT_INPUT = ROOT / "testquery.py"
DEFAULT_OUTPUT_LLM = "ai_payload.json"
DEFAULT_OUTPUT_FULL = "preprocess_output.json"


def main():
    parser = argparse.ArgumentParser(
        description="Preprocess a file -> JSON (default: LLM payload only)",
    )
    parser.add_argument(
        "input",
        nargs="?",
        default=str(DEFAULT_INPUT),
        help="File path to preprocess (default: testquery.py)",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output JSON path (default: ai_payload.json or preprocess_output.json with --full)",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Write full preprocess JSON (includes chunk content; for scanners, not for LLM)",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"Not a file: {input_path}", file=sys.stderr)
        sys.exit(1)

    if args.full:
        data = run_file(input_path)
        out = args.output or DEFAULT_OUTPUT_FULL
    else:
        data = run_file_ai_payload(input_path)
        out = args.output or DEFAULT_OUTPUT_LLM

    out_path = Path(out)
    out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {out_path}")
    print(f"  project_id: {data.get('project_id', '')[:16]}...")

    if args.full:
        print(f"  mode: full preprocess")
        print(f"  files: {len(data['files'])}, chunks: {len(data['chunks'])}, skipped: {len(data['files_skipped'])}")
    else:
        n = len(data.get("normalized_findings") or [])
        print(f"  mode: LLM payload ({n} findings, no chunk content)")


if __name__ == "__main__":
    main()
