"""
Read file as text: UTF-8 first, then fallbacks. Detect unreadable/binary.
"""

from pathlib import Path
from typing import Optional, Tuple

ENCODING_FALLBACKS = ["utf-8", "utf-8-sig", "latin-1", "cp1252"]


def read_text_with_fallback(path: Path) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Returns (text, encoding_used, error).
    If unreadable, text is None and error explains why.
    """
    raw = path.read_bytes()
    if b"\x00" in raw[:8192] and raw[:8192].count(b"\x00") > 2:
        return None, None, "likely_binary_null_bytes"
    for enc in ENCODING_FALLBACKS:
        try:
            text = raw.decode(enc)
            return text, enc, None
        except UnicodeDecodeError:
            continue
    return None, None, "decode_failed_all_encodings"


def is_probably_text(s: str, sample_lines: int = 50) -> bool:
    """Heuristic: too many non-printable chars => skip."""
    sample = "\n".join(s.splitlines()[:sample_lines])
    if not sample.strip():
        return True
    printable = sum(1 for c in sample if c.isprintable() or c in "\n\r\t")
    ratio = printable / max(len(sample), 1)
    return ratio >= 0.85
