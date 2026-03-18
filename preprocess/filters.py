"""
Skip binary/large/minified paths and irrelevant directories.
"""

from pathlib import Path
from typing import Optional, Tuple

SKIP_DIR_NAMES = {
    "node_modules",
    "venv",
    ".venv",
    ".git",
    "dist",
    "build",
    "__pycache__",
    ".next",
    "target",
    ".idea",
    ".vscode",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".so", ".dll", ".dylib", ".exe", ".bin",
    ".pyc", ".pyo", ".class", ".o", ".a",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".webm", ".avi",
}

MINIFIED_NAME_SUFFIXES = (".min.js", ".min.css")
GENERATED_NAME_PARTS = ("-generated", "_generated", ".generated.")


def should_skip_path(path: Path, max_bytes: int = 512 * 1024) -> Tuple[bool, Optional[str]]:
    """
    Returns (skip, reason). reason is None if not skipped.
    """
    if not path.exists():
        return True, "not_found"
    if path.is_dir():
        if path.name in SKIP_DIR_NAMES:
            return True, f"skip_dir:{path.name}"
        return False, None
    suffix = path.suffix.lower()
    if suffix in BINARY_EXTENSIONS:
        return True, f"binary_ext:{suffix}"
    try:
        size = path.stat().st_size
    except OSError:
        return True, "stat_failed"
    if size > max_bytes:
        return True, f"too_large:{size}"
    name = path.name.lower()
    for s in MINIFIED_NAME_SUFFIXES:
        if name.endswith(s):
            return True, "minified_name"
    for part in GENERATED_NAME_PARTS:
        if part in name:
            return True, "generated_name"
    return False, None


def path_has_skip_segment(path: Path) -> bool:
    for part in path.parts:
        if part in SKIP_DIR_NAMES:
            return True
    return False
