import hashlib
import uuid
from pathlib import Path


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def new_uuid() -> str:
    return str(uuid.uuid4())
