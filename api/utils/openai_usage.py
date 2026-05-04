"""Accumulate OpenAI completion.usage onto the custom User model."""
from __future__ import annotations

from typing import Any

from django.db.models import F


def record_openai_usage_for_user(user_id: int | None, usage: Any) -> None:
    if not user_id or usage is None:
        return
    from ..models import User
    try:
        p = int(getattr(usage, "prompt_tokens", 0) or 0)
        c = int(getattr(usage, "completion_tokens", 0) or 0)
    except (TypeError, ValueError):
        return
    if p <= 0 and c <= 0:
        return
    User.objects.filter(user_id=user_id).update(
        total_llm_prompt_tokens=F("total_llm_prompt_tokens") + p,
        total_llm_completion_tokens=F("total_llm_completion_tokens") + c,
    )
