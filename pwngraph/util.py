"""Small shared utilities."""

from __future__ import annotations

from typing import Any


def flatten_text(obj: Any) -> str:
    """Flatten an LLM/agent output into plain text.

    Modern chat models (Gemini, Claude, ...) return message content as a *list
    of content blocks* like ``[{"type": "text", "text": "..."}]`` rather than a
    bare string. Stringifying that with ``str()`` leaks Python reprs into the
    trace and breaks text matching. This collapses the common shapes — strings,
    message objects with ``.content``, content-block dicts, and lists — into one
    clean string.
    """
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj

    # LangChain message object (AIMessage, ...) carries text on .content
    if not isinstance(obj, (dict, list, tuple)):
        content = getattr(obj, "content", None)
        if content is not None:
            return flatten_text(content)
        text_attr = getattr(obj, "text", None)
        if isinstance(text_attr, str):
            return text_attr
        return str(obj)

    if isinstance(obj, dict):
        # A content block such as {"type": "text", "text": "..."}
        if isinstance(obj.get("text"), str):
            return obj["text"]
        for key in ("output", "content", "answer", "result"):
            if key in obj:
                return flatten_text(obj[key])
        return str(obj)

    # list / tuple of blocks → join the text of each
    parts = [flatten_text(x) for x in obj]
    return " ".join(p for p in parts if p)
