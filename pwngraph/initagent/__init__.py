"""AI-driven adapter generation for ``pwngraph init``.

An LLM agent explores the target repository with read-only tools, writes
adapter.py, and runs it in a subprocess until the adapter loads the
repository's real agent with its real tools — see ``loop.build_adapter``.
"""

from pwngraph.initagent.loop import DEFAULT_MODEL, AdapterResult, build_adapter

__all__ = ["DEFAULT_MODEL", "AdapterResult", "build_adapter"]
