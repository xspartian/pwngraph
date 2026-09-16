"""Reporter — the raw trace dump.

This module used to render a static ``report.html`` (and before that, a pyvis
attack graph). Both are retired. The findings write-up now lives in
``pwngraph serve``, which reads it back out of the graph backend
(``pwngraph.report_store``) rather than from a file, so a scan's report can't
drift from the graph sitting next to it and there is no HTML artifact to keep
in sync. What a scan leaves on disk is data — ``graph.json``, ``trace.json``,
``asr.json``, ``delivery.json``, ``findings.sarif``, ``evidence_ladder.json``,
and ``poc/`` — assembled by ``PwnGraph.report()``.

The Jinja2 template that produced ``report.html`` is in git history if an
offline HTML export is ever wanted again; ``findings.sarif`` covers the CI
case in the meantime, and ``poc/`` covers sharing an individual finding.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from pwngraph.types import TraceEvent

log = logging.getLogger(__name__)


class Reporter:
    """Writes the raw event stream for offline analysis."""

    def dump_trace(self, events: list[TraceEvent], output_path: Path) -> Path:
        """Write the full event stream to JSON for offline analysis."""
        output_path.write_text(
            json.dumps(
                [e.model_dump(mode="json") for e in events],
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
        return output_path
