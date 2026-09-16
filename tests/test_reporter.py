"""Tests for pwngraph.reporter.reporter — the raw trace dump.

The HTML severity report this module used to render is gone: the findings
write-up lives in `pwngraph serve`, read back out of the graph backend
(pwngraph.report_store), so a scan no longer writes a static report.html that
could drift from the graph beside it. What remains here is the trace dump.

Coverage for the *content* of a report — severity breakdowns agreeing with
the headline finding count, CVSS, ASR — now lives in tests/test_report_store.py
and tests/test_api_scans.py, against the data the viewer actually reads.
"""

from __future__ import annotations

import json

from pwngraph.reporter.reporter import Reporter
from pwngraph.types import NodeType, TraceEvent


def _event(**over) -> TraceEvent:
    defaults = dict(run_id="r1", node_type=NodeType.TOOL_CALL, name="send_email", content="body")
    defaults.update(over)
    return TraceEvent(**defaults)


def test_dump_trace_writes_every_event(tmp_path):
    events = [_event(name="a"), _event(name="b"), _event(name="c")]
    out = Reporter().dump_trace(events, tmp_path / "trace.json")

    assert out.exists()
    rows = json.loads(out.read_text(encoding="utf-8"))
    assert [r["name"] for r in rows] == ["a", "b", "c"]


def test_dump_trace_preserves_the_fields_an_offline_reader_needs(tmp_path):
    ev = _event(content="canary PWN-DEADBEEF", is_adversarial=True, payload_id="p7")
    out = Reporter().dump_trace([ev], tmp_path / "trace.json")

    row = json.loads(out.read_text(encoding="utf-8"))[0]
    assert row["node_type"] == "tool_call"
    assert row["content"] == "canary PWN-DEADBEEF"
    assert row["is_adversarial"] is True
    assert row["payload_id"] == "p7"
    assert row["run_id"] == "r1"


def test_dump_trace_is_valid_json_for_an_empty_scan(tmp_path):
    out = Reporter().dump_trace([], tmp_path / "trace.json")
    assert json.loads(out.read_text(encoding="utf-8")) == []
