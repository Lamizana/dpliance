from redteam.monitoring.trace import TraceEvent
from redteam.benchmark.metrics import metrics_from_trace, quality


def _ev(type, **kw):
    return TraceEvent(ts="t", run_id="r", mode="crew", agent="a", phase="p", type=type, **kw)


def test_metrics_counts():
    events = [_ev("llm_call", tokens_in=10, tokens_out=5), _ev("tool_call"),
              _ev("verification", status="confirmed"), _ev("verification", status="discarded")]
    m = metrics_from_trace(events, duration_s=2.0)
    assert m.llm_calls == 1 and m.tool_calls == 1
    assert m.confirmed_count == 1 and m.discarded_count == 1
    assert m.tokens_in == 10


def test_quality_precision_recall():
    q = quality(confirmed_ids={"a", "b"}, truth_ids={"a", "c"})
    assert q["precision"] == 0.5 and q["recall"] == 0.5
