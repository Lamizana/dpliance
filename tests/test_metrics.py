from redteam.monitoring.trace import TraceEvent
from redteam.benchmark.compare import load_ground_truth, quality_report
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


def test_load_ground_truth_reads_probe_ids():
    ids = load_ground_truth("eval/mirage_ground_truth.yaml")
    assert "web.security_headers" in ids and len(ids) >= 1


def test_quality_report_renders_precision_recall():
    truth = load_ground_truth("eval/mirage_ground_truth.yaml")
    q = quality(confirmed_ids={"web.security_headers"}, truth_ids=truth)
    out = quality_report([("crew", q)])
    assert "précision" in out and "rappel" in out and "F1" in out
    assert "| crew |" in out
