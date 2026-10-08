from redteam.monitoring.trace import TraceEvent, TraceLog
from redteam.safety.audit import AuditLog, verify_chain


def _ev(**kw):
    base = dict(run_id="r1", mode="crew", agent="recon", phase="recon", type="llm_call")
    base.update(kw)
    return TraceEvent(ts="2026-10-05T00:00:00Z", **base)


def test_emit_writes_jsonl(tmp_path):
    log = TraceLog(str(tmp_path / "trace.jsonl"), run_id="r1", mode="crew")
    log.emit(_ev())
    assert len(log.events()) == 1


def test_critical_event_also_audited(tmp_path):
    audit_path = str(tmp_path / "audit.jsonl")
    log = TraceLog(str(tmp_path / "trace.jsonl"), run_id="r1", mode="crew",
                   audit=AuditLog(audit_path))
    log.emit(_ev(type="finding", finding_id="F1", severity="high"))
    assert verify_chain(audit_path)
