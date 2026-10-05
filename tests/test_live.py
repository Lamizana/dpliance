from redteam.monitoring.trace import TraceEvent
from redteam.monitoring.live import format_event


def test_format_verification_event():
    e = TraceEvent(ts="t", run_id="r", mode="crew", agent="verifier", phase="verify",
                   type="verification", finding_id="F1", severity="medium",
                   status="confirmed", confidence=0.85)
    line = format_event(e)
    assert "F1" in line and "confirmed" in line and "verify" in line
