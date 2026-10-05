from redteam.safety.audit import AuditLog, verify_chain


def test_append_and_chain_valid(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    log = AuditLog(p)
    log.append("run", "localhost", {"module": "a"})
    log.append("run", "localhost", {"module": "b"})
    assert verify_chain(p)


def test_tampering_breaks_chain(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    log = AuditLog(p)
    log.append("run", "localhost", {"module": "a"})
    lines = open(p).read().replace('"module": "a"', '"module": "HACKED"')
    open(p, "w").write(lines)
    assert not verify_chain(p)
