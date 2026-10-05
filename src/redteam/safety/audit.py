from __future__ import annotations

import datetime
import hashlib
import json
from typing import Callable

from redteam.safety.signing import Signer

GENESIS = "0" * 64


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _entry_hash(prev_hash: str, entry_without_hash: dict) -> str:
    canonical = json.dumps(entry_without_hash, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str, clock: Callable[[], str] = _utc_now_iso):
        self.path = path
        self.clock = clock

    def _last_hash(self) -> tuple[int, str]:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                last = None
                for line in fh:
                    if line.strip():
                        last = json.loads(line)
                if last is None:
                    return -1, GENESIS
                return last["index"], last["hash"]
        except FileNotFoundError:
            return -1, GENESIS

    def append(self, action: str, target: str, detail: dict) -> str:
        prev_index, prev_hash = self._last_hash()
        entry = {
            "index": prev_index + 1,
            "timestamp": self.clock(),
            "action": action,
            "target": target,
            "detail": detail,
            "prev_hash": prev_hash,
        }
        entry["hash"] = _entry_hash(prev_hash, entry)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry["hash"]

    def tip(self) -> tuple[int, str]:
        return self._last_hash()  # (index, hash); (-1, GENESIS) if empty

    def write_checkpoint(self, signer: Signer) -> None:
        index, tip_hash = self.tip()
        payload = {"index": index, "hash": tip_hash}
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        payload["signature"] = signer.sign(canonical)
        with open(self.path + ".tip", "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)


def verify_chain(path: str, expected_tip_hash: str | None = None) -> bool:
    prev_hash = GENESIS
    last_hash = GENESIS
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            entry = json.loads(line)
            stored = entry.pop("hash")
            if entry["prev_hash"] != prev_hash:
                return False
            if _entry_hash(prev_hash, entry) != stored:
                return False
            prev_hash = stored
            last_hash = stored
    if expected_tip_hash is not None and last_hash != expected_tip_hash:
        return False
    return True


def read_checkpoint(path: str, signer: Signer) -> tuple[int, str] | None:
    try:
        with open(path + ".tip", "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return None
    sig = data.pop("signature", "")
    canonical = json.dumps(
        {"index": data["index"], "hash": data["hash"]}, sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    if not signer.verify(canonical, sig):
        raise ValueError("Checkpoint d'audit invalide (signature).")
    return data["index"], data["hash"]


def export_bundle(path: str, signer: Signer | None = None) -> dict:
    count = 0
    tip_hash = GENESIS
    first_ts = None
    last_ts = None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                entry = json.loads(line)
                count += 1
                tip_hash = entry["hash"]
                if first_ts is None:
                    first_ts = entry["timestamp"]
                last_ts = entry["timestamp"]
    except FileNotFoundError:
        pass

    chain_ok = (count == 0) or verify_chain(path)

    if signer is None:
        # Legacy path (no anchoring available/requested): best-effort chain check only.
        integrity_status = "verified" if chain_ok else "broken"
    else:
        try:
            cp = read_checkpoint(path, signer)
        except ValueError:
            # Tampered/forged checkpoint signature: cannot trust anything it claims.
            integrity_status = "broken"
        else:
            if cp is None:
                # No signed checkpoint at all: chain may be internally consistent,
                # but truncation/deletion is undetectable without an anchor.
                integrity_status = "unanchored" if chain_ok else "broken"
            else:
                _cp_index, cp_hash = cp
                anchored_ok = chain_ok and verify_chain(path, expected_tip_hash=cp_hash)
                integrity_status = "verified" if anchored_ok else "broken"

    # FAIL-CLOSED: only an anchored, fully-verified chain counts as intact.
    intact = integrity_status == "verified"

    return {
        "count": count,
        "tip_hash": tip_hash,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "intact": intact,
        "integrity_status": integrity_status,
    }
