from dataclasses import dataclass
import hashlib
import json
from typing import Any


@dataclass(frozen=True)
class AuditEvent:
    seq: int
    prev_hash: str
    event_type: str
    fencing_token: int
    payload_json: str
    entry_hash: str


def event_digest(seq: int, prev_hash: str, event_type: str, fencing_token: int, payload_json: str) -> str:
    raw = f"{seq}|{prev_hash}|{event_type}|{fencing_token}|{payload_json}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class HashChainedAuditLog:
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(self, event_type: str, fencing_token: int, payload: dict[str, Any]) -> AuditEvent:
        seq = len(self._events) + 1
        prev_hash = self._events[-1].entry_hash if self._events else "0" * 64
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        entry_hash = event_digest(seq, prev_hash, event_type, fencing_token, payload_json)
        ev = AuditEvent(
            seq=seq,
            prev_hash=prev_hash,
            event_type=event_type,
            fencing_token=fencing_token,
            payload_json=payload_json,
            entry_hash=entry_hash,
        )
        self._events.append(ev)
        return ev

    def verify(self) -> tuple[bool, str]:
        prev = "0" * 64
        for idx, ev in enumerate(self._events, start=1):
            if ev.seq != idx:
                return False, f"sequence gap at {idx}"
            if ev.prev_hash != prev:
                return False, f"prev_hash broken at seq {ev.seq}"
            expected = event_digest(ev.seq, ev.prev_hash, ev.event_type, ev.fencing_token, ev.payload_json)
            if expected != ev.entry_hash:
                return False, f"hash mismatch at seq {ev.seq}"
            prev = ev.entry_hash
        return True, "ok"

    def events(self) -> list[AuditEvent]:
        return list(self._events)
