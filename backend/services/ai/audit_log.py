"""
Audit Log -- who/what/when/before/after/result for every remediation
action (Team Plan section 5, "Remediation Execution").

Appends JSON lines to a local file so nothing is lost on process restart,
without needing Sireen's Postgres schema to exist yet. `GET
/remediation/history` reads this file. Swap `_LOG_PATH` writes for an
INSERT into her `remediation_logs`/`audit_logs` tables later -- the record
shape (dict) is already what those tables want.
"""

import json
import os
from datetime import datetime, timezone

_LOG_PATH = os.path.join(os.path.dirname(__file__), "audit_log.jsonl")


def record(event: dict) -> dict:
    entry = {"timestamp": datetime.now(timezone.utc).isoformat(), **event}
    with open(_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def history(limit: int = 100) -> list[dict]:
    if not os.path.exists(_LOG_PATH):
        return []
    with open(_LOG_PATH, "r", encoding="utf-8") as f:
        lines = [json.loads(line) for line in f if line.strip()]
    return list(reversed(lines))[:limit]
