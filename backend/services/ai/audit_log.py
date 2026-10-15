"""
Audit Log -- who/what/when/before/after/result for every remediation
action (Team Plan section 5, "Remediation Execution").

Appends JSON lines to a local file so nothing is lost on process restart.
Masks sensitive keys and credentials automatically before writing.
"""

import json
import os
import re
from datetime import datetime, timezone

_LOG_PATH = os.path.join(os.path.dirname(__file__), "audit_log.jsonl")

SENSITIVE_KEYS = {
    "password", "secret", "token", "authorization", "access_key", "secret_key",
    "aws_secret_access_key", "aws_access_key_id", "credential", "api_key"
}


def _mask_sensitive(obj):
    if isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            k_str = str(k)
            if any(s in k_str.lower() for s in SENSITIVE_KEYS) and not k_str.lower().endswith(("_id", "_name", "_arn")):
                if isinstance(v, dict):
                    cleaned[k] = _mask_sensitive(v)
                else:
                    cleaned[k] = "******"
            else:
                cleaned[k] = _mask_sensitive(v)
        return cleaned
    elif isinstance(obj, list):
        return [_mask_sensitive(item) for item in obj]
    elif isinstance(obj, str):
        # Mask Bearer tokens or obvious secret values in free text
        if re.search(r'(?i)(Bearer\s+[a-zA-Z0-9_\-\.]+)', obj):
            return re.sub(r'(?i)(Bearer\s+)[a-zA-Z0-9_\-\.]+', r'\1******', obj)
        return obj
    return obj


def record(event: dict) -> dict:
    masked_event = _mask_sensitive(event)
    entry = {"timestamp": datetime.now(timezone.utc).isoformat(), **masked_event}
    try:
        with open(_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        # In case disk write fails, do not silently ignore
        entry["_log_error"] = str(e)
    return entry


def history(limit: int = 100) -> list[dict]:
    if not os.path.exists(_LOG_PATH):
        return []
    with open(_LOG_PATH, "r", encoding="utf-8") as f:
        lines = [json.loads(line) for line in f if line.strip()]
    return list(reversed(lines))[:limit]
