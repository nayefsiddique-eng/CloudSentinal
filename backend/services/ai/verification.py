"""
Verification Engine.

Apply fix -> re-check the SAME specific control (not a full /scan, for
speed) -> compare against what the fix was supposed to achieve -> report
RESOLVED or STILL_OPEN. Reuses Nayef's own scanner check functions so the
"is this actually fixed" answer is defined identically to how it was
originally *detected* -- no separate logic that could disagree with the
scanner.
"""

from backend.services.aws import s3 as s3_scanner
from backend.services.aws import iam as iam_scanner

VERIFICATION_PASSED = "VERIFICATION_PASSED"
VERIFICATION_FAILED = "VERIFICATION_FAILED"
NOT_VERIFIABLE = "NOT_VERIFIABLE"


def _verify_s3(finding: dict) -> dict:
    bucket = finding.get("resource_id")
    text = finding.get("finding", "")

    if "Block Public Access is disabled" in text:
        fixed = s3_scanner.get_public_access_block_status(bucket)
        return {"check": "block_public_access_enabled", "resolved": fixed}
    if "Bucket is publicly accessible" in text:
        fixed = not s3_scanner.is_bucket_public(bucket)
        return {"check": "bucket_not_public", "resolved": fixed}
    if "Versioning is disabled" in text:
        fixed = s3_scanner.is_versioning_enabled(bucket)
        return {"check": "versioning_enabled", "resolved": fixed}
    if "Encryption is disabled" in text:
        fixed = s3_scanner.is_encryption_enabled(bucket)
        return {"check": "encryption_enabled", "resolved": fixed}
    return {"check": None, "resolved": None}


def _verify_iam(finding: dict) -> dict:
    text = finding.get("finding", "")
    resource_type = finding.get("resource_type")

    if resource_type == "iam_account" and "Weak password policy" in text:
        result = iam_scanner.has_weak_password_policy()
        return {"check": "password_policy_meets_baseline", "resolved": not result["weak"]}

    if finding.get("category") == "CREDENTIAL_HYGIENE" and "access key" in text.lower():
        username = finding.get("resource_id")
        still_old = iam_scanner.get_old_access_keys(username)
        # Old keys that were *deactivated* still show up as "old" by age,
        # but they're no longer usable -- so check status instead of presence.
        still_active_and_old = [k for k in still_old if k["status"] == "Active"]
        return {"check": "old_keys_deactivated", "resolved": len(still_active_and_old) == 0}

    return {"check": None, "resolved": None}


def verify_finding(finding: dict) -> dict:
    """Re-check the resource after a remediation was applied."""
    resource_type = finding.get("resource_type")

    try:
        if resource_type == "s3_bucket":
            result = _verify_s3(finding)
        elif resource_type in ("iam_user", "iam_account"):
            result = _verify_iam(finding)
        else:
            result = {"check": None, "resolved": None}
    except Exception as e:
        return {"status": VERIFICATION_FAILED, "check": None, "error": str(e)}

    if result["resolved"] is None:
        return {"status": NOT_VERIFIABLE, "check": result["check"]}

    status = VERIFICATION_PASSED if result["resolved"] else VERIFICATION_FAILED
    return {"status": status, "check": result["check"], "resolved": result["resolved"]}
