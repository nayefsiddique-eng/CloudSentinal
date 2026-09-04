"""
Backup / Rollback.

Before executor.py applies a fix, snapshot the current AWS-side config for
that resource. If remediation fails partway, or verification later shows
the fix didn't work, restore() puts it back.

Snapshots are kept in-memory (module-level dict) keyed by finding_id for
this process's lifetime -- good enough for the demo/thesis pipeline.
Swap `_STORE` for a real table (Sireen's `remediation_logs`/audit schema
already has room for this) once the DB lands; the read/write shape below
won't need to change.
"""

from datetime import datetime, timezone
from backend.services.aws.client import get_client

_STORE: dict[str, dict] = {}


def _snapshot_s3(bucket: str) -> dict:
    s3 = get_client("s3")
    snap = {}
    try:
        pab = s3.get_public_access_block(Bucket=bucket)
        snap["public_access_block"] = pab["PublicAccessBlockConfiguration"]
    except Exception:
        snap["public_access_block"] = None
    try:
        acl = s3.get_bucket_acl(Bucket=bucket)
        snap["acl_grants"] = acl.get("Grants", [])
    except Exception:
        snap["acl_grants"] = None
    try:
        ver = s3.get_bucket_versioning(Bucket=bucket)
        snap["versioning_status"] = ver.get("Status")
    except Exception:
        snap["versioning_status"] = None
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket)
        snap["encryption_rules"] = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
    except Exception:
        snap["encryption_rules"] = None
    return snap


def _snapshot_iam(finding: dict) -> dict:
    iam = get_client("iam")
    snap = {}
    if finding.get("resource_type") == "iam_account":
        try:
            snap["password_policy"] = iam.get_account_password_policy()["PasswordPolicy"]
        except Exception:
            snap["password_policy"] = None
    if finding.get("category") == "CREDENTIAL_HYGIENE":
        username = finding.get("resource_id")
        try:
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            snap["access_key_statuses"] = {k["AccessKeyId"]: k["Status"] for k in keys}
        except Exception:
            snap["access_key_statuses"] = None
    return snap


def snapshot(finding: dict) -> dict:
    """Capture pre-change state for a finding's resource. Returns the
    snapshot AND stores it keyed by finding_id for later restore()."""
    resource_type = finding.get("resource_type")

    if resource_type == "s3_bucket":
        state = _snapshot_s3(finding["resource_id"])
    elif resource_type in ("iam_user", "iam_account"):
        state = _snapshot_iam(finding)
    else:
        state = {}

    record = {
        "finding_id": finding.get("finding_id"),
        "resource_type": resource_type,
        "resource_id": finding.get("resource_id"),
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "state": state,
    }
    if finding.get("finding_id"):
        _STORE[finding["finding_id"]] = record
    return record


def get_snapshot(finding_id: str) -> dict | None:
    return _STORE.get(finding_id)


def _restore_s3(bucket: str, state: dict) -> dict:
    s3 = get_client("s3")
    restored = []
    try:
        if state.get("public_access_block") is not None:
            s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=state["public_access_block"])
            restored.append("public_access_block")
        if state.get("versioning_status"):
            s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": state["versioning_status"]})
            restored.append("versioning")
        # ACL and encryption restore are intentionally left manual: PUT
        # bucket-acl needs the full original grant list re-derived
        # correctly (not just re-sent) to avoid accidentally widening
        # access on restore -- flag for manual review instead of guessing.
        return {"restored": restored, "note": "ACL/encryption rollback needs manual review; other fields restored."}
    except Exception as e:
        return {"restored": restored, "error": str(e)}


def _restore_iam(finding: dict, state: dict) -> dict:
    iam = get_client("iam")
    restored = []
    try:
        if state.get("password_policy"):
            p = state["password_policy"]
            iam.update_account_password_policy(
                MinimumPasswordLength=p.get("MinimumPasswordLength", 8),
                RequireSymbols=p.get("RequireSymbols", False),
                RequireNumbers=p.get("RequireNumbers", False),
                RequireUppercaseCharacters=p.get("RequireUppercaseCharacters", False),
                RequireLowercaseCharacters=p.get("RequireLowercaseCharacters", False),
            )
            restored.append("password_policy")
        if state.get("access_key_statuses"):
            username = finding.get("resource_id")
            for key_id, status in state["access_key_statuses"].items():
                iam.update_access_key(UserName=username, AccessKeyId=key_id, Status=status)
            restored.append("access_key_statuses")
        return {"restored": restored}
    except Exception as e:
        return {"restored": restored, "error": str(e)}


def restore(finding_id: str) -> dict:
    """Roll a finding's resource back to its pre-remediation snapshot."""
    record = _STORE.get(finding_id)
    if not record:
        return {"rolled_back": False, "reason": "No snapshot found for this finding_id."}

    resource_type = record["resource_type"]
    if resource_type == "s3_bucket":
        result = _restore_s3(record["resource_id"], record["state"])
    elif resource_type in ("iam_user", "iam_account"):
        result = _restore_iam({"resource_id": record["resource_id"], "category": "CREDENTIAL_HYGIENE"}, record["state"])
    else:
        return {"rolled_back": False, "reason": f"No rollback logic for resource_type={resource_type}."}

    return {"rolled_back": "error" not in result, **result}
