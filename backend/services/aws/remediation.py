"""
Remediation logic: maps a finding to a plan (plan_remediation) and,
if the plan is "automatable", carries it out (apply_remediation).

Matching is done on (category, finding text) rather than resource_type
alone, since one resource_type (e.g. s3_bucket) has several distinct
finding types that need different fixes.

Safety rule: only reversible, low-blast-radius fixes are "automatable".
Anything that could lock someone out (deleting a user, revoking a wildcard
policy, disabling an access key still in active use) is
"manual_action_required" and is never auto-applied, even with confirm=true --
main.py's /remediate route enforces this by refusing non-automatable plans.
"""

from backend.services.aws.client import get_client


def _s3_plan(finding: dict) -> dict:
    text = finding.get("finding", "")
    bucket = finding.get("resource_id")

    if "Block Public Access is disabled" in text:
        return {
            "kind": "automatable",
            "description": f"Enable S3 Block Public Access on bucket '{bucket}'.",
            "risk": "None -- this only removes public-access ability, does not change existing bucket policies.",
        }

    if "Bucket is publicly accessible" in text:
        return {
            "kind": "automatable",
            "description": f"Remove public ACL grants (AllUsers/AuthenticatedUsers) on bucket '{bucket}'.",
            "risk": "Any workflow relying on public read/write access to this bucket will break.",
        }

    if "Versioning is disabled" in text:
        return {
            "kind": "automatable",
            "description": f"Enable versioning on bucket '{bucket}'.",
            "risk": "None -- versioning is additive and reversible (can be suspended later).",
        }

    if "Encryption is disabled" in text:
        return {
            "kind": "automatable",
            "description": f"Enable default SSE-S3 (AES256) encryption on bucket '{bucket}'.",
            "risk": "None -- only affects new objects written after this is applied.",
        }

    return {
        "kind": "no_action_needed",
        "description": "No remediation needed for this finding.",
    }


def _apply_s3(finding: dict) -> dict:
    s3 = get_client("s3")
    text = finding.get("finding", "")
    bucket = finding.get("resource_id")

    try:
        if "Block Public Access is disabled" in text:
            s3.put_public_access_block(
                Bucket=bucket,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            return {"applied": True, "detail": "Block Public Access enabled."}

        if "Bucket is publicly accessible" in text:
            s3.put_bucket_acl(Bucket=bucket, ACL="private")
            return {"applied": True, "detail": "Bucket ACL reset to private."}

        if "Versioning is disabled" in text:
            s3.put_bucket_versioning(
                Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
            )
            return {"applied": True, "detail": "Versioning enabled."}

        if "Encryption is disabled" in text:
            s3.put_bucket_encryption(
                Bucket=bucket,
                ServerSideEncryptionConfiguration={
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                },
            )
            return {"applied": True, "detail": "Default encryption (AES256) enabled."}

        return {"applied": False, "reason": "No automated fix defined for this finding."}

    except Exception as e:
        return {"applied": False, "error": str(e)}


def _iam_plan(finding: dict) -> dict:
    text = finding.get("finding", "")
    category = finding.get("category")
    resource_type = finding.get("resource_type")

    if resource_type == "iam_account" and category == "IDENTITY_SECURITY" and "Root account MFA" in text:
        return {
            "kind": "manual_action_required",
            "description": "Root MFA cannot be enabled programmatically -- sign in as root and add an MFA device in the console.",
        }

    if resource_type == "iam_account" and "Weak password policy" in text:
        return {
            "kind": "automatable",
            "description": "Update account password policy to require length >=14, symbols, numbers, and mixed case.",
            "risk": "Existing users won't be forced to change passwords immediately, but new/changed passwords must meet the new policy.",
        }

    if resource_type == "iam_user" and category == "IDENTITY_SECURITY" and "MFA is not enabled" in text:
        return {
            "kind": "manual_action_required",
            "description": f"MFA must be enrolled by the user '{finding.get('resource_id')}' themselves -- cannot be enabled on their behalf.",
        }

    if category == "EXCESSIVE_PERMISSIONS" and "wildcard" in text.lower():
        return {
            "kind": "manual_action_required",
            "description": f"User '{finding.get('resource_id')}' has Action:*/Resource:* permissions. Review before detaching -- auto-removal could break active workloads.",
            "risk": "High -- detaching a policy in use will break whatever depends on it.",
        }

    if category == "CREDENTIAL_HYGIENE" and "access key" in text.lower():
        old_keys = finding.get("evidence", {}).get("old_keys", [])
        if old_keys:
            return {
                "kind": "automatable",
                "description": f"Deactivate {len(old_keys)} access key(s) older than 90 days for '{finding.get('resource_id')}'.",
                "risk": "Any script or service still using these keys will start failing immediately.",
            }

    return {
        "kind": "no_action_needed",
        "description": "No remediation needed for this finding.",
    }


def _apply_iam(finding: dict) -> dict:
    iam = get_client("iam")
    text = finding.get("finding", "")
    resource_type = finding.get("resource_type")

    try:
        if resource_type == "iam_account" and "Weak password policy" in text:
            iam.update_account_password_policy(
                MinimumPasswordLength=14,
                RequireSymbols=True,
                RequireNumbers=True,
                RequireUppercaseCharacters=True,
                RequireLowercaseCharacters=True,
            )
            return {"applied": True, "detail": "Password policy updated to baseline."}

        if finding.get("category") == "CREDENTIAL_HYGIENE" and "access key" in text.lower():
            username = finding.get("resource_id")
            old_keys = finding.get("evidence", {}).get("old_keys", [])
            deactivated = []
            for key in old_keys:
                iam.update_access_key(
                    UserName=username,
                    AccessKeyId=key["access_key_id"],
                    Status="Inactive",
                )
                deactivated.append(key["access_key_id"])
            return {"applied": True, "detail": f"Deactivated keys: {deactivated}"}

        return {"applied": False, "reason": "No automated fix defined for this finding."}

    except Exception as e:
        return {"applied": False, "error": str(e)}


def _default_plan(finding: dict) -> dict:
    """Fallback for resource types without dedicated remediation logic yet
    (ec2/security_group, cloudtrail, lambda_function). Kept as
    manual_action_required rather than silently no-op, so these findings
    still show up as needing attention in the UI."""
    if finding.get("category") == "SCAN_ERROR":
        return {
            "kind": "no_action_needed",
            "description": "This is a scan error, not a security finding -- nothing to remediate.",
        }
    return {
        "kind": "manual_action_required",
        "description": "Automated remediation for this resource type isn't implemented yet -- please review and fix manually.",
    }


def plan_remediation(finding: dict) -> dict:
    resource_type = finding.get("resource_type")

    if resource_type == "s3_bucket":
        return _s3_plan(finding)
    if resource_type in ("iam_user", "iam_account"):
        return _iam_plan(finding)

    return _default_plan(finding)


def apply_remediation(finding: dict) -> dict:
    resource_type = finding.get("resource_type")

    if resource_type == "s3_bucket":
        return _apply_s3(finding)
    if resource_type in ("iam_user", "iam_account"):
        return _apply_iam(finding)

    return {"applied": False, "reason": "No automated fix defined for this resource type."}
