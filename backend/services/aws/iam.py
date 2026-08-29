import json
from datetime import datetime, timezone
from backend.services.aws.client import get_client


def list_users() -> list:
    iam = get_client("iam")
    response = iam.list_users()
    return [u["UserName"] for u in response.get("Users", [])]


def has_mfa_enabled(username: str) -> bool:
    iam = get_client("iam")
    response = iam.list_mfa_devices(UserName=username)
    return len(response.get("MFADevices", [])) > 0


def _policy_has_wildcard(policy_document: dict) -> bool:
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        resources = statement.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        if "*" in actions and "*" in resources:
            return True

    return False


def has_wildcard_permissions(username: str) -> bool:
    iam = get_client("iam")

    attached = iam.list_attached_user_policies(UserName=username)
    for policy in attached.get("AttachedPolicies", []):
        policy_arn = policy["PolicyArn"]
        policy_info = iam.get_policy(PolicyArn=policy_arn)
        version_id = policy_info["Policy"]["DefaultVersionId"]
        version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        doc = version["PolicyVersion"]["Document"]
        if _policy_has_wildcard(doc):
            return True

    inline = iam.list_user_policies(UserName=username)
    for policy_name in inline.get("PolicyNames", []):
        policy = iam.get_user_policy(UserName=username, PolicyName=policy_name)
        doc = policy["PolicyDocument"]
        if _policy_has_wildcard(doc):
            return True

    return False


def get_old_access_keys(username: str, max_age_days: int = 90) -> list:
    iam = get_client("iam")
    response = iam.list_access_keys(UserName=username)
    old_keys = []

    now = datetime.now(timezone.utc)
    for key in response.get("AccessKeyMetadata", []):
        create_date = key["CreateDate"]
        age_days = (now - create_date).days
        if age_days > max_age_days:
            old_keys.append({
                "access_key_id": key["AccessKeyId"],
                "age_days": age_days,
                "status": key["Status"],
            })

    return old_keys


def scan_iam_users() -> list:
    findings = []
    users = list_users()

    for username in users:
        mfa = has_mfa_enabled(username)
        findings.append({
            "resource_id": username,
            "resource_type": "iam_user",
            "finding": "MFA is not enabled" if not mfa else "MFA is enabled",
            "severity": "HIGH" if not mfa else "INFO",
            "category": "IDENTITY_SECURITY",
            "evidence": {"mfa_enabled": mfa},
            "status": "OPEN" if not mfa else "RESOLVED",
        })

        wildcard = has_wildcard_permissions(username)
        findings.append({
            "resource_id": username,
            "resource_type": "iam_user",
            "finding": "User has wildcard (Action:* Resource:*) permissions" if wildcard else "No wildcard permissions found",
            "severity": "CRITICAL" if wildcard else "INFO",
            "category": "EXCESSIVE_PERMISSIONS",
            "evidence": {"wildcard_permissions": wildcard},
            "status": "OPEN" if wildcard else "RESOLVED",
        })

        old_keys = get_old_access_keys(username)
        findings.append({
            "resource_id": username,
            "resource_type": "iam_user",
            "finding": f"{len(old_keys)} access key(s) older than 90 days" if old_keys else "No old access keys",
            "severity": "MEDIUM" if old_keys else "INFO",
            "category": "CREDENTIAL_HYGIENE",
            "evidence": {"old_keys": old_keys},
            "status": "OPEN" if old_keys else "RESOLVED",
        })

    return findings
