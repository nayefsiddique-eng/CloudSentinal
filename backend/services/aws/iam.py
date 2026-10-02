import json
from datetime import datetime, timezone
from backend.services.aws.client import get_client


def list_users() -> list:
    iam = get_client("iam")
    users = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        users.extend(u["UserName"] for u in page.get("Users", []))
    return users


def has_mfa_enabled(username: str) -> bool:
    iam = get_client("iam")
    response = iam.list_mfa_devices(UserName=username)
    return len(response.get("MFADevices", [])) > 0


def root_account_has_mfa() -> bool:
    iam = get_client("iam")
    summary = iam.get_account_summary()
    return summary.get("SummaryMap", {}).get("AccountMFAEnabled", 0) == 1


def has_weak_password_policy() -> dict:
    iam = get_client("iam")
    try:
        policy = iam.get_account_password_policy().get("PasswordPolicy", {})
    except iam.exceptions.NoSuchEntityException:
        return {"weak": True, "reason": "No password policy set"}

    issues = []
    if policy.get("MinimumPasswordLength", 0) < 14:
        issues.append("minimum length below 14")
    if not policy.get("RequireSymbols", False):
        issues.append("symbols not required")
    if not policy.get("RequireNumbers", False):
        issues.append("numbers not required")
    if not policy.get("RequireUppercaseCharacters", False):
        issues.append("uppercase not required")
    if not policy.get("RequireLowercaseCharacters", False):
        issues.append("lowercase not required")

    return {"weak": len(issues) > 0, "reason": ", ".join(issues) if issues else "policy meets baseline"}


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

    root_mfa = root_account_has_mfa()
    findings.append({
        "resource_id": "root",
        "resource_type": "iam_account",
        "finding": "Root account MFA is not enabled" if not root_mfa else "Root account MFA is enabled",
        "severity": "CRITICAL" if not root_mfa else "INFO",
        "category": "IDENTITY_SECURITY",
        "evidence": {"root_mfa_enabled": root_mfa},
        "status": "OPEN" if not root_mfa else "RESOLVED",
    })

    pw_policy = has_weak_password_policy()
    findings.append({
        "resource_id": "account",
        "resource_type": "iam_account",
        "finding": f"Weak password policy ({pw_policy['reason']})" if pw_policy["weak"] else "Password policy meets baseline",
        "severity": "MEDIUM" if pw_policy["weak"] else "INFO",
        "category": "IDENTITY_SECURITY",
        "evidence": pw_policy,
        "status": "OPEN" if pw_policy["weak"] else "RESOLVED",
    })

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
