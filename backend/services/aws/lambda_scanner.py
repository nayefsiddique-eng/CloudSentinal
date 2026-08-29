import re
from backend.services.aws.client import get_client

SECRET_PATTERNS = [
    re.compile(r"(?i)secret"),
    re.compile(r"(?i)password"),
    re.compile(r"(?i)api[_-]?key"),
    re.compile(r"(?i)token"),
    re.compile(r"(?i)access[_-]?key"),
]


def list_functions() -> list:
    lam = get_client("lambda")
    functions = []
    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        functions.extend(page.get("Functions", []))
    return functions


def has_excessive_permissions(role_arn: str) -> bool:
    iam = get_client("iam")
    role_name = role_arn.split("/")[-1]

    attached = iam.list_attached_role_policies(RoleName=role_name)
    for policy in attached.get("AttachedPolicies", []):
        policy_arn = policy["PolicyArn"]
        if "AdministratorAccess" in policy_arn or "PowerUserAccess" in policy_arn:
            return True

        policy_info = iam.get_policy(PolicyArn=policy_arn)
        version_id = policy_info["Policy"]["DefaultVersionId"]
        version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        doc = version["PolicyVersion"]["Document"]

        statements = doc.get("Statement", [])
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


def has_public_function_url(function_name: str) -> bool:
    lam = get_client("lambda")
    try:
        url_config = lam.get_function_url_config(FunctionName=function_name)
        auth_type = url_config.get("AuthType", "")
        return auth_type == "NONE"
    except lam.exceptions.ResourceNotFoundException:
        return False


def has_secrets_in_env(function_name: str) -> list:
    lam = get_client("lambda")
    config = lam.get_function_configuration(FunctionName=function_name)
    env_vars = config.get("Environment", {}).get("Variables", {})

    flagged_keys = []
    for key in env_vars.keys():
        for pattern in SECRET_PATTERNS:
            if pattern.search(key):
                flagged_keys.append(key)
                break

    return flagged_keys


def scan_lambda_functions() -> list:
    findings = []
    functions = list_functions()

    for fn in functions:
        name = fn["FunctionName"]
        role_arn = fn.get("Role", "")

        excessive = has_excessive_permissions(role_arn) if role_arn else False
        findings.append({
            "resource_id": name,
            "resource_type": "lambda_function",
            "finding": "Execution role has excessive permissions" if excessive else "Execution role permissions look scoped",
            "severity": "CRITICAL" if excessive else "INFO",
            "category": "EXCESSIVE_PERMISSIONS",
            "evidence": {"role_arn": role_arn, "excessive": excessive},
            "status": "OPEN" if excessive else "RESOLVED",
        })

        public_url = has_public_function_url(name)
        findings.append({
            "resource_id": name,
            "resource_type": "lambda_function",
            "finding": "Function URL is publicly invokable (no auth)" if public_url else "No public function URL exposure",
            "severity": "HIGH" if public_url else "INFO",
            "category": "PUBLIC_ACCESS",
            "evidence": {"public_url": public_url},
            "status": "OPEN" if public_url else "RESOLVED",
        })

        secret_keys = has_secrets_in_env(name)
        findings.append({
            "resource_id": name,
            "resource_type": "lambda_function",
            "finding": f"Possible secrets in environment variables: {secret_keys}" if secret_keys else "No suspicious environment variable names found",
            "severity": "HIGH" if secret_keys else "INFO",
            "category": "CREDENTIAL_HYGIENE",
            "evidence": {"flagged_keys": secret_keys},
            "status": "OPEN" if secret_keys else "RESOLVED",
        })

    return findings
