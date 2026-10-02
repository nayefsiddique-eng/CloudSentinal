"""Real AWS inventory + security scan.
Uses boto3's normal credential chain and scans global services once plus
regional services in every enabled AWS region the caller can access.
"""
import json
import hashlib
from typing import Any

from botocore.exceptions import ClientError, BotoCoreError

from backend.services.aws.client import (
    get_client,
    get_regions,
    get_account_context,
)


def _fid(service: str, resource_id: str, finding: str) -> str:
    raw = f"{service}|{resource_id}|{finding}".encode()
    return hashlib.sha256(raw).hexdigest()[:20]


def _finding(service, resource_id, resource_type, resource_name, region,
             finding, severity, category, evidence, status):
    return {
        "finding_id": _fid(service, resource_id, finding),
        "resource_id": resource_id,
        "resource_name": resource_name or resource_id,
        "resource_type": resource_type,
        "region": region,
        "service": service,
        "finding": finding,
        "severity": severity,
        "category": category,
        "evidence": evidence or {},
        "status": status,
    }


def _error(service, error, region=None):
    label = service if not region else f"{service}[{region}]"
    return {"scanner": label, "error": str(error)}


def _account_arn(account_id: str) -> str:
    return f"arn:aws:iam::{account_id}:root"


def _scan_s3(account_id: str):
    findings, resources, errors = [], [], []
    s3 = get_client("s3", region="us-east-1")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as exc:
        return [], [], [_error("s3", exc)]

    for b in buckets:
        name = b["Name"]
        arn = f"arn:aws:s3:::{name}"
        region = "us-east-1"
        try:
            loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
            region = loc or "us-east-1"
            if region == "EU":
                region = "eu-west-1"
        except Exception as exc:
            errors.append(_error("s3-location", exc, name))

        resources.append({"resource_id": arn, "resource_type": "s3_bucket",
                          "resource_name": name, "region": region, "service": "s3"})
        regional = get_client("s3", region=region)

        try:
            pab = regional.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            block_enabled = all(pab.get(k, False) for k in (
                "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
        except ClientError as exc:
            block_enabled = False if exc.response.get("Error", {}).get("Code") in {
                "NoSuchPublicAccessBlockConfiguration", "AccessDenied", "MethodNotAllowed"
            } else False
        findings.append(_finding("s3", arn, "s3_bucket", name, region,
            "Block Public Access is disabled" if not block_enabled else "Block Public Access is enabled",
            "HIGH" if not block_enabled else "INFO", "PUBLIC_ACCESS",
            {"block_public_access_enabled": block_enabled}, "OPEN" if not block_enabled else "RESOLVED"))

        try:
            acl = regional.get_bucket_acl(Bucket=name)
            public = any("AllUsers" in g.get("Grantee", {}).get("URI", "") or
                         "AuthenticatedUsers" in g.get("Grantee", {}).get("URI", "")
                         for g in acl.get("Grants", []))
        except Exception as exc:
            public = False
            errors.append(_error("s3-acl", exc, name))
        findings.append(_finding("s3", arn, "s3_bucket", name, region,
            "Bucket is publicly accessible" if public else "Bucket is not public",
            "HIGH" if public else "INFO", "PUBLIC_ACCESS", {"public": public},
            "OPEN" if public else "RESOLVED"))

        try:
            versioning = regional.get_bucket_versioning(Bucket=name).get("Status") == "Enabled"
        except Exception as exc:
            versioning = False
            errors.append(_error("s3-versioning", exc, name))
        findings.append(_finding("s3", arn, "s3_bucket", name, region,
            "Versioning is disabled" if not versioning else "Versioning is enabled",
            "MEDIUM" if not versioning else "INFO", "DATA_PROTECTION",
            {"versioning_enabled": versioning}, "OPEN" if not versioning else "RESOLVED"))

        try:
            enc = regional.get_bucket_encryption(Bucket=name)
            encrypted = bool(enc.get("ServerSideEncryptionConfiguration", {}).get("Rules"))
        except ClientError:
            encrypted = False
        except Exception as exc:
            encrypted = False
            errors.append(_error("s3-encryption", exc, name))
        findings.append(_finding("s3", arn, "s3_bucket", name, region,
            "Encryption is disabled" if not encrypted else "Encryption is enabled",
            "MEDIUM" if not encrypted else "INFO", "DATA_PROTECTION",
            {"encryption_enabled": encrypted}, "OPEN" if not encrypted else "RESOLVED"))

    return findings, resources, errors


def _scan_iam(account_id: str):
    findings, resources, errors = [], [], []
    iam = get_client("iam", region="us-east-1")
    root_arn = _account_arn(account_id)
    resources.append({"resource_id": root_arn, "resource_type": "iam_account",
                      "resource_name": f"AWS Account {account_id}", "region": None, "service": "iam"})
    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
        root_mfa = summary.get("AccountMFAEnabled", 0) == 1
        findings.append(_finding("iam", root_arn, "iam_account", f"AWS Account {account_id}", None,
            "Root account MFA is not enabled" if not root_mfa else "Root account MFA is enabled",
            "CRITICAL" if not root_mfa else "INFO", "IDENTITY_SECURITY",
            {"root_mfa_enabled": root_mfa}, "OPEN" if not root_mfa else "RESOLVED"))
    except Exception as exc:
        errors.append(_error("iam-account", exc))

    try:
        try:
            policy = iam.get_account_password_policy().get("PasswordPolicy", {})
            issues = []
            if policy.get("MinimumPasswordLength", 0) < 14: issues.append("minimum length below 14")
            if not policy.get("RequireSymbols", False): issues.append("symbols not required")
            if not policy.get("RequireNumbers", False): issues.append("numbers not required")
            if not policy.get("RequireUppercaseCharacters", False): issues.append("uppercase not required")
            if not policy.get("RequireLowercaseCharacters", False): issues.append("lowercase not required")
            reason = ", ".join(issues) if issues else "policy meets baseline"
            weak = bool(issues)
        except iam.exceptions.NoSuchEntityException:
            weak, reason = True, "No password policy set"
        findings.append(_finding("iam", root_arn, "iam_account", f"AWS Account {account_id}", None,
            f"Weak password policy ({reason})" if weak else "Password policy meets baseline",
            "MEDIUM" if weak else "INFO", "IDENTITY_SECURITY",
            {"weak": weak, "reason": reason}, "OPEN" if weak else "RESOLVED"))
    except Exception as exc:
        errors.append(_error("iam-password-policy", exc))

    try:
        paginator = iam.get_paginator("list_users")
        users = [u for page in paginator.paginate() for u in page.get("Users", [])]
    except Exception as exc:
        return findings, resources, errors + [_error("iam-users", exc)]

    now = get_account_context()["now"]
    for user in users:
        username = user["UserName"]
        arn = user.get("Arn") or f"arn:aws:iam::{account_id}:user/{username}"
        resources.append({"resource_id": arn, "resource_type": "iam_user",
                          "resource_name": username, "region": None, "service": "iam"})
        try:
            mfa = bool(iam.list_mfa_devices(UserName=username).get("MFADevices"))
            findings.append(_finding("iam", arn, "iam_user", username, None,
                "MFA is not enabled" if not mfa else "MFA is enabled",
                "HIGH" if not mfa else "INFO", "IDENTITY_SECURITY",
                {"mfa_enabled": mfa}, "OPEN" if not mfa else "RESOLVED"))
        except Exception as exc:
            errors.append(_error("iam-mfa", exc, username))

        try:
            wildcard = False
            attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
            for policy in attached:
                p = iam.get_policy(PolicyArn=policy["PolicyArn"])["Policy"]
                doc = iam.get_policy_version(PolicyArn=policy["PolicyArn"], VersionId=p["DefaultVersionId"])["PolicyVersion"]["Document"]
                if _policy_wildcard(doc):
                    wildcard = True; break
            if not wildcard:
                for pname in iam.list_user_policies(UserName=username).get("PolicyNames", []):
                    doc = iam.get_user_policy(UserName=username, PolicyName=pname)["PolicyDocument"]
                    if _policy_wildcard(doc): wildcard = True; break
            findings.append(_finding("iam", arn, "iam_user", username, None,
                "User has wildcard (Action:* Resource:*) permissions" if wildcard else "No wildcard permissions found",
                "CRITICAL" if wildcard else "INFO", "EXCESSIVE_PERMISSIONS",
                {"wildcard_permissions": wildcard}, "OPEN" if wildcard else "RESOLVED"))
        except Exception as exc:
            errors.append(_error("iam-policies", exc, username))

        try:
            old = []
            for key in iam.list_access_keys(UserName=username).get("AccessKeyMetadata", []):
                age = (now - key["CreateDate"]).days
                if age > 90:
                    old.append({"access_key_id": key["AccessKeyId"], "age_days": age, "status": key["Status"]})
            findings.append(_finding("iam", arn, "iam_user", username, None,
                f"{len(old)} access key(s) older than 90 days" if old else "No old access keys",
                "MEDIUM" if old else "INFO", "CREDENTIAL_HYGIENE",
                {"old_keys": old}, "OPEN" if old else "RESOLVED"))
        except Exception as exc:
            errors.append(_error("iam-access-keys", exc, username))

    return findings, resources, errors


def _policy_wildcard(doc: dict) -> bool:
    statements = doc.get("Statement", [])
    if isinstance(statements, dict): statements = [statements]
    for st in statements:
        if st.get("Effect") != "Allow": continue
        actions = st.get("Action", [])
        resources = st.get("Resource", [])
        if isinstance(actions, str): actions = [actions]
        if isinstance(resources, str): resources = [resources]
        if "*" in actions and "*" in resources: return True
    return False


def _scan_ec2(region: str, account_id: str):
    findings, resources, errors = [], [], []
    ec2 = get_client("ec2", region=region)
    try:
        groups = ec2.describe_security_groups().get("SecurityGroups", [])
    except Exception as exc:
        return [], [], [_error("ec2-security-groups", exc, region)]
    for sg in groups:
        gid = sg["GroupId"]
        arn = f"arn:aws:ec2:{region}:{account_id}:security-group/{gid}"
        name = sg.get("GroupName", gid)
        resources.append({"resource_id": arn, "resource_type": "security_group", "resource_name": name, "region": region, "service": "ec2"})
        risky = []
        unrestricted = False
        for p in sg.get("IpPermissions", []):
            proto = p.get("IpProtocol")
            fp = p.get("FromPort")
            tp = p.get("ToPort")
            for r in p.get("IpRanges", []):
                if r.get("CidrIp") != "0.0.0.0/0": continue
                if proto == "-1" or fp is None:
                    unrestricted = True
                if fp is not None and tp is not None:
                    for port, svc in ((22, "SSH"), (3389, "RDP")):
                        if fp <= port <= tp: risky.append({"port": port, "service": svc})
        findings.append(_finding("ec2", arn, "security_group", name, region,
            f"{', '.join(p['service'] for p in risky)} exposed to the internet (0.0.0.0/0)" if risky else "No risky ports exposed to the internet",
            "CRITICAL" if risky else "INFO", "NETWORK_SECURITY", {"group_name": name, "open_ports": risky}, "OPEN" if risky else "RESOLVED"))
        findings.append(_finding("ec2", arn, "security_group", name, region,
            "All ports/protocols open to the internet" if unrestricted else "No unrestricted inbound rule found",
            "CRITICAL" if unrestricted else "INFO", "NETWORK_SECURITY", {"group_name": name, "unrestricted_inbound": unrestricted}, "OPEN" if unrestricted else "RESOLVED"))
    return findings, resources, errors


def _scan_lambda(region: str, account_id: str):
    findings, resources, errors = [], [], []
    lam = get_client("lambda", region=region)
    try:
        paginator = lam.get_paginator("list_functions")
        functions = [f for page in paginator.paginate() for f in page.get("Functions", [])]
    except Exception as exc:
        return [], [], [_error("lambda", exc, region)]
    iam = get_client("iam", region="us-east-1")
    for fn in functions:
        name = fn["FunctionName"]
        arn = fn.get("FunctionArn") or f"arn:aws:lambda:{region}:{account_id}:function:{name}"
        resources.append({"resource_id": arn, "resource_type": "lambda_function", "resource_name": name, "region": region, "service": "lambda"})
        role = fn.get("Role", "")
        excessive = False
        if role:
            try:
                role_name = role.split("/")[-1]
                for policy in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
                    if policy["PolicyArn"].endswith(("AdministratorAccess", "PowerUserAccess")):
                        excessive = True; break
                    p = iam.get_policy(PolicyArn=policy["PolicyArn"])["Policy"]
                    doc = iam.get_policy_version(PolicyArn=policy["PolicyArn"], VersionId=p["DefaultVersionId"])["PolicyVersion"]["Document"]
                    if _policy_wildcard(doc): excessive = True; break
            except Exception as exc:
                errors.append(_error("lambda-role-policy", exc, name))
        findings.append(_finding("lambda", arn, "lambda_function", name, region,
            "Execution role has excessive permissions" if excessive else "Execution role permissions look scoped",
            "CRITICAL" if excessive else "INFO", "EXCESSIVE_PERMISSIONS", {"role_arn": role, "excessive": excessive}, "OPEN" if excessive else "RESOLVED"))

        public_url = False
        try:
            public_url = lam.get_function_url_config(FunctionName=name).get("AuthType") == "NONE"
        except lam.exceptions.ResourceNotFoundException:
            pass
        except Exception as exc:
            errors.append(_error("lambda-url", exc, name))
        findings.append(_finding("lambda", arn, "lambda_function", name, region,
            "Function URL is publicly invokable (no auth)" if public_url else "No public function URL exposure",
            "HIGH" if public_url else "INFO", "PUBLIC_ACCESS", {"public_url": public_url}, "OPEN" if public_url else "RESOLVED"))

        flagged = []
        try:
            env = lam.get_function_configuration(FunctionName=name).get("Environment", {}).get("Variables", {})
            for key in env:
                if any(x in key.lower() for x in ("secret", "password", "api_key", "token", "access_key")):
                    flagged.append(key)
        except Exception as exc:
            errors.append(_error("lambda-environment", exc, name))
        findings.append(_finding("lambda", arn, "lambda_function", name, region,
            f"Possible secrets in environment variables: {flagged}" if flagged else "No suspicious environment variable names found",
            "HIGH" if flagged else "INFO", "CREDENTIAL_HYGIENE", {"flagged_keys": flagged}, "OPEN" if flagged else "RESOLVED"))

        encrypted = bool(fn.get("KMSKeyArn"))
        findings.append(_finding("lambda", arn, "lambda_function", name, region,
            "Environment variables are not encrypted with a customer KMS key" if not encrypted else "Environment variables encrypted with customer KMS key",
            "LOW" if not encrypted else "INFO", "DATA_PROTECTION", {"kms_encrypted": encrypted}, "OPEN" if not encrypted else "RESOLVED"))
    return findings, resources, errors


def _scan_cloudtrail(region: str, account_id: str):
    findings, resources, errors = [], [], []
    ct = get_client("cloudtrail", region=region)
    try:
        trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
    except Exception as exc:
        return [], [], [_error("cloudtrail", exc, region)]
    seen = set()
    for trail in trails:
        arn = trail.get("TrailARN") or trail.get("Name")
        if arn in seen: continue
        seen.add(arn)
        name = trail.get("Name", arn)

        # CloudTrail trail metadata can be returned while scanning another
        # region. Prefer the trail's HomeRegion and ARN region.
        arn_parts = str(arn).split(":")
        arn_region = arn_parts[3] if len(arn_parts) > 3 and arn_parts[3] else None
        trail_region = trail.get("HomeRegion") or arn_region or region

        resources.append({
            "resource_id": arn,
            "resource_type": "cloudtrail",
            "resource_name": name,
            "region": trail_region,
            "service": "cloudtrail"
        })
        try:
            logging = ct.get_trail_status(Name=arn).get("IsLogging", False)
        except Exception as exc:
            errors.append(_error("cloudtrail-status", exc, name)); continue
        findings.append(_finding("cloudtrail", arn, "cloudtrail", name, trail_region,
            "CloudTrail logging is disabled" if not logging else "CloudTrail logging is enabled",
            "HIGH" if not logging else "INFO", "LOGGING_MONITORING", {"logging_enabled": logging}, "OPEN" if not logging else "RESOLVED"))
    if not trails:
        arn = f"arn:aws:cloudtrail:{region}:{account_id}:trail/none"
        findings.append(_finding("cloudtrail", arn, "cloudtrail", "CloudTrail", region,
            "No CloudTrail trails configured in this region", "CRITICAL", "LOGGING_MONITORING", {"trail_count": 0}, "OPEN"))
    return findings, resources, errors


def discover_tagged_resources(regions):
    """Broad inventory across AWS services that expose Resource Groups Tagging API."""
    resources, errors = [], []
    for region in regions:
        try:
            tagging = get_client("resourcegroupstaggingapi", region=region)
            paginator = tagging.get_paginator("get_resources")
            for page in paginator.paginate(ResourcesPerPage=100):
                for item in page.get("ResourceTagMappingList", []):
                    arn = item.get("ResourceARN")
                    if not arn: continue
                    parts = arn.split(":")
                    service = parts[2] if len(parts) > 2 else "unknown"
                    resources.append({
                        "resource_id": arn,
                        "resource_type": f"{service}_resource",
                        "resource_name": arn.split("/")[-1].split(":")[-1],
                        "region": region,
                        "service": service,
                        "tags": {t.get("Key"): t.get("Value") for t in item.get("Tags", [])},
                    })
        except Exception as exc:
            errors.append(_error("resourcegroupstaggingapi", exc, region))
    return resources, errors


def discover_resource_explorer(regions):
    """Use AWS Resource Explorer 2 when an account has it enabled.
    Unlike the tagging API, Resource Explorer can discover untagged resources too.
    It is optional, so AccessDenied/NotFound is reported as a non-fatal inventory error.
    """
    resources, errors = [], []
    seen = set()
    for region in regions:
        try:
            rex = get_client("resource-explorer-2", region=region)
            token = None
            while True:
                kwargs = {"QueryString": "*", "MaxResults": 1000}
                if token:
                    kwargs["NextToken"] = token
                response = rex.list_resources(**kwargs)
                for item in response.get("Resources", []):
                    arn = item.get("Arn")
                    if not arn or arn in seen:
                        continue
                    seen.add(arn)
                    parts = arn.split(":")
                    service = parts[2] if len(parts) > 2 else "unknown"
                    resources.append({
                        "resource_id": arn,
                        "resource_type": f"{service}_resource",
                        "resource_name": arn.split("/")[-1].split(":")[-1],
                        "region": item.get("Region") or region,
                        "service": service,
                    })
                token = response.get("NextToken")
                if not token:
                    break
        except Exception as exc:
            errors.append(_error("resource-explorer-2", exc, region))
    return resources, errors


def run_real_aws_scan():
    context = get_account_context()
    account_id = context["account_id"]
    regions = get_regions()
    findings, resources, errors = [], [], []

    f, r, e = _scan_s3(account_id); findings += f; resources += r; errors += e
    f, r, e = _scan_iam(account_id); findings += f; resources += r; errors += e

    for region in regions:
        for scanner in (_scan_ec2, _scan_lambda, _scan_cloudtrail):
            try:
                f, r, e = scanner(region, account_id)
                findings += f; resources += r; errors += e
            except Exception as exc:
                errors.append(_error(scanner.__name__, exc, region))

    explored, explorer_errors = discover_resource_explorer(regions)
    resources.extend(explored)
    errors.extend(explorer_errors)

    tagged, tagged_errors = discover_tagged_resources(regions)
    resources.extend(tagged)
    errors.extend(tagged_errors)

    # Deduplicate inventory by ARN and findings by finding_id.
    unique_resources = {r["resource_id"]: r for r in resources if r.get("resource_id")}
    unique_findings = {f["finding_id"]: f for f in findings if f.get("finding_id")}
    findings = list(unique_findings.values())
    resources = list(unique_resources.values())

    severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        severity[f.get("severity", "INFO")] = severity.get(f.get("severity", "INFO"), 0) + 1

    return {
        "account_id": account_id,
        "regions": regions,
        "service_count": len(set(r.get("service") for r in resources if r.get("service"))),
        "resource_count": len(resources),
        "total_findings": len(findings),
        "severity_summary": severity,
        "findings": findings,
        "resources": resources,
        "errors": errors,
    }

