from backend.services.aws.client import get_client


def list_buckets() -> list:
    s3 = get_client("s3")
    response = s3.list_buckets()
    return [b["Name"] for b in response.get("Buckets", [])]


def get_public_access_block_status(bucket_name: str) -> bool:
    s3 = get_client("s3")
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)
        config = pab["PublicAccessBlockConfiguration"]
        return all(config.values())
    except s3.exceptions.ClientError:
        return False


def is_bucket_public(bucket_name: str) -> bool:
    s3 = get_client("s3")

    if get_public_access_block_status(bucket_name):
        return False

    acl = s3.get_bucket_acl(Bucket=bucket_name)
    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI", "")
        if "AllUsers" in uri or "AuthenticatedUsers" in uri:
            return True

    return False


def is_versioning_enabled(bucket_name: str) -> bool:
    s3 = get_client("s3")
    response = s3.get_bucket_versioning(Bucket=bucket_name)
    return response.get("Status") == "Enabled"


def is_encryption_enabled(bucket_name: str) -> bool:
    s3 = get_client("s3")
    try:
        response = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        return len(rules) > 0
    except s3.exceptions.ClientError:
        return False


def scan_s3_buckets() -> list:
    findings = []
    buckets = list_buckets()

    for bucket_name in buckets:
        block_enabled = get_public_access_block_status(bucket_name)
        findings.append({
            "resource_id": bucket_name,
            "resource_type": "s3_bucket",
            "finding": "Block Public Access is disabled" if not block_enabled else "Block Public Access is enabled",
            "severity": "HIGH" if not block_enabled else "INFO",
            "category": "PUBLIC_ACCESS",
            "evidence": {"block_public_access_enabled": block_enabled},
            "status": "OPEN" if not block_enabled else "RESOLVED",
        })

        public = is_bucket_public(bucket_name)
        findings.append({
            "resource_id": bucket_name,
            "resource_type": "s3_bucket",
            "finding": "Bucket is publicly accessible" if public else "Bucket is not public",
            "severity": "HIGH" if public else "INFO",
            "category": "PUBLIC_ACCESS",
            "evidence": {"public": public},
            "status": "OPEN" if public else "RESOLVED",
        })

        versioning = is_versioning_enabled(bucket_name)
        findings.append({
            "resource_id": bucket_name,
            "resource_type": "s3_bucket",
            "finding": "Versioning is disabled" if not versioning else "Versioning is enabled",
            "severity": "MEDIUM" if not versioning else "INFO",
            "category": "DATA_PROTECTION",
            "evidence": {"versioning_enabled": versioning},
            "status": "OPEN" if not versioning else "RESOLVED",
        })

        encrypted = is_encryption_enabled(bucket_name)
        findings.append({
            "resource_id": bucket_name,
            "resource_type": "s3_bucket",
            "finding": "Encryption is disabled" if not encrypted else "Encryption is enabled",
            "severity": "MEDIUM" if not encrypted else "INFO",
            "category": "DATA_PROTECTION",
            "evidence": {"encryption_enabled": encrypted},
            "status": "OPEN" if not encrypted else "RESOLVED",
        })

    return findings
