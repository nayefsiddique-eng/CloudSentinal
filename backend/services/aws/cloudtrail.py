from backend.services.aws.client import get_client


def list_trails() -> list:
    ct = get_client("cloudtrail")
    response = ct.describe_trails()
    return response.get("trailList", [])


def is_trail_logging(trail_name: str) -> bool:
    ct = get_client("cloudtrail")
    status = ct.get_trail_status(Name=trail_name)
    return status.get("IsLogging", False)


def scan_cloudtrail() -> list:
    findings = []
    trails = list_trails()

    if not trails:
        findings.append({
            "resource_id": "account",
            "resource_type": "cloudtrail",
            "finding": "No CloudTrail trails configured",
            "severity": "CRITICAL",
            "category": "LOGGING_MONITORING",
            "evidence": {"trail_count": 0},
            "status": "OPEN",
        })
        return findings

    for trail in trails:
        name = trail["Name"]
        logging_enabled = is_trail_logging(name)
        findings.append({
            "resource_id": name,
            "resource_type": "cloudtrail",
            "finding": "CloudTrail logging is disabled" if not logging_enabled else "CloudTrail logging is enabled",
            "severity": "HIGH" if not logging_enabled else "INFO",
            "category": "LOGGING_MONITORING",
            "evidence": {"logging_enabled": logging_enabled},
            "status": "OPEN" if not logging_enabled else "RESOLVED",
        })

    return findings
