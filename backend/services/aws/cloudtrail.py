from backend.services.aws.client import get_client


def list_trails() -> list:
    ct = get_client("cloudtrail")
    response = ct.describe_trails()
    return response.get("trailList", [])


def is_trail_logging(trail_arn: str) -> bool:
    ct = get_client("cloudtrail")
    status = ct.get_trail_status(Name=trail_arn)
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
        trail_arn = trail.get("TrailARN", name)

        try:
            logging_enabled = is_trail_logging(trail_arn)
        except Exception as e:
            findings.append({
                "resource_id": name,
                "resource_type": "cloudtrail",
                "finding": f"Could not determine logging status: {e}",
                "severity": "MEDIUM",
                "category": "LOGGING_MONITORING",
                "evidence": {"error": str(e)},
                "status": "OPEN",
            })
            continue

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
