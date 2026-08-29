from backend.services.aws.s3 import scan_s3_buckets
from backend.services.aws.iam import scan_iam_users
from backend.services.aws.ec2 import scan_security_groups
from backend.services.aws.cloudtrail import scan_cloudtrail
from backend.services.aws.lambda_scanner import scan_lambda_functions


def run_full_scan() -> dict:
    findings = []
    errors = []

    scanners = {
        "s3": scan_s3_buckets,
        "iam": scan_iam_users,
        "ec2": scan_security_groups,
        "cloudtrail": scan_cloudtrail,
        "lambda": scan_lambda_functions,
    }

    for name, scanner_fn in scanners.items():
        try:
            findings.extend(scanner_fn())
        except Exception as e:
            errors.append({"scanner": name, "error": str(e)})

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "total_findings": len(findings),
        "severity_summary": severity_counts,
        "findings": findings,
        "errors": errors,
    }
