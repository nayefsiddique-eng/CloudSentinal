from backend.services.aws.s3 import scan_s3_buckets
from backend.services.aws.iam import scan_iam_users
from backend.services.aws.ec2 import scan_security_groups
from backend.services.aws.cloudtrail import scan_cloudtrail
from backend.services.aws.lambda_scanner import scan_lambda_functions
from backend.services.ai.analysis_service import AnalysisService
from backend.services.risk_engine import RiskEngine
from backend.services.safety_gate import SafetyGate, ActionTier


def run_full_scan() -> dict:
    findings = []
    errors = []

    # Initialize AI analysis service, risk engine, and safety gate
    ai_analyzer = AnalysisService()
    risk_engine = RiskEngine()
    safety_gate = SafetyGate()

    scanners = {
        "s3": scan_s3_buckets,
        "iam": scan_iam_users,
        "ec2": scan_security_groups,
        "cloudtrail": scan_cloudtrail,
        "lambda": scan_lambda_functions,
    }

    for name, scanner_fn in scanners.items():
        try:
            service_findings = scanner_fn()
            # Add AI analysis, risk assessment, and safety gate classification to each finding
            for finding in service_findings:
                # Provide context for analysis
                aws_config = {"service": name}
                security_rule = {"scanner": name}
                resource_context = {"resource_type": finding.get("resource_type", "unknown")}

                # AI Analysis
                analysis = ai_analyzer.analyze_finding(finding, aws_config, security_rule, resource_context)
                finding.update(analysis)

                # Risk Assessment
                enhanced_finding = risk_engine.enhance_finding_with_risk(
                    finding,
                    aws_config=aws_config,
                    resource_tags={}  # In a real implementation, this would come from AWS resource tags
                )
                # Update finding with risk assessment results
                finding.update(enhanced_finding)

                # Safety Gate Classification
                resource_type = finding.get("resource_type", "unknown")
                category = finding.get("category", "unknown")
                # Create a simplified finding type for safety gate lookup
                finding_type = finding.get("finding", "").lower().replace(" ", "_").replace("-", "_")
                safety_classification = safety_gate.classify_action(resource_type, category, finding_type)
                finding["safety_classification"] = safety_classification["tier"].value
                finding["requires_approval"] = safety_classification["requires_approval"]
                finding["automatically_allowed"] = not safety_classification["requires_approval"] and safety_classification["tier"] == ActionTier.AUTOMATICALLY_ALLOWED
                finding["automatically_blocked"] = safety_classification["tier"] == ActionTier.AUTOMATICALLY_BLOCKED

            findings.extend(service_findings)
        except Exception as e:
            errors.append({"scanner": name, "error": str(e)})

    # Count findings by severity for summary
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
