from backend.services.aws.real_scan import run_real_aws_scan
from backend.services.ai.analysis_service import AnalysisService
from backend.services.risk_engine import RiskEngine
from backend.services.safety_gate import SafetyGate, ActionTier
from backend.services.finding_quality import normalize_finding


def run_full_scan() -> dict:
    """Run the real multi-region AWS inventory/security scan."""
    try:
        result = run_real_aws_scan()
    except Exception as exc:
        return {
            "total_findings": 0,
            "severity_summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "findings": [],
            "resources": [],
            "errors": [{"scanner": "aws-connection", "error": str(exc)}],
        }

    ai_analyzer = AnalysisService()
    risk_engine = RiskEngine()
    safety_gate = SafetyGate()

    for finding in result["findings"]:
        service = finding.get("service", "aws")
        aws_config = {
            "service": service,
            "region": finding.get("region"),
            "account_id": result.get("account_id"),
        }
        resource_context = {
            "resource_type": finding.get("resource_type"),
            "resource_name": finding.get("resource_name"),
            "region": finding.get("region"),
            "evidence": finding.get("evidence", {}),
        }
        try:
            finding.update(ai_analyzer.analyze_finding(
                finding, aws_config, {"scanner": service}, resource_context
            ))
        except Exception as exc:
            result["errors"].append({"scanner": f"ai[{service}]", "error": str(exc)})

        try:
            finding.update(risk_engine.enhance_finding_with_risk(
                finding, aws_config=aws_config, resource_tags={}
            ))
        except Exception as exc:
            result["errors"].append({"scanner": f"risk[{service}]", "error": str(exc)})

        try:
            resource_type = finding.get("resource_type", "unknown")
            category = finding.get("category", "unknown")
            finding_type = finding.get("finding", "").lower().replace(" ", "_").replace("-", "_")
            cls = safety_gate.classify_action(resource_type, category, finding_type)
            finding["safety_classification"] = cls["tier"].value
            finding["requires_approval"] = cls["requires_approval"]
            finding["automatically_allowed"] = cls["tier"] == ActionTier.AUTOMATICALLY_ALLOWED
            finding["automatically_blocked"] = cls["tier"] == ActionTier.AUTOMATICALLY_BLOCKED
        except Exception as exc:
            result["errors"].append({"scanner": f"safety[{service}]", "error": str(exc)})

    # Final deterministic consistency pass.
    # Scanner evidence is authoritative; AI explanations must not contradict it.
    for finding in result["findings"]:
        finding.update(normalize_finding(finding))

    # Recalculate after AI/risk/quality processing.
    severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding in result["findings"]:
        severity[finding.get("severity", "INFO")] = severity.get(finding.get("severity", "INFO"), 0) + 1
    result["severity_summary"] = severity
    result["total_findings"] = len(result["findings"])
    return result

