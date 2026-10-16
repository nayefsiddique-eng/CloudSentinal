"""
Demonstration of Enhanced AI and Remediation System for CloudSentinel
Shows how the AI analysis, risk engine, safety gate, remediation, and verification components work together.
"""

import json
from backend.services.ai.analysis_service import AnalysisService
from backend.services.risk_engine import RiskEngine
from backend.services.safety_gate import SafetyGate
from backend.services.remediation_engine import remediation_engine
from backend.services.verification_engine import verification_engine


def demonstrate_ai_analysis():
    """Demonstrate the AI analysis engine."""
    print("=" * 60)
    print("AI ANALYSIS ENGINE DEMONSTRATION")
    print("=" * 60)

    # Sample finding from S3 scanner
    sample_finding = {
        "finding_id": "abc123def456",
        "resource_id": "my-public-bucket",
        "resource_type": "s3_bucket",
        "finding": "Bucket is publicly accessible",
        "severity": "HIGH",
        "category": "PUBLIC_ACCESS",
        "evidence": {"public": True, "acl_grants": [{"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}]},
        "status": "OPEN"
    }

    # Context for analysis
    aws_config = {"service": "s3", "region": "us-east-1"}
    security_rule = {"rule_id": "S3-PUBLIC-ACCESS", "description": "S3 buckets should not be publicly accessible"}
    resource_context = {"tags": {"Environment": "production", "Team": "data"}, "creation_date": "2024-01-15"}

    # Initialize AI analysis service
    ai_analyzer = AnalysisService()

    # Perform AI analysis
    print("Analyzing finding:")
    print(f"  Resource: {sample_finding['resource_id']} ({sample_finding['resource_type']})")
    print(f"  Issue: {sample_finding['finding']}")
    print(f"  Severity: {sample_finding['severity']}")
    print()

    analysis = ai_analyzer.analyze_finding(
        sample_finding,
        aws_config=aws_config,
        security_rule=security_rule,
        resource_context=resource_context
    )

    print("AI Analysis Results:")
    print(f"  Severity: {analysis['severity']}")
    print(f"  Risk Score: {analysis['risk_score']}/10.0")
    print(f"  Explanation: {analysis['explanation']}")
    print(f"  Impact: {analysis['impact']}")
    print(f"  Attack Scenario: {analysis['attack_scenario']}")
    print(f"  Recommendation: {analysis['recommendation']}")
    print(f"  Confidence: {analysis['confidence']}")
    print()

    # Return the finding with analysis added for next steps
    sample_finding.update(analysis)
    return sample_finding


def demonstrate_risk_engine(finding):
    """Demonstrate the risk engine."""
    print("=" * 60)
    print("RISK ENGINE DEMONSTRATION")
    print("=" * 60)

    # Initialize risk engine
    risk_engine = RiskEngine()

    # Assess risk factors
    print("Assessing risk factors:")

    exposure = risk_engine.assess_exposure(finding)
    print(f"  Exposure Level: {exposure}")

    asset_criticality = risk_engine.assess_asset_criticality(
        finding.get("resource_id", ""),
        finding.get("resource_type", ""),
        {"Environment": "production", "Team": "data"}  # Sample tags
    )
    print(f"  Asset Criticality: {asset_criticality}")

    exploitability = risk_engine.assess_exploitability(finding)
    print(f"  Exploitability: {exploitability}")

    detection_confidence = risk_engine.assess_detection_confidence(finding)
    print(f"  Detection Confidence: {detection_confidence}")
    print()

    # Calculate risk score
    risk_result = risk_engine.calculate_risk_score(
        severity=finding.get("severity", "INFO"),
        exposure=exposure,
        asset_criticality=asset_criticality,
        exploitability=exploitability,
        detection_confidence=detection_confidence
    )

    print("Risk Calculation Results:")
    print(f"  Risk Score: {risk_result['risk_score']}/10.0")
    print(f"  Risk Level: {risk_result['risk_level']}")
    print(f"  Priority: {risk_result['priority']}")
    print("  Risk Factors:")
    for factor, value in risk_result['factors'].items():
        if isinstance(value, float):
            print(f"    {factor}: {value:.2f}")
        else:
            print(f"    {factor}: {value}")
    print()

    # Enhance finding with risk assessment
    enhanced_finding = risk_engine.enhance_finding_with_risk(finding)
    return enhanced_finding


def demonstrate_safety_gate(finding):
    """Demonstrate the safety gate."""
    print("=" * 60)
    print("SAFETY/POLICY GATE DEMONSTRATION")
    print("=" * 60)

    # Initialize safety gate
    safety_gate = SafetyGate()

    # Classify the action
    resource_type = finding.get("resource_type", "unknown")
    category = finding.get("category", "unknown")
    # Create a simplified finding type for lookup
    finding_type = finding.get("finding", "").lower().replace(" ", "_").replace("-", "_")

    print(f"Classifying action for:")
    print(f"  Resource Type: {resource_type}")
    print(f"  Category: {category}")
    print(f"  Finding Type: {finding_type}")
    print()

    classification = safety_gate.classify_action(resource_type, category, finding_type)

    print("Safety Gate Classification:")
    print(f"  Tier: {classification['tier'].value}")
    print(f"  Action Allowed: {classification['allowed']}")
    print(f"  Requires Approval: {classification['requires_approval']}")
    print()

    if classification["action_info"]:
        action_info = classification["action_info"]
        print("Action Details:")
        print(f"  Action: {action_info.get('action', 'N/A')}")
        print(f"  Description: {action_info.get('description', 'N/A')}")
        print(f"  Safe: {action_info.get('safe', 'N/A')}")
        if "blocked_reason" in action_info:
            print(f"  Blocked Reason: {action_info['blocked_reason']}")
    print()

    # Add safety classification to finding
    finding["safety_classification"] = classification["tier"].value
    finding["requires_approval"] = classification["requires_approval"]
    from backend.services.safety_gate import ActionTier
    finding["automatically_allowed"] = (
        classification["tier"] == ActionTier.AUTOMATICALLY_ALLOWED
    )
    finding["automatically_blocked"] = (
        classification["tier"] == ActionTier.AUTOMATICALLY_BLOCKED
    )

    return finding


def demonstrate_remediation_engine(finding):
    """Demonstrate the remediation engine."""
    print("=" * 60)
    print("REMEDIATION ENGINE DEMONSTRATION")
    print("=" * 60)

    print("Creating remediation plan:")
    plan = remediation_engine.create_remediation_plan(finding)

    print(f"  Finding ID: {plan['finding_id']}")
    print(f"  Resource: {plan['resource_id']} ({plan['resource_type']})")
    print(f"  Issue: {plan['finding']}")
    print(f"  Severity: {plan['severity']}")
    print(f"  Risk Score: {plan.get('risk_score', 'N/A')}")
    print(f"  Safety Classification: {plan.get('safety_classification', 'N/A')}")
    print(f"  Requires Approval: {plan['requires_approval']}")
    print(f"  Automatically Allowed: {plan['automatically_allowed']}")
    print(f"  Recommended Action: {plan['recommended_action']}")
    print()

    # For demonstration, let's simulate what would happen if we executed it
    # In reality, this would require AWS credentials and proper confirmation
    print("Note: Actual execution would require:")
    print("  1. Valid AWS credentials")
    print("  2. Confirmation flag (confirm=True)")
    print("  3. Approval if required (approved_by parameter)")
    print("  4. Network access to AWS APIs")
    print()

    # Show what a safe execution would look like
    if plan["automatically_allowed"] and not plan["requires_approval"]:
        print("This action is automatically allowed and could be executed immediately")
        print("with confirm=True parameter.")
    elif plan["requires_approval"]:
        print("This action requires human approval before execution.")
        print("Would need to provide approved_by parameter and confirm=True.")
    else:
        print("This action is automatically blocked and cannot be executed.")

    print()
    return plan


def demonstrate_verification_engine(original_finding, remediation_plan):
    """Demonstrate the verification engine."""
    print("=" * 60)
    print("VERIFICATION ENGINE DEMONSTRATION")
    print("=" * 60)

    print("Verifying remediation effectiveness:")
    print("  Process: Apply fix -> re-scan -> compare -> confirm resolved")
    print()

    # In a real scenario, we would have actual remediation results
    # For demonstration, we'll show what the verification would look like

    verification_result = {
        "status": "passed",
        "message": "Remediation verified successful - original finding no longer detected",
        "timestamp": "2024-01-20T10:30:00Z",
        "duration_seconds": 45.2,
        "verified": True,
        "details": {
            "resource_id": original_finding.get("resource_id"),
            "resource_type": original_finding.get("resource_type"),
            "original_finding_id": original_finding.get("finding_id"),
            "verification_method": "re_scan_and_compare",
            "findings_after_remediation": 0  # No findings of this type after remediation
        }
    }

    print("Verification Results:")
    print(f"  Status: {verification_result['status']}")
    print(f"  Message: {verification_result['message']}")
    print(f"  Verified: {verification_result['verified']}")
    print(f"  Duration: {verification_result['duration_seconds']} seconds")
    print(f"  Timestamp: {verification_result['timestamp']}")
    print()

    if verification_result["details"]:
        details = verification_result["details"]
        print("Verification Details:")
        for key, value in details.items():
            print(f"  {key}: {value}")
    print()

    return verification_result


def main():
    """Run the complete demonstration."""
    print("CloudSentinel Enhanced AI and Remediation System")
    print("================================================")
    print("This demonstration shows how the enhanced AI and remediation")
    print("components work together to provide intelligent security")
    print("analysis and automated remediation with safety guarantees.")
    print()

    try:
        # Step 1: AI Analysis
        finding_with_ai = demonstrate_ai_analysis()

        # Step 2: Risk Assessment
        finding_with_risk = demonstrate_risk_engine(finding_with_ai)

        # Step 3: Safety Gate
        finding_with_safety = demonstrate_safety_gate(finding_with_risk)

        # Step 4: Remediation Planning
        remediation_plan = demonstrate_remediation_engine(finding_with_safety)

        # Step 5: Verification (would happen after actual remediation)
        print("Note: Verification would occur after actual remediation execution")
        print("For demonstration, we'll show what verification would look like:")
        verification_result = demonstrate_verification_engine(
            finding_with_safety,
            remediation_plan
        )

        # Summary
        print("=" * 60)
        print("DEMONSTRATION COMPLETE")
        print("=" * 60)
        print("Enhanced AI and Remediation Pipeline:")
        print("  1. Finding -> AI Analysis -> Risk Assessment -> Safety Gate")
        print("  2. Remediation Planning -> Execution -> Verification")
        print()
        print("Key Enhancements:")
        print("  • AI Analysis: Structured JSON output with explanations, impact, scenarios")
        print("  • Risk Engine: Deterministic scoring (Severity × Exposure × Criticality × Exploitability × Detection Confidence)")
        print("  • Safety Gate: Three-tier system (Auto-allowed, Approval-required, Auto-blocked)")
        print("  • Remediation Engine: Audit trails, rollback capabilities, execution tracking")
        print("  • Verification Engine: Re-scan comparison to confirm fixes work")
        print()
        print("The system provides intelligent, secure, and verifiable")
        print("cloud security remediation with appropriate safety controls.")

    except Exception as e:
        print(f"Error during demonstration: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()