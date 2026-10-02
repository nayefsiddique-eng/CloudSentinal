"""
Test script for enhanced AI and remediation components
Tests the core logic without requiring AWS connections
"""

import sys
import os

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

def test_ai_analysis_service():
    """Test the AI analysis service with template fallback."""
    print("Testing AI Analysis Service...")

    try:
        from backend.services.ai.analysis_service import AnalysisService

        # Initialize service (will fall back to template since no API keys)
        ai_service = AnalysisService()

        # Test finding
        finding = {
            "finding_id": "test123",
            "resource_id": "test-bucket",
            "resource_type": "s3_bucket",
            "finding": "Bucket is publicly accessible",
            "severity": "HIGH",
            "category": "PUBLIC_ACCESS",
            "evidence": {"public": True},
            "status": "OPEN"
        }

        # Analyze finding
        analysis = ai_service.analyze_finding(finding)

        # Validate required fields
        required_fields = ["severity", "risk_score", "explanation", "impact",
                         "attack_scenario", "recommendation", "confidence"]
        for field in required_fields:
            assert field in analysis, f"Missing field: {field}"
            assert analysis[field] is not None, f"Field {field} is None"

        print("  PASS: AI analysis service working correctly")
        print(f"    Severity: {analysis['severity']}")
        print(f"    Risk Score: {analysis['risk_score']}")
        print(f"    Confidence: {analysis['confidence']}")
        return True

    except Exception as e:
        print(f"  FAIL: AI analysis service failed: {e}")
        return False


def test_risk_engine():
    """Test the risk engine."""
    print("Testing Risk Engine...")

    try:
        from backend.services.risk_engine import RiskEngine

        risk_engine = RiskEngine()

        # Test risk calculation
        result = risk_engine.calculate_risk_score(
            severity="HIGH",
            exposure="high",
            asset_criticality="medium",
            exploitability="medium",
            detection_confidence="high"
        )

        # Validate result
        assert "risk_score" in result
        assert "risk_level" in result
        assert "priority" in result
        assert "factors" in result

        print("  PASS: Risk engine working correctly")
        print(f"    Risk Score: {result['risk_score']}")
        print(f"    Risk Level: {result['risk_level']}")
        print(f"    Priority: {result['priority']}")
        return True

    except Exception as e:
        print(f"  FAIL: Risk engine failed: {e}")
        return False


def test_safety_gate():
    """Test the safety gate."""
    print("Testing Safety Gate...")

    try:
        from backend.services.safety_gate import SafetyGate

        safety_gate = SafetyGate()

        # Test allowed action
        classification = safety_gate.classify_action(
            "s3_bucket",
            "PUBLIC_ACCESS",
            "block_public_access_disabled"
        )

        assert classification["tier"].value == "automatically_allowed"
        assert classification["allowed"] == True
        assert classification["requires_approval"] == False

        # Test approval required action
        classification2 = safety_gate.classify_action(
            "iam_user",
            "IDENTITY_SECURITY",
            "mfa_disabled"
        )

        assert classification2["tier"].value == "approval_required"
        assert classification2["requires_approval"] == True

        # Test blocked action
        classification3 = safety_gate.classify_action(
            "iam_user",
            "IDENTITY_SECURITY",
            "modify_admin_permissions"
        )

        assert classification3["tier"].value == "automatically_blocked"
        assert classification3["allowed"] == False

        print("  PASS: Safety gate working correctly")
        return True

    except Exception as e:
        print(f"  FAIL: Safety gate failed: {e}")
        return False


def test_integration():
    """Test integration of components."""
    print("Testing Component Integration...")

    try:
        from backend.services.ai.analysis_service import AnalysisService
        from backend.services.risk_engine import RiskEngine
        from backend.services.safety_gate import SafetyGate

        # Initialize services
        ai_service = AnalysisService()
        risk_engine = RiskEngine()
        safety_gate = SafetyGate()

        # Sample finding
        finding = {
            "finding_id": "integration_test",
            "resource_id": "test-bucket",
            "resource_type": "s3_bucket",
            "finding": "Bucket is publicly accessible",
            "severity": "HIGH",
            "category": "PUBLIC_ACCESS",
            "evidence": {"public": True},
            "status": "OPEN"
        }

        # Step 1: AI Analysis
        analysis = ai_service.analyze_finding(finding)
        finding.update(analysis)

        # Step 2: Risk Assessment
        risk_result = risk_engine.enhance_finding_with_risk(finding)
        finding.update(risk_result)

        # Step 3: Safety Gate Classification
        resource_type = finding.get("resource_type")
        category = finding.get("category")
        finding_type = finding.get("finding", "").lower().replace(" ", "_").replace("-", "_")
        safety_class = safety_gate.classify_action(resource_type, category, finding_type)

        finding["safety_classification"] = safety_class["tier"].value
        finding["requires_approval"] = safety_class["requires_approval"]
        from backend.services.safety_gate import ActionTier
        finding["automatically_allowed"] = (
            safety_class["tier"] == ActionTier.AUTOMATICALLY_ALLOWED
        )

        # Validate integrated result
        assert "explanation" in finding
        assert "risk_score" in finding
        assert "safety_classification" in finding

        print("  PASS: Component integration working correctly")
        print(f"    AI Explanation: {finding['explanation'][:50]}...")
        print(f"    Risk Score: {finding['risk_score']}")
        print(f"    Safety Classification: {finding['safety_classification']}")
        return True

    except Exception as e:
        print(f"  FAIL: Component integration failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("Testing Enhanced AI and Remediation Components")
    print("=" * 50)

    tests = [
        test_ai_analysis_service,
        test_risk_engine,
        test_safety_gate,
        test_integration
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1
        print()

    print("=" * 50)
    print(f"Results: {passed}/{total} tests passed")

    if passed == total:
        print("PASS: All tests passed! Enhanced components are working correctly.")
        return 0
    else:
        print("FAIL: Some tests failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())