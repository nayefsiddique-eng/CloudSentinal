"""
Verification Engine for CloudSentinel
Verifies that remediation actions were successful by re-scanning and comparing results.
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum
from backend.services.aws.s3 import scan_s3_buckets
from backend.services.aws.iam import scan_iam_users
from backend.services.aws.ec2 import scan_security_groups
from backend.services.aws.cloudtrail import scan_cloudtrail
from backend.services.aws.lambda_scanner import scan_lambda_functions
from backend.services.ai.analysis_service import AnalysisService
from backend.services.risk_engine import RiskEngine

logger = logging.getLogger(__name__)


class VerificationStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"


class VerificationEngine:
    """Engine for verifying remediation effectiveness through re-scanning."""

    def __init__(self):
        self.ai_analyzer = AnalysisService()
        self.risk_engine = RiskEngine()

        # Map resource types to their scanning functions
        self.scanners = {
            "s3_bucket": scan_s3_buckets,
            "iam_user": scan_iam_users,
            "iam_account": scan_iam_users,  # IAM account scans users
            "security_group": scan_security_groups,
            "cloudtrail": scan_cloudtrail,
            "lambda_function": scan_lambda_functions
        }

    def verify_remediation(self, original_finding: Dict[str, Any],
                          remediation_action: Dict[str, Any],
                          wait_time_seconds: int = 30) -> Dict[str, Any]:
        """
        Verify that remediation was successful by re-scanning the target resource.

        Args:
            original_finding: The original finding before remediation
            remediation_action: Details of the remediation action that was performed
            wait_time_seconds: Time to wait after remediation before re-scanning

        Returns:
            Verification results with status and details
        """
        start_time = datetime.utcnow()

        try:
            resource_id = original_finding.get("resource_id")
            resource_type = original_finding.get("resource_type")

            if not resource_id or not resource_type:
                return self._create_verification_result(
                    VerificationStatus.ERROR,
                    "Missing resource ID or type for verification",
                    start_time
                )

            # Get the appropriate scanner for this resource type
            scanner_func = self.scanners.get(resource_type)
            if not scanner_func:
                return self._create_verification_result(
                    VerificationStatus.ERROR,
                    f"No scanner available for resource type: {resource_type}",
                    start_time
                )

            # In a real implementation, we would wait and then re-scan just the specific resource
            # For now, we'll re-scan all resources of this type and look for the specific finding
            # This is less efficient but works for demonstration

            # Re-scan resources of this type
            try:
                current_findings = scanner_func()
            except Exception as e:
                logger.error(f"Error during re-scan: {e}")
                return self._create_verification_result(
                    VerificationStatus.ERROR,
                    f"Failed to re-scan {resource_type} resources: {str(e)}",
                    start_time
                )

            # Look for the original finding in the current results
            original_finding_id = original_finding.get("finding_id")
            original_finding_text = original_finding.get("finding", "").lower()

            # Check if the original finding is still present
            finding_resolved = True
            residual_risk = None

            for finding in current_findings:
                # Check if this is the same resource
                if finding.get("resource_id") == resource_id:
                    # Check if it's the same type of finding
                    current_finding_text = finding.get("finding", "").lower()

                    # Simple string matching - in reality would be more sophisticated
                    if (original_finding_text in current_finding_text or
                        current_finding_text in original_finding_text or
                        finding.get("finding_id") == original_finding_id):
                        # The original finding (or similar) is still present
                        finding_resolved = False
                        residual_risk = self._assess_residual_risk(original_finding, finding)
                        break

            # Determine verification status
            if finding_resolved:
                status = VerificationStatus.PASSED
                message = "Remediation verified successful - original finding no longer detected"
            else:
                status = VerificationStatus.FAILED
                message = "Remediation verification failed - original finding still present or similar issue detected"

            return self._create_verification_result(
                status,
                message,
                start_time,
                details={
                    "resource_id": resource_id,
                    "resource_type": resource_type,
                    "original_finding_id": original_finding_id,
                    "original_finding": original_finding.get("finding"),
                    "residual_risk": residual_risk,
                    "findings_after_remediation": len(current_findings),
                    "verification_method": "re_scan_and_compare"
                }
            )

        except Exception as e:
            logger.error(f"Error during verification: {e}")
            return self._create_verification_result(
                VerificationStatus.ERROR,
                f"Verification process failed: {str(e)}",
                start_time
            )

    def _assess_residual_risk(self, original_finding: Dict[str, Any],
                            current_finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Assess any residual risk if the original finding is still present.

        Args:
            original_finding: The original finding before remediation
            current_finding: The current finding after remediation

        Returns:
            Residual risk assessment or None if no residual risk
        """
        try:
            # Calculate risk scores for both findings to see if risk decreased
            original_risk = self.risk_engine.calculate_risk_score(
                severity=original_finding.get("severity", "INFO"),
                exposure="medium",  # Simplified - would assess properly
                asset_criticality="medium",
                exploitability="medium",
                detection_confidence="medium"
            )

            current_risk = self.risk_engine.calculate_risk_score(
                severity=current_finding.get("severity", "INFO"),
                exposure="medium",
                asset_criticality="medium",
                exploitability="medium",
                detection_confidence="medium"
            )

            risk_reduction = original_risk["risk_score"] - current_risk["risk_score"]

            return {
                "original_risk_score": original_risk["risk_score"],
                "current_risk_score": current_risk["risk_score"],
                "risk_reduction": risk_reduction,
                "risk_reduction_percentage": (risk_reduction / max(original_risk["risk_score"], 0.1)) * 100,
                "still_present": True,
                "assessment": "Risk reduced" if risk_reduction > 0 else "Risk unchanged or increased"
            }
        except Exception as e:
            logger.warning(f"Could not assess residual risk: {e}")
            return None

    def _create_verification_result(self, status: VerificationStatus,
                                  message: str,
                                  start_time: datetime,
                                  details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Create a standardized verification result.

        Args:
            status: The verification status
            message: Human-readable message
            start_time: When the verification started
            details: Additional details about the verification

        Returns:
            Standardized verification result dictionary
        """
        end_time = datetime.utcnow()
        duration_seconds = (end_time - start_time).total_seconds()

        result = {
            "status": status.value,
            "message": message,
            "timestamp": end_time.isoformat(),
            "duration_seconds": round(duration_seconds, 2),
            "verified": status == VerificationStatus.PASSED
        }

        if details:
            result["details"] = details

        return result

    def batch_verify_findings(self, findings: List[Dict[str, Any]],
                            remediation_actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Verify multiple remediation actions in batch.

        Args:
            findings: List of original findings
            remediation_actions: List of corresponding remediation actions

        Returns:
            List of verification results
        """
        if len(findings) != len(remediation_actions):
            raise ValueError("Number of findings must match number of remediation actions")

        results = []
        for finding, action in zip(findings, remediation_actions):
            verification = self.verify_remediation(finding, action)
            results.append({
                "finding_id": finding.get("finding_id"),
                "resource_id": finding.get("resource_id"),
                "verification": verification
            })

        return results


# Global instance for easy access
verification_engine = VerificationEngine()