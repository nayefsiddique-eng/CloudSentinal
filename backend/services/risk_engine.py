"""
Risk Engine for CloudSentinel
Calculates risk scores using a deterministic model:
Severity × Exposure × Asset Criticality × Exploitability × Detection Confidence
"""

from typing import Dict, Any, Optional
from enum import Enum
from backend.models import Severity, Category


class ExposureLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AssetCriticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Exploitability(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionConfidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskPriority(str, Enum):
    P1 = "P1"  # Critical
    P2 = "P2"  # High
    P3 = "P3"  # Medium
    P4 = "P4"  # Low
    P5 = "P5"  # Informational


class RiskEngine:
    """Engine for calculating risk scores using deterministic model."""

    def __init__(self):
        # Severity weights (base score out of 10)
        self.severity_weights = {
            "CRITICAL": 10.0,
            "HIGH": 8.0,
            "MEDIUM": 5.0,
            "LOW": 3.0,
            "INFO": 1.0
        }

        # Exposure weights
        self.exposure_weights = {
            ExposureLevel.LOW: 0.5,
            ExposureLevel.MEDIUM: 1.0,
            ExposureLevel.HIGH: 1.5,
            ExposureLevel.CRITICAL: 2.0
        }

        # Asset criticality weights
        self.criticality_weights = {
            AssetCriticality.LOW: 0.5,
            AssetCriticality.MEDIUM: 1.0,
            AssetCriticality.HIGH: 1.5,
            AssetCriticality.CRITICAL: 2.0
        }

        # Exploitability weights
        self.exploitability_weights = {
            Exploitability.LOW: 0.5,
            Exploitability.MEDIUM: 1.0,
            Exploitability.HIGH: 1.5,
            Exploitability.CRITICAL: 2.0
        }

        # Detection confidence weights (higher confidence = lower risk multiplier)
        self.detection_weights = {
            DetectionConfidence.LOW: 2.0,   # Low confidence = higher risk
            DetectionConfidence.MEDIUM: 1.5,
            DetectionConfidence.HIGH: 1.0,
            DetectionConfidence.CRITICAL: 0.5  # High confidence = lower risk
        }

        # Risk score to priority mapping
        self.risk_priority_map = [
            (9.0, RiskPriority.P1),   # 9.0-10.0 = P1 (Critical)
            (7.0, RiskPriority.P2),   # 7.0-8.9 = P2 (High)
            (5.0, RiskPriority.P3),   # 5.0-6.9 = P3 (Medium)
            (3.0, RiskPriority.P4),   # 3.0-4.9 = P4 (Low)
            (0.0, RiskPriority.P5)    # 0.0-2.9 = P5 (Informational)
        ]

    def calculate_risk_score(self,
                           severity: str,
                           exposure: Optional[str] = None,
                           asset_criticality: Optional[str] = None,
                           exploitability: Optional[str] = None,
                           detection_confidence: Optional[str] = None) -> Dict[str, Any]:
        """
        Calculate risk score using the deterministic model:
        Severity × Exposure × Asset Criticality × Exploitability × Detection Confidence

        Args:
            severity: The severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            exposure: Exposure level (low, medium, high, critical)
            asset_criticality: Asset criticality (low, medium, high, critical)
            exploitability: Exploitability (low, medium, high, critical)
            detection_confidence: Detection confidence (low, medium, high, critical)

        Returns:
            Dictionary with risk_score, risk_level, and priority
        """
        # Get base severity score
        severity_score = self.severity_weights.get(severity.upper(), 5.0)

        # Get weights for each factor (default to medium if not specified)
        exposure_weight = self.exposure_weights.get(
            ExposureLevel(exposure.lower()) if exposure else ExposureLevel.MEDIUM, 1.0
        )
        criticality_weight = self.criticality_weights.get(
            AssetCriticality(asset_criticality.lower()) if asset_criticality else AssetCriticality.MEDIUM, 1.0
        )
        exploitability_weight = self.exploitability_weights.get(
            Exploitability(exploitability.lower()) if exploitability else Exploitability.MEDIUM, 1.0
        )
        detection_weight = self.detection_weights.get(
            DetectionConfidence(detection_confidence.lower()) if detection_confidence else DetectionConfidence.MEDIUM, 1.0
        )

        # Calculate risk score: Severity × Exposure × Asset Criticality × Exploitability × Detection Confidence
        risk_score = severity_score * exposure_weight * criticality_weight * exploitability_weight * detection_weight

        # Normalize to 0-10 scale (assuming max possible score is around 32)
        normalized_score = min(10.0, risk_score / 3.2)  # 3.2 is approximate normalization factor

        # Determine priority based on score
        priority = self._get_priority_from_score(normalized_score)

        # Determine risk level based on score
        if normalized_score >= 8.0:
            risk_level = "CRITICAL"
        elif normalized_score >= 6.0:
            risk_level = "HIGH"
        elif normalized_score >= 4.0:
            risk_level = "MEDIUM"
        elif normalized_score >= 2.0:
            risk_level = "LOW"
        else:
            risk_level = "INFO"

        return {
            "risk_score": round(normalized_score, 2),
            "risk_level": risk_level,
            "priority": priority.value,
            "factors": {
                "severity": severity,
                "severity_score": severity_score,
                "exposure": exposure or "medium",
                "exposure_weight": exposure_weight,
                "asset_criticality": asset_criticality or "medium",
                "criticality_weight": criticality_weight,
                "exploitability": exploitability or "medium",
                "exploitability_weight": exploitability_weight,
                "detection_confidence": detection_confidence or "medium",
                "detection_weight": detection_weight
            }
        }

    def _get_priority_from_score(self, score: float) -> RiskPriority:
        """Get priority based on risk score."""
        for threshold, priority in self.risk_priority_map:
            if score >= threshold:
                return priority
        return RiskPriority.P5  # Default to lowest priority

    def assess_exposure(self, finding: Dict[str, Any], aws_config: Dict[str, Any] = None) -> str:
        """
        Assess exposure level based on finding and AWS configuration.

        Args:
            finding: The security finding
            aws_config: AWS configuration context

        Returns:
            Exposure level (low, medium, high, critical)
        """
        resource_type = finding.get("resource_type", "")
        category = finding.get("category", "")
        evidence = finding.get("evidence", {})

        # Publicly accessible resources have high exposure
        if category == "PUBLIC_ACCESS" or evidence.get("public") == True:
            return ExposureLevel.CRITICAL.value

        # Resources with wide accessibility
        if category in ["NETWORK_SECURITY", "EXCESSIVE_PERMISSIONS"]:
            return ExposureLevel.HIGH.value

        # Default to medium exposure
        return ExposureLevel.MEDIUM.value

    def assess_asset_criticality(self, resource_id: str, resource_type: str,
                               tags: Dict[str, str] = None) -> str:
        """
        Assess asset criticality based on resource properties and tags.

        Args:
            resource_id: The resource identifier
            resource_type: The resource type
            tags: Resource tags (optional)

        Returns:
            Asset criticality level (low, medium, high, critical)
        """
        # Check for criticality tags
        if tags:
            criticality_tag = tags.get("Criticality", tags.get("criticality", tags.get("CRITICALITY"))) \
                           or tags.get("BusinessCriticality", tags.get("business_criticality"))
            if criticality_tag:
                try:
                    return AssetCriticality(criticality_tag.lower()).value
                except ValueError:
                    pass  # Invalid value, continue to default logic

        # Default criticality based on resource type
        critical_resources = ["s3_bucket", "iam_account", "rds_instance", "lambda_function"]
        high_resources = ["ec2_instance", "security_group", "iam_user", "iam_role"]

        if resource_type in critical_resources:
            return AssetCriticality.HIGH.value
        elif resource_type in high_resources:
            return AssetCriticality.MEDIUM.value
        else:
            return AssetCriticality.LOW.value

    def assess_exploitability(self, finding: Dict[str, Any]) -> str:
        """
        Assess exploitability based on the finding characteristics.

        Args:
            finding: The security finding

        Returns:
            Exploitability level (low, medium, high, critical)
        """
        category = finding.get("category", "")
        severity = finding.get("severity", "INFO")
        evidence = finding.get("evidence", {})

        # High exploitability categories
        if category in ["PUBLIC_ACCESS", "EXCESSIVE_PERMISSIONS", "CREDENTIAL_HYGIENE"]:
            if severity in ["CRITICAL", "HIGH"]:
                return Exploitability.HIGH.value
            else:
                return Exploitability.MEDIUM.value

        # Medium exploitability
        if category in ["DATA_PROTECTION", "IDENTITY_SECURITY", "NETWORK_SECURITY"]:
            return Exploitability.MEDIUM.value

        # Low exploitability
        if category in ["LOGGING_MONITORING", "SCAN_ERROR"]:
            return Exploitability.LOW.value

        # Default based on severity
        if severity == "CRITICAL":
            return Exploitability.HIGH.value
        elif severity == "HIGH":
            return Exploitability.MEDIUM.value
        else:
            return Exploitability.LOW.value

    def assess_detection_confidence(self, finding: Dict[str, Any]) -> str:
        """
        Assess detection confidence based on finding quality and evidence.

        Args:
            finding: The security finding

        Returns:
            Detection confidence level (low, medium, high, critical)
        """
        evidence = finding.get("evidence", {})
        finding_text = finding.get("finding", "")

        # High confidence: clear, factual findings with concrete evidence
        if evidence and len(str(evidence)) > 20:
            if any(key in evidence for key in ["enabled", "disabled", "True", "False", "public", "access"]):
                return DetectionConfidence.HIGH.value

        # Medium confidence: reasonable findings with some evidence
        if evidence or len(finding_text) > 30:
            return DetectionConfidence.MEDIUM.value

        # Low confidence: vague findings or minimal evidence
        return DetectionConfidence.LOW.value

    def enhance_finding_with_risk(self, finding: Dict[str, Any],
                                aws_config: Dict[str, Any] = None,
                                resource_tags: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Enhance a finding with calculated risk score and metadata.

        Args:
            finding: The security finding to enhance
            aws_config: AWS configuration context
            resource_tags: Resource tags for criticality assessment

        Returns:
            Enhanced finding with risk score, level, priority, and factors
        """
        # Assess each risk factor
        exposure = self.assess_exposure(finding, aws_config)
        asset_criticality = self.assess_asset_criticality(
            finding.get("resource_id", ""),
            finding.get("resource_type", ""),
            resource_tags
        )
        exploitability = self.assess_exploitability(finding)
        detection_confidence = self.assess_detection_confidence(finding)

        # Calculate risk score
        risk_result = self.calculate_risk_score(
            severity=finding.get("severity", "INFO"),
            exposure=exposure,
            asset_criticality=asset_criticality,
            exploitability=exploitability,
            detection_confidence=detection_confidence
        )

        # Add risk information to finding
        finding.update({
            "risk_score": risk_result["risk_score"],
            "risk_level": risk_result["risk_level"],
            "priority": risk_result["priority"],
            "risk_factors": risk_result["factors"]
        })

        return finding