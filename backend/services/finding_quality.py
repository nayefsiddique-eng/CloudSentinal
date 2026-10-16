"""
CloudSentinel finding quality and consistency layer.

The AWS scanner is authoritative for:
- finding
- evidence
- severity
- status
- resource identity

AI enrichment may explain a finding, but it must never contradict
the scanner's actual evidence.
"""

from __future__ import annotations

from typing import Any, Dict


SEVERITY_TO_RISK = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
}

SEVERITY_TO_PRIORITY = {
    "CRITICAL": "P1",
    "HIGH": "P2",
    "MEDIUM": "P3",
    "LOW": "P4",
    "INFO": "P5",
}


def _name(finding: Dict[str, Any]) -> str:
    return (
        finding.get("resource_name")
        or finding.get("resource_id")
        or "AWS resource"
    )


def _resource_type(finding: Dict[str, Any]) -> str:
    return str(finding.get("resource_type") or "resource").replace("_", " ")


def _is_resolved(finding: Dict[str, Any]) -> bool:
    return str(finding.get("status", "")).upper() in {
        "RESOLVED",
        "CLOSED",
        "PASS",
        "PASSED",
    }


def _finding_text(finding: Dict[str, Any]) -> str:
    return str(finding.get("finding") or "").strip()


def normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize AI/scanner output so positive findings are never described
    as vulnerabilities and severity/risk metadata cannot contradict each other.
    """

    finding = dict(finding)

    title = _finding_text(finding)
    title_lower = title.lower()
    resource = _name(finding)
    resource_type = _resource_type(finding)
    evidence = finding.get("evidence") or {}
    severity = str(finding.get("severity") or "INFO").upper()
    resolved = _is_resolved(finding)

    # --------------------------------------------------------
    # Preserve scanner severity as authoritative.
    # --------------------------------------------------------
    if severity not in SEVERITY_TO_RISK:
        severity = "INFO"

    finding["severity"] = severity
    finding["risk_level"] = SEVERITY_TO_RISK[severity]
    finding["priority"] = SEVERITY_TO_PRIORITY[severity]

    # --------------------------------------------------------
    # Explicit evidence-driven explanations.
    # --------------------------------------------------------

    # S3 encryption
    if "encryption is enabled" in title_lower:
        if bool(evidence.get("encryption_enabled")):
            finding["explanation"] = (
                f"{resource} has server-side encryption enabled. "
                "This provides encryption at rest for objects stored in the bucket."
            )
            finding["impact"] = (
                "Encryption at rest helps protect stored data if the underlying "
                "storage is accessed outside the intended authorization boundary."
            )
            finding["attack_scenario"] = (
                "An attacker who obtains unauthorized access to stored objects "
                "would face the additional protection provided by encryption at rest."
            )
            finding["recommendation"] = (
                "Maintain encryption at rest, review the encryption configuration "
                "regularly, and use an appropriate customer-managed KMS key when "
                "your security requirements require additional key control."
            )

    # Root/user MFA
    elif "mfa is enabled" in title_lower:
        if bool(evidence.get("mfa_enabled")):
            finding["explanation"] = (
                f"MFA is enabled for {resource}. "
                "The scanner verified that an additional authentication factor is configured."
            )
            finding["impact"] = (
                "MFA reduces the likelihood that a stolen password alone can be "
                "used to authenticate as this identity."
            )
            finding["attack_scenario"] = (
                "If the password is compromised, an attacker would still need "
                "the configured MFA factor to complete authentication."
            )
            finding["recommendation"] = (
                "Keep MFA enabled and periodically verify that the configured "
                "authentication factor remains under the account owner's control."
            )

    # MFA missing
    elif "mfa is not enabled" in title_lower:
        finding["explanation"] = (
            f"MFA is not enabled for {resource}. "
            "A password compromise could therefore provide a direct authentication path."
        )
        finding["impact"] = (
            "A compromised password could allow unauthorized access without "
            "the additional protection provided by MFA."
        )
        finding["attack_scenario"] = (
            "An attacker obtains the user's password through phishing, credential "
            "reuse, malware, or another compromise and authenticates without a second factor."
        )
        finding["recommendation"] = (
            "Enable MFA for this identity and prefer phishing-resistant MFA where supported."
        )

    # Wildcard permissions
    elif "no wildcard permissions" in title_lower:
        if evidence.get("wildcard_permissions") is False:
            finding["explanation"] = (
                f"{resource} does not have wildcard Action:* and Resource:* "
                "permissions according to the scanned IAM policies."
            )
            finding["impact"] = (
                "No wildcard permission issue was identified by this rule."
            )
            finding["attack_scenario"] = (
                "This rule did not identify an unrestricted IAM permission path."
            )
            finding["recommendation"] = (
                "Continue following least-privilege principles and periodically review IAM policies."
            )

    elif "wildcard permissions" in title_lower or "action:*" in title_lower:
        if evidence.get("wildcard_permissions") is True:
            finding["explanation"] = (
                f"{resource} has wildcard IAM permissions that can grant "
                "broad access to AWS actions and resources."
            )
            finding["impact"] = (
                "Excessive IAM permissions can increase the blast radius of a "
                "compromised identity and permit unauthorized actions."
            )
            finding["attack_scenario"] = (
                "An attacker who compromises this identity can use its broad "
                "permissions to access or modify resources beyond the intended scope."
            )
            finding["recommendation"] = (
                "Replace wildcard permissions with narrowly scoped actions and resources, "
                "remove unused permissions, and apply least privilege."
            )

    # Password policy
    elif "password policy meets baseline" in title_lower:
        finding["explanation"] = (
            "The AWS account password policy meets the configured CloudSentinel baseline."
        )
        finding["impact"] = (
            "No password-policy weakness was identified by this rule."
        )
        finding["attack_scenario"] = (
            "This rule did not identify a password-policy weakness."
        )
        finding["recommendation"] = (
            "Continue reviewing the password policy periodically and combine it with MFA "
            "and other identity protections."
        )

    # Old access keys
    elif "no old access keys" in title_lower:
        finding["explanation"] = (
            f"No stale access keys were identified for {resource} by the configured age threshold."
        )
        finding["impact"] = (
            "No stale-access-key issue was identified by this rule."
        )
        finding["attack_scenario"] = (
            "This rule did not identify an aged access key that could unnecessarily "
            "increase credential exposure."
        )
        finding["recommendation"] = (
            "Continue rotating credentials when required and prefer temporary credentials "
            "or IAM roles where appropriate."
        )

    # Old/stale access keys detected
    elif "old access key" in title_lower or "stale access key" in title_lower:
        finding["explanation"] = (
            f"{resource} has an access key that exceeds the configured credential-age threshold."
        )
        finding["impact"] = (
            "Long-lived credentials increase the period during which a compromised "
            "access key may remain useful to an attacker."
        )
        finding["attack_scenario"] = (
            "An attacker obtains an old access key and uses it to authenticate "
            "to AWS until the credential is revoked or rotated."
        )
        finding["recommendation"] = (
            "Rotate or remove unused access keys and prefer short-lived credentials "
            "such as IAM roles where possible."
        )

    # EC2 safe ports
    elif "no risky ports exposed" in title_lower:
        finding["explanation"] = (
            f"{resource} does not expose the ports checked by the CloudSentinel "
            "network-security rule to the public internet."
        )
        finding["impact"] = (
            "No risky public-port exposure was identified by this rule."
        )
        finding["attack_scenario"] = (
            "This rule did not identify a direct unrestricted public-port exposure."
        )
        finding["recommendation"] = (
            "Maintain least-privilege network rules and review security-group "
            "changes periodically."
        )

    # EC2 unrestricted inbound
    elif "no unrestricted inbound" in title_lower:
        finding["explanation"] = (
            f"{resource} does not contain an unrestricted inbound rule matching "
            "the scanner's public-access criteria."
        )
        finding["impact"] = (
            "No unrestricted inbound exposure was identified by this rule."
        )
        finding["attack_scenario"] = (
            "This rule did not identify a security-group rule allowing unrestricted inbound access."
        )
        finding["recommendation"] = (
            "Continue restricting inbound access to required sources and ports only."
        )

    # CloudTrail enabled
    elif "cloudtrail logging is enabled" in title_lower:
        finding["explanation"] = (
            f"CloudTrail logging is enabled for {resource}. "
            "AWS API activity can therefore be recorded for the configured trail."
        )
        finding["impact"] = (
            "Enabled CloudTrail logging improves visibility for security monitoring "
            "and incident investigation."
        )
        finding["attack_scenario"] = (
            "Relevant API activity can be recorded, providing evidence that can "
            "support investigation of unauthorized activity."
        )
        finding["recommendation"] = (
            "Keep CloudTrail enabled and verify log delivery, retention, integrity "
            "protection, and monitoring coverage."
        )

    # CloudTrail disabled
    elif "cloudtrail logging is disabled" in title_lower:
        finding["explanation"] = (
            f"CloudTrail logging is disabled for {resource}."
        )
        finding["impact"] = (
            "Reduced audit visibility can delay detection and investigation of "
            "unauthorized AWS activity."
        )
        finding["attack_scenario"] = (
            "An attacker performs AWS API operations while logging is unavailable "
            "or incomplete, reducing the evidence available for detection and investigation."
        )
        finding["recommendation"] = (
            "Enable CloudTrail logging and verify delivery, retention, integrity "
            "protection, and monitoring."
        )

    # Generic resolved fallback
    elif resolved:
        finding["explanation"] = (
            f"The security control represented by '{title}' passed for {resource}."
        )
        finding["impact"] = (
            "No security weakness was identified by this specific control."
        )
        finding["attack_scenario"] = (
            "This control did not identify the tested attack condition."
        )
        finding["recommendation"] = (
            "Maintain the current configuration and periodically revalidate it."
        )

    # Generic open finding fallback
    else:
        finding["explanation"] = (
            f"{resource} ({resource_type}) failed the security control: {title}."
        )

    # --------------------------------------------------------
    # Status consistency.
    # Positive controls should not look like open vulnerabilities.
    # --------------------------------------------------------
    if resolved and severity not in {"INFO", "LOW"}:
        # Scanner status wins, but an INFO-style passed check should not retain
        # an inflated severity from an enrichment model.
        finding["severity"] = "INFO"
        finding["risk_level"] = "INFO"
        finding["priority"] = "P5"

    return finding


def normalize_findings(findings):
    return [normalize_finding(f) for f in findings]
