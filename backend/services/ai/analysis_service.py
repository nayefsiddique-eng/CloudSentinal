"""
AI Analysis Service for CloudSentinel
Provides comprehensive AI analysis of security findings including risk scoring,
explanations, impact assessment, and remediation recommendations.
"""

import os
import json
from typing import Dict, Any, Optional
from enum import Enum


class AIProvider(str, Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    TEMPLATE = "template"  # Fallback to template-based analysis


class AnalysisService:
    """Service for generating comprehensive AI analysis of security findings."""

    def __init__(self):
        self.provider = self._determine_provider()
        self._setup_client()

    def _determine_provider(self) -> AIProvider:
        """Determine which AI provider to use based on available API keys."""
        if os.getenv("ANTHROPIC_API_KEY"):
            return AIProvider.ANTHROPIC
        elif os.getenv("OPENAI_API_KEY"):
            return AIProvider.OPENAI
        else:
            return AIProvider.TEMPLATE

    def _setup_client(self):
        """Setup the AI client based on the selected provider."""
        if self.provider == AIProvider.ANTHROPIC:
            try:
                import anthropic
                self.client = anthropic.Anthropic(
                    api_key=os.getenv("ANTHROPIC_API_KEY")
                )
            except ImportError:
                print("Warning: anthropic package not installed. Falling back to template analysis.")
                self.provider = AIProvider.TEMPLATE

        elif self.provider == AIProvider.OPENAI:
            try:
                import openai
                self.client = openai.OpenAI(
                    api_key=os.getenv("OPENAI_API_KEY")
                )
            except ImportError:
                print("Warning: openai package not installed. Falling back to template analysis.")
                self.provider = AIProvider.TEMPLATE

    def analyze_finding(self, finding: Dict[str, Any], aws_config: Dict[str, Any] = None,
                       security_rule: Dict[str, Any] = None, resource_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Generate a comprehensive AI analysis for a security finding.

        Args:
            finding: The finding dictionary from scanners
            aws_config: AWS configuration context
            security_rule: The security rule that triggered this finding
            resource_context: Additional context about the resource

        Returns:
            Dictionary containing: severity, risk_score, explanation, impact,
            attack_scenario, recommendation, confidence
        """
        if self.provider == AIProvider.TEMPLATE:
            return self._generate_template_analysis(finding, aws_config, security_rule, resource_context)

        try:
            if self.provider == AIProvider.ANTHROPIC:
                return self._generate_anthropic_analysis(finding, aws_config, security_rule, resource_context)
            elif self.provider == AIProvider.OPENAI:
                return self._generate_openai_analysis(finding, aws_config, security_rule, resource_context)
        except Exception as e:
            print(f"Warning: AI analysis failed ({e}). Falling back to template.")
            return self._generate_template_analysis(finding, aws_config, security_rule, resource_context)

    def _generate_anthropic_analysis(self, finding: Dict[str, Any], aws_config: Dict[str, Any] = None,
                                   security_rule: Dict[str, Any] = None, resource_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate analysis using Anthropic's Claude."""
        prompt = self._build_analysis_prompt(finding, aws_config, security_rule, resource_context)

        message = self.client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1000,
            temperature=0.2,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        # Parse the JSON response
        response_text = message.content[0].text.strip()
        try:
            # Try to parse as JSON
            analysis = json.loads(response_text)
            # Validate required fields
            required_fields = ["severity", "risk_score", "explanation", "impact",
                             "attack_scenario", "recommendation", "confidence"]
            for field in required_fields:
                if field not in analysis:
                    analysis[field] = self._get_default_value(field, finding)
            return analysis
        except json.JSONDecodeError:
            # If not valid JSON, extract information from text
            return self._parse_text_analysis(response_text, finding)

    def _generate_openai_analysis(self, finding: Dict[str, Any], aws_config: Dict[str, Any] = None,
                                security_rule: Dict[str, Any] = None, resource_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate analysis using OpenAI's GPT."""
        prompt = self._build_analysis_prompt(finding, aws_config, security_rule, resource_context)

        response = self.client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a cloud security expert. Provide analysis in valid JSON format only."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=1000,
            temperature=0.2
        )

        # Parse the JSON response
        response_text = response.choices[0].message.content.strip()
        try:
            # Try to parse as JSON
            analysis = json.loads(response_text)
            # Validate required fields
            required_fields = ["severity", "risk_score", "explanation", "impact",
                             "attack_scenario", "recommendation", "confidence"]
            for field in required_fields:
                if field not in analysis:
                    analysis[field] = self._get_default_value(field, finding)
            return analysis
        except json.JSONDecodeError:
            # If not valid JSON, extract information from text
            return self._parse_text_analysis(response_text, finding)

    def _build_analysis_prompt(self, finding: Dict[str, Any], aws_config: Dict[str, Any] = None,
                             security_rule: Dict[str, Any] = None, resource_context: Dict[str, Any] = None) -> str:
        """Build a prompt for analyzing the security finding."""
        return f"""
You are a cloud security expert providing comprehensive analysis of AWS security findings.

Analyze the following finding and provide a structured JSON response with these exact fields:
- severity: The security severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- risk_score: Numerical risk score from 0.0 to 10.0
- explanation: Clear explanation of what the finding means and why it's a security concern
- impact: Description of potential business and security impact if left unaddressed
- attack_scenario: How an attacker could exploit this vulnerability
- recommendation: Specific, actionable remediation steps
- confidence: Confidence score from 0.0 to 1.0 indicating certainty in this analysis

Finding Details:
- Resource ID: {finding.get('resource_id', 'unknown')}
- Resource Type: {finding.get('resource_type', 'unknown')}
- Finding: {finding.get('finding', 'unknown issue')}
- Current Severity: {finding.get('severity', 'INFO')}
- Category: {finding.get('category', 'general')}
- Evidence: {json.dumps(finding.get('evidence', {}), indent=2)}

AWS Configuration Context:
{json.dumps(aws_config or {}, indent=2)}

Security Rule Context:
{json.dumps(security_rule or {}, indent=2)}

Resource Context:
{json.dumps(resource_context or {}, indent=2)}

Provide ONLY valid JSON in your response, no additional text. Ensure all fields are present and properly formatted.
"""

    def _get_default_value(self, field: str, finding: Dict[str, Any]) -> Any:
        """Get default value for a missing field based on the finding."""
        defaults = {
            "severity": finding.get("severity", "INFO"),
            "risk_score": 5.0,
            "explanation": finding.get("finding", "Security finding detected"),
            "impact": "Potential security impact if not addressed",
            "attack_scenario": "Could be exploited by attackers",
            "recommendation": "Review and address according to security best practices",
            "confidence": 0.7
        }
        return defaults.get(field, "")

    def _parse_text_analysis(self, text: str, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Parse text response when JSON parsing fails."""
        # Basic fallback - extract what we can
        return {
            "severity": finding.get("severity", "INFO"),
            "risk_score": 5.0,
            "explanation": text[:500] if text else "Analysis completed",
            "impact": "Security impact requires attention",
            "attack_scenario": "Potential exploitation vector identified",
            "recommendation": "Follow security remediation best practices",
            "confidence": 0.6
        }

    def _generate_template_analysis(self, finding: Dict[str, Any], aws_config: Dict[str, Any] = None,
                                  security_rule: Dict[str, Any] = None, resource_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate template-based analysis when AI services are not available."""
        resource_type = finding.get('resource_type', 'resource')
        resource_id = finding.get('resource_id', 'unknown')
        issue = finding.get('finding', 'unknown issue')
        severity = finding.get('severity', 'INFO')
        category = finding.get('category', 'general')

        # Calculate risk score based on severity and other factors
        severity_scores = {
            "CRITICAL": 9.0,
            "HIGH": 7.0,
            "MEDIUM": 5.0,
            "LOW": 3.0,
            "INFO": 1.0
        }
        base_score = severity_scores.get(severity, 5.0)

        # Adjust based on category
        category_adjustments = {
            "PUBLIC_ACCESS": 2.0,
            "DATA_PROTECTION": 1.5,
            "IDENTITY_SECURITY": 2.5,
            "EXCESSIVE_PERMISSIONS": 2.0,
            "CREDENTIAL_HYGIENE": 1.0,
            "NETWORK_SECURITY": 1.5,
            "LOGGING_MONITORING": 0.5,
            "SCAN_ERROR": -1.0
        }
        adjustment = category_adjustments.get(category, 0.0)
        risk_score = min(10.0, max(0.0, base_score + adjustment))

        # Generate explanation
        explanations = {
            "PUBLIC_ACCESS": f"The {resource_id} {resource_type} has public access settings that could expose data to unauthorized users.",
            "DATA_PROTECTION": f"The {resource_id} {resource_type} lacks adequate data protection measures.",
            "IDENTITY_SECURITY": f"There are identity and access management concerns with the {resource_id} {resource_type}.",
            "EXCESSIVE_PERMISSIONS": f"The {resource_id} {resource_type} has overly permissive permissions.",
            "CREDENTIAL_HYGIENE": f"The {resource_id} {resource_type} has credential-related security issues.",
            "NETWORK_SECURITY": f"The {resource_id} {resource_type} has network configuration issues.",
            "LOGGING_MONITORING": f"The {resource_id} {resource_type} has insufficient logging or monitoring.",
            "SCAN_ERROR": f"An error occurred while scanning the {resource_id} {resource_type}."
        }

        explanation = explanations.get(
            category,
            f"The {resource_id} {resource_type} has a security issue: {issue}."
        )

        # Impact descriptions
        impacts = {
            "PUBLIC_ACCESS": "Unauthorized access to sensitive data, potential data breaches, compliance violations",
            "DATA_PROTECTION": "Data loss, unauthorized data modification, breach of data protection regulations",
            "IDENTITY_SECURITY": "Privilege escalation, unauthorized access to critical systems, credential theft",
            "EXCESSIVE_PERMISSIONS": "Accidental or malicious misuse of privileges, lateral movement by attackers",
            "CREDENTIAL_HYGIENE": "Credential theft, unauthorized account access, potential for broader compromise",
            "NETWORK_SECURITY": "Network-based attacks, data exfiltration, service disruption",
            "LOGGING_MONITORING": "Reduced visibility into security events, delayed threat detection",
            "SCAN_ERROR": "Incomplete security assessment, potential undetected vulnerabilities"
        }

        impact = impacts.get(category, "Security risk requiring investigation and remediation")

        # Attack scenarios
        attack_scenarios = {
            "PUBLIC_ACCESS": "Attacker discovers publicly accessible resource and exfiltrates sensitive data",
            "DATA_PROTECTION": "Attacker accesses unencrypted sensitive data or modifies data without detection",
            "IDENTITY_SECURITY": "Attacker compromises credentials and escalates privileges to access critical systems",
            "EXCESSIVE_PERMISSIONS": "Attacker gains excessive permissions and uses them to access unauthorized resources",
            "CREDENTIAL_HYGIENE": "Attacker steals or guesses weak credentials to gain unauthorized access",
            "NETWORK_SECURITY": "Attacker exploits network misconfigurations to intercept or modify traffic",
            "LOGGING_MONITORING": "Attacker performs malicious activities without detection due to insufficient logging",
            "SCAN_ERROR": "Attacker exploits vulnerabilities that were not detected due to scanning errors"
        }

        attack_scenario = attack_scenarios.get(
            category,
            f"Attacker could exploit the {issue} vulnerability to compromise security."
        )

        # Recommendations
        recommendations = {
            "PUBLIC_ACCESS": "Disable public access, implement proper access controls, and use private endpoints where possible",
            "DATA_PROTECTION": "Enable encryption at rest and in transit, implement proper key management, and enable versioning",
            "IDENTITY_SECURITY": "Enforce MFA for all users, implement least privilege access, and regularly review permissions",
            "EXCESSIVE_PERMISSIONS": "Review and reduce permissions to least privilege, remove unused permissions, and implement permission boundaries",
            "CREDENTIAL_HYGIENE": "Rotate credentials, implement strong password policies, and use secrets management services",
            "NETWORK_SECURITY": "Restrict network access to least privilege, use security groups and network ACLs effectively",
            "LOGGING_MONITORING": "Enable comprehensive logging across all services, implement log monitoring and alerting",
            "SCAN_ERROR": "Investigate the scanning error, ensure proper permissions, and manually verify the resource status"
        }

        recommendation = recommendations.get(
            category,
            "Review the finding against security best practices and implement appropriate remediation measures."
        )

        # Confidence based on information availability
        confidence = 0.8
        if not aws_config or len(str(aws_config)) < 10:
            confidence -= 0.1
        if not security_rule or len(str(security_rule)) < 10:
            confidence -= 0.1
        if not resource_context or len(str(resource_context)) < 10:
            confidence -= 0.1

        return {
            "severity": severity,
            "risk_score": round(risk_score, 1),
            "explanation": explanation,
            "impact": impact,
            "attack_scenario": attack_scenario,
            "recommendation": recommendation,
            "confidence": round(confidence, 2)
        }