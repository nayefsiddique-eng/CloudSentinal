"""
AI Explanation Service for CloudSentinel
Generates natural language explanations for security findings using LLMs.
"""

import os
import json
from typing import Dict, Any, Optional
from enum import Enum


class AIProvider(str, Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    TEMPLATE = "template"  # Fallback to template-based explanations


class ExplanationService:
    """Service for generating AI explanations of security findings."""

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
                print("Warning: anthropic package not installed. Falling back to template explanations.")
                self.provider = AIProvider.TEMPLATE

        elif self.provider == AIProvider.OPENAI:
            try:
                import openai
                self.client = openai.OpenAI(
                    api_key=os.getenv("OPENAI_API_KEY")
                )
            except ImportError:
                print("Warning: openai package not installed. Falling back to template explanations.")
                self.provider = AIProvider.TEMPLATE

    def explain_finding(self, finding: Dict[str, Any]) -> str:
        """
        Generate a natural language explanation for a security finding.

        Args:
            finding: The finding dictionary from scanners

        Returns:
            A natural language explanation of the finding
        """
        if self.provider == AIProvider.TEMPLATE:
            return self._generate_template_explanation(finding)

        try:
            if self.provider == AIProvider.ANTHROPIC:
                return self._generate_anthropic_explanation(finding)
            elif self.provider == AIProvider.OPENAI:
                return self._generate_openai_explanation(finding)
        except Exception as e:
            print(f"Warning: AI explanation failed ({e}). Falling back to template.")
            return self._generate_template_explanation(finding)

    def _generate_anthropic_explanation(self, finding: Dict[str, Any]) -> str:
        """Generate explanation using Anthropic's Claude."""
        prompt = self._build_explanation_prompt(finding)

        message = self.client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=300,
            temperature=0.3,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        return message.content[0].text.strip()

    def _generate_openai_explanation(self, finding: Dict[str, Any]) -> str:
        """Generate explanation using OpenAI's GPT."""
        prompt = self._build_explanation_prompt(finding)

        response = self.client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a cloud security expert explaining AWS security findings in clear, actionable language."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=300,
            temperature=0.3
        )

        return response.choices[0].message.content.strip()

    def _build_explanation_prompt(self, finding: Dict[str, Any]) -> str:
        """Build a prompt for explaining the security finding."""
        return f"""
You are a cloud security expert. Explain the following AWS security finding in clear, concise, and actionable language.

Finding Details:
- Resource: {finding.get('resource_id')} ({finding.get('resource_type')})
- Issue: {finding.get('finding')}
- Severity: {finding.get('severity')}
- Category: {finding.get('category')}
- Evidence: {json.dumps(finding.get('evidence', {}), indent=2)}

Please provide:
1. A clear explanation of what this finding means
2. Why it's a security concern
3. Potential impact if left unaddressed
4. Brief context about AWS best practices related to this issue

Keep your explanation under 300 words and focus on being helpful and actionable.
"""

    def _generate_template_explanation(self, finding: Dict[str, Any]) -> str:
        """Generate a template-based explanation when AI services are not available."""
        resource_type = finding.get('resource_type', 'resource')
        resource_id = finding.get('resource_id', 'unknown')
        issue = finding.get('finding', 'unknown issue')
        severity = finding.get('severity', 'INFO')
        category = finding.get('category', 'general')

        # Template explanations based on common finding types
        explanations = {
            "PUBLIC_ACCESS": f"The {resource_id} {resource_type} has public access settings that could expose data to unauthorized users. This is a {severity.lower()} severity issue because it could lead to data breaches or unauthorized access.",
            "DATA_PROTECTION": f"The {resource_id} {resource_type} lacks adequate data protection measures. This {severity.lower()} severity finding indicates that data may not be properly protected against unauthorized access or loss.",
            "IDENTITY_SECURITY": f"There are identity and access management concerns with the {resource_id} {resource_type}. This {severity.lower()} severity issue could allow unauthorized users to gain elevated privileges or access sensitive resources.",
            "EXCESSIVE_PERMISSIONS": f"The {resource_id} {resource_type} has overly permissive permissions that exceed what's necessary for normal operation. This {severity.lower()} severity finding increases the risk of accidental or malicious misuse.",
            "CREDENTIAL_HYGIENE": f"The {resource_id} {resource_type} has credential-related security issues that could lead to unauthorized access. This {severity.lower()} severity finding suggests poor credential management practices.",
            "NETWORK_SECURITY": f"The {resource_id} {resource_type} has network configuration issues that could expose it to unwanted traffic or attacks. This {severity.lower()} severity finding needs attention to maintain proper network security boundaries.",
            "LOGGING_MONITORING": f"The {resource_id} {resource_type} has insufficient logging or monitoring configuration. This {severity.lower()} severity finding reduces visibility into activities and could delay detection of security incidents.",
            "SCAN_ERROR": f"An error occurred while scanning the {resource_id} {resource_type}. This {severity.lower()} severity issue means the scan results may be incomplete or inaccurate."
        }

        # Get explanation based on category, or use a generic one
        explanation = explanations.get(
            category,
            f"The {resource_id} {resource_type} has a security issue: {issue}. This is rated as {severity.lower()} severity and requires attention to maintain proper security posture."
        )

        # Add severity-specific context
        if severity == "CRITICAL":
            explanation += " This requires immediate attention as it poses a significant risk to your environment."
        elif severity == "HIGH":
            explanation += " This should be addressed promptly to prevent potential security incidents."
        elif severity == "MEDIUM":
            explanation += " This should be addressed as part of your regular security maintenance."
        else:
            explanation += " This is informational and may not require immediate action."

        return explanation