"""
AI Analysis Engine.

Input: a Finding dict (+ the risk score from risk_engine.py).
Output: structured JSON -- explanation, impact, attack_scenario,
recommendation, confidence -- for a human reader (dashboard "Findings
Detail" view per the Team Plan).

Important (per the Team Plan / HANDOFF): the LLM only *explains and
recommends*. It never decides what gets auto-applied -- that's
safety_gate.py, which runs on the deterministic finding/category text,
not on anything the model says. If the model is unavailable or
misbehaves, the pipeline still works via the template fallback below.
"""

from backend.services.ai.groq_client import call_groq_json, is_configured

SYSTEM_PROMPT = """You are a cloud security analyst embedded in an automated \
AWS security scanner (CloudSentinel). You are given one finding and must \
explain it for a mixed audience (engineers + non-technical stakeholders).

Rules:
- Be concrete and specific to the finding given, not generic security advice.
- Never invent facts not supported by the finding/evidence you were given.
- You only explain and recommend. You never claim to have applied a fix.
- Respond with ONLY a JSON object, no prose, matching exactly this schema:
{
  "explanation": "plain-English, 1-3 sentences, what is actually wrong",
  "impact": "1-2 sentences, what could realistically happen if left open",
  "attack_scenario": "1-3 sentences, a concrete step-by-step way this gets exploited",
  "recommendation": "1-2 sentences, the specific fix to apply",
  "confidence": 0.0-1.0
}
"""


def _user_prompt(finding: dict, risk: dict) -> str:
    return (
        f"resource_type: {finding.get('resource_type')}\n"
        f"resource_id: {finding.get('resource_id')}\n"
        f"finding: {finding.get('finding')}\n"
        f"severity: {finding.get('severity')}\n"
        f"category: {finding.get('category')}\n"
        f"evidence: {finding.get('evidence')}\n"
        f"computed_risk_score (0-10): {risk.get('risk_score')}\n"
        f"priority: {risk.get('priority')}\n"
    )


# Template fallback used when GROQ_API_KEY isn't set or the call fails, so
# a finding is never left without *some* explanation. Keyed by category;
# generic enough to apply across resource types within that category.
_TEMPLATES = {
    "PUBLIC_ACCESS": {
        "explanation": "This resource is reachable from the public internet without restriction.",
        "impact": "Anyone on the internet can read, and potentially modify, this resource's contents.",
        "attack_scenario": "An attacker scans public IP/endpoint ranges, finds the exposed resource, and accesses it directly with no credentials.",
        "recommendation": "Restrict access to trusted principals/networks only and re-scan to confirm it is no longer publicly reachable.",
    },
    "NETWORK_SECURITY": {
        "explanation": "A network rule allows unrestricted inbound traffic from the internet (0.0.0.0/0).",
        "impact": "The underlying instance/service is exposed to internet-wide scanning and brute-force attempts.",
        "attack_scenario": "An attacker port-scans the exposed range, finds the open port, and attempts credential stuffing or exploits a known service vulnerability.",
        "recommendation": "Restrict the security group rule to specific known CIDR ranges (e.g. office VPN) instead of 0.0.0.0/0.",
    },
    "IDENTITY_SECURITY": {
        "explanation": "An identity-security control (MFA or password policy) does not meet baseline.",
        "impact": "A compromised or guessed credential is sufficient on its own to gain access, with no second factor.",
        "attack_scenario": "An attacker obtains a leaked/reused password (e.g. from a breach dump) and logs in directly, since no second factor is required.",
        "recommendation": "Enforce MFA and/or a stronger password policy for this identity.",
    },
    "EXCESSIVE_PERMISSIONS": {
        "explanation": "This identity holds broader permissions (wildcard Action/Resource, or an excessively privileged role) than it needs.",
        "impact": "If this identity's credentials are compromised, the attacker inherits full account access, not just what the workload actually needs.",
        "attack_scenario": "An attacker compromises the identity via a leaked key or SSRF against the workload, then uses its wildcard permissions to pivot across the account.",
        "recommendation": "Replace the wildcard/administrator policy with a least-privilege policy scoped to the specific actions this identity actually performs.",
    },
    "CREDENTIAL_HYGIENE": {
        "explanation": "A credential (access key) has exceeded the recommended rotation age.",
        "impact": "Long-lived keys increase the window in which a leaked credential remains valid and undetected.",
        "attack_scenario": "A key leaked months ago (e.g. committed to a public repo) is still active and usable by an attacker today.",
        "recommendation": "Rotate/deactivate the old key(s) and issue fresh credentials to whatever depends on them.",
    },
    "DATA_PROTECTION": {
        "explanation": "Data-at-rest protection (encryption or versioning) is not enabled for this resource.",
        "impact": "Data could be unrecoverable after accidental deletion/overwrite, or exposed in cleartext if storage is ever accessed out-of-band.",
        "attack_scenario": "An attacker (or a misconfigured process) deletes or overwrites objects with no versioning to recover from, or an underlying disk/snapshot leak exposes unencrypted data.",
        "recommendation": "Enable the missing control (versioning and/or default encryption) on this resource.",
    },
    "LOGGING_MONITORING": {
        "explanation": "Audit logging is disabled or missing for this account/resource.",
        "impact": "Malicious or accidental changes in the account leave no trail, making detection and incident response effectively impossible.",
        "attack_scenario": "An attacker gains access, makes changes to resources or IAM, and there is no CloudTrail record to detect or investigate the activity.",
        "recommendation": "Enable and configure a CloudTrail trail covering all regions and management events.",
    },
}
_DEFAULT_TEMPLATE = {
    "explanation": "This finding indicates a deviation from the expected secure baseline.",
    "impact": "Depending on how this resource is used, this could increase the account's overall attack surface.",
    "attack_scenario": "An attacker with partial access to the account could leverage this misconfiguration as part of a broader compromise.",
    "recommendation": "Review this finding's evidence and apply the corresponding AWS best-practice fix.",
}


def _template_analysis(finding: dict, risk: dict) -> dict:
    tmpl = _TEMPLATES.get(finding.get("category"), _DEFAULT_TEMPLATE)
    return {
        "severity": finding.get("severity"),
        "risk_score": risk.get("risk_score"),
        "explanation": tmpl["explanation"],
        "impact": tmpl["impact"],
        "attack_scenario": tmpl["attack_scenario"],
        "recommendation": tmpl["recommendation"],
        "confidence": round(risk.get("confidence", 0.8), 2),
        "source": "template",  # "groq" once a live call succeeds
    }


def analyze_finding(finding: dict, risk: dict) -> dict:
    """Return the structured AI analysis for one finding. Never raises --
    falls back to a template so /scan-derived endpoints stay demoable
    without a Groq key configured."""
    if finding.get("status") != "OPEN":
        return {
            "severity": finding.get("severity"),
            "risk_score": risk.get("risk_score", 0),
            "explanation": "This check passed -- no issue detected.",
            "impact": "None.",
            "attack_scenario": "Not applicable.",
            "recommendation": "No action needed.",
            "confidence": 1.0,
            "source": "rule",
        }

    if is_configured():
        result = call_groq_json(SYSTEM_PROMPT, _user_prompt(finding, risk))
        if result and all(k in result for k in ("explanation", "impact", "attack_scenario", "recommendation")):
            result.setdefault("confidence", 0.8)
            result["severity"] = finding.get("severity")
            result["risk_score"] = risk.get("risk_score")
            result["source"] = "groq"
            return result

    return _template_analysis(finding, risk)
