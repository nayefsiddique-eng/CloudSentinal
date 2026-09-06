"""
Risk Engine -- turns a rule-assigned `severity` into a numeric 0-10 risk
score, per HANDOFF.md's spec:

    risk_score = severity_weight x exposure x asset_criticality x confidence

This is deliberately deterministic (no LLM) so it is cheap, reproducible,
and defensible in the research paper/viva. The AI Analysis Engine
(ai_engine.py) explains findings; this module scores them.

Methodology (document this in the report):

- severity_weight  (0-10)   : the scanner's own CRITICAL..INFO call, the
                               baseline signal.
- exposure         (0.5-1.0): how reachable the misconfiguration is.
                               Internet-facing (public S3 bucket, SSH/RDP
                               open to 0.0.0.0/0, public Lambda URL) scores
                               1.0; account-internal issues (weak password
                               policy, missing encryption) score lower.
- asset_criticality(0.5-1.0): how sensitive the resource class is. Identity
                               boundaries (root/IAM) and audit logging
                               (CloudTrail) are weighted highest because
                               their compromise cascades to everything else.
- confidence       (0.6-1.0): how directly the scanner observed the fact.
                               A boolean API read (e.g. versioning status)
                               is high confidence; a heuristic (e.g.
                               regex-matching env var *names* for secrets)
                               is lower confidence because it can false-positive.

Final score = 10 x (severity_weight/10) x exposure x asset_criticality x confidence,
rounded to 1 decimal, capped to [0, 10].
"""

from typing import TypedDict

SEVERITY_WEIGHT = {
    "CRITICAL": 10.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 2.0,
    "INFO": 0.0,
}

# Resource-class sensitivity. Override per-account by passing a
# `criticality_overrides` dict (e.g. {"prod-payments-bucket": 1.0}) once
# Sireen's `resources` table can tag production vs dev assets.
ASSET_CRITICALITY = {
    "iam_account": 1.0,
    "iam_user": 0.75,
    "cloudtrail": 0.9,
    "s3_bucket": 0.8,
    "security_group": 0.85,
    "lambda_function": 0.75,
}

# category -> baseline exposure if we can't inspect evidence further.
CATEGORY_EXPOSURE = {
    "PUBLIC_ACCESS": 1.0,
    "NETWORK_SECURITY": 1.0,
    "IDENTITY_SECURITY": 0.85,
    "EXCESSIVE_PERMISSIONS": 0.8,
    "CREDENTIAL_HYGIENE": 0.65,
    "DATA_PROTECTION": 0.6,
    "LOGGING_MONITORING": 0.7,
    "SCAN_ERROR": 0.0,
}

# Findings we're less sure about (heuristics / string matching rather than
# a direct boolean API read) get a lower confidence factor.
LOW_CONFIDENCE_MARKERS = (
    "possible secrets",  # lambda_scanner regex match on env var *names*
)


class RiskResult(TypedDict):
    risk_score: float
    priority: str
    exposure: float
    asset_criticality: float
    confidence: float
    severity_weight: float


def _exposure(finding: dict) -> float:
    category = finding.get("category", "")
    base = CATEGORY_EXPOSURE.get(category, 0.7)

    evidence = finding.get("evidence", {}) or {}
    # Sharpen the category default with the actual evidence where we have it.
    if category == "PUBLIC_ACCESS" and "public" in evidence:
        return 1.0 if evidence["public"] else 0.3
    if category == "NETWORK_SECURITY" and "open_ports" in evidence:
        return 1.0 if evidence["open_ports"] else 0.3
    return base


def _confidence(finding: dict) -> float:
    text = finding.get("finding", "").lower()
    if any(marker in text for marker in LOW_CONFIDENCE_MARKERS):
        return 0.7
    if finding.get("category") == "SCAN_ERROR":
        return 0.0
    return 0.95


def _priority(score: float) -> str:
    if score >= 9:
        return "P1"
    if score >= 7:
        return "P2"
    if score >= 4:
        return "P3"
    if score >= 1:
        return "P4"
    return "P5"


def score_finding(finding: dict, criticality_overrides: dict | None = None) -> RiskResult:
    """Score a single Finding dict. Non-destructive -- returns a new dict,
    caller decides whether to merge it into the finding."""
    severity_weight = SEVERITY_WEIGHT.get(finding.get("severity", "INFO"), 0.0)

    overrides = criticality_overrides or {}
    resource_id = finding.get("resource_id")
    resource_type = finding.get("resource_type", "")
    asset_criticality = overrides.get(resource_id, ASSET_CRITICALITY.get(resource_type, 0.7))

    exposure = _exposure(finding)
    confidence = _confidence(finding)

    raw = 10 * (severity_weight / 10) * exposure * asset_criticality * confidence
    risk_score = round(min(max(raw, 0.0), 10.0), 1)

    return {
        "risk_score": risk_score,
        "priority": _priority(risk_score),
        "exposure": exposure,
        "asset_criticality": asset_criticality,
        "confidence": confidence,
        "severity_weight": severity_weight,
    }


def score_findings(findings: list[dict], criticality_overrides: dict | None = None) -> list[dict]:
    """Score a whole /scan findings list, attaching `risk` to each finding
    and returning them sorted highest-risk first (what the dashboard wants)."""
    scored = []
    for f in findings:
        f = dict(f)
        f["risk"] = score_finding(f, criticality_overrides)
        scored.append(f)
    scored.sort(key=lambda f: f["risk"]["risk_score"], reverse=True)
    return scored
