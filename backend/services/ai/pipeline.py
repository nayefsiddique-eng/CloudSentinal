"""
Pipeline -- the single entry point that ties Risk -> AI -> Remediation ->
Safety together into one "analyze this finding" call, and a bulk version
for a whole /scan response. Used by routes.py; also perfectly reusable
from a notebook/test for the evaluation work (Sireen's Research Evaluation
section, or Masooma's own precision/recall write-up).
"""

from backend.services.ai import risk_engine, ai_engine, safety_gate


def analyze_finding(finding: dict) -> dict:
    risk = risk_engine.score_finding(finding)
    analysis = ai_engine.analyze_finding(finding, risk)
    decision = safety_gate.gate(finding)

    return {
        "finding_id": finding.get("finding_id"),
        "resource_id": finding.get("resource_id"),
        "resource_type": finding.get("resource_type"),
        "finding": finding.get("finding"),
        "status": finding.get("status"),
        "risk": risk,
        "ai_analysis": analysis,
        "remediation": {
            "tier": decision["tier"],
            "reason": decision["reason"],
            "can_execute": decision["can_execute"],
            "requires_approval": decision["requires_approval"],
            "plan": decision["remediation_plan"],
        },
    }


def analyze_scan(findings: list[dict], open_only: bool = True) -> dict:
    targets = [f for f in findings if f.get("status") == "OPEN"] if open_only else findings
    analyzed = [analyze_finding(f) for f in targets]
    analyzed.sort(key=lambda a: a["risk"]["risk_score"], reverse=True)

    return {
        "total_analyzed": len(analyzed),
        "by_tier": {
            tier: len([a for a in analyzed if a["remediation"]["tier"] == tier])
            for tier in (safety_gate.AUTO_ALLOWED, safety_gate.APPROVAL_REQUIRED, safety_gate.NEVER_AUTO)
        },
        "findings": analyzed,
    }
