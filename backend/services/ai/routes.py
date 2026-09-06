"""
Masooma's endpoints. Mounted onto the same `app` in backend/main.py via
`app.include_router(ai_router)` -- see that file for the one-line wiring.
Deliberately namespaced so nothing collides with Nayef's existing
/scan* and /remediate routes:

  GET  /scan/analyzed          full scan + risk score + AI explanation for every OPEN finding
  POST /ai/analyze             risk + AI explanation + safety tier for one finding
  POST /remediation/preview    risk + safety tier + plan for one finding (no LLM call, fast)
  POST /remediation/apply      actually apply a fix (backup -> apply -> verify -> audit)
  POST /remediation/rollback   restore a resource to its pre-remediation snapshot
  GET  /remediation/history    recent remediation actions from the audit log
"""

from fastapi import APIRouter, HTTPException

from backend.services.scan_service import run_full_scan
from backend.services.ai import risk_engine, pipeline, executor, audit_log, safety_gate
from backend.services.ai.models_ai import AnalyzeFindingRequest, RemediationApplyRequest, RollbackRequest

router = APIRouter()


@router.get("/scan/analyzed")
def scan_analyzed():
    """Same data /scan gives Sireen, plus Masooma's full pipeline output
    for every open finding -- what the Findings Detail view in the Team
    Plan's dashboard section is meant to render."""
    scan = run_full_scan()
    analyzed = pipeline.analyze_scan(scan["findings"])
    return {
        "total_findings": scan["total_findings"],
        "severity_summary": scan["severity_summary"],
        "errors": scan["errors"],
        **analyzed,
    }


@router.post("/ai/analyze")
def ai_analyze(req: AnalyzeFindingRequest):
    if "resource_id" not in req.finding or "finding" not in req.finding:
        raise HTTPException(status_code=422, detail="finding must at least include resource_id and finding text.")
    return pipeline.analyze_finding(req.finding)


@router.post("/remediation/preview")
def remediation_preview(req: AnalyzeFindingRequest):
    """Lightweight preview: risk + safety tier + plan, no LLM call. Use
    this for the findings LIST view; use /ai/analyze (or /scan/analyzed)
    when the user opens the detail view and wants the full explanation."""
    finding = req.finding
    risk = risk_engine.score_finding(finding)
    decision = safety_gate.gate(finding)
    return {
        "finding_id": finding.get("finding_id"),
        "risk": risk,
        "tier": decision["tier"],
        "reason": decision["reason"],
        "can_execute": decision["can_execute"],
        "requires_approval": decision["requires_approval"],
        "plan": decision["remediation_plan"],
    }


@router.post("/remediation/apply")
def remediation_apply(req: RemediationApplyRequest):
    if not req.confirm:
        raise HTTPException(status_code=400, detail="confirm=true is required to apply a fix.")

    result = executor.execute_remediation(req.finding, approved_by=req.approved_by)
    if not result["executed"]:
        status = 403 if result.get("requires_approval") else 422
        raise HTTPException(status_code=status, detail=result["reason"])
    return result


@router.post("/remediation/rollback")
def remediation_rollback(req: RollbackRequest):
    result = executor.rollback_remediation(req.finding_id)
    if not result.get("rolled_back"):
        raise HTTPException(status_code=422, detail=result.get("reason") or result.get("error") or "Rollback failed.")
    return result


@router.get("/remediation/history")
def remediation_history(limit: int = 100):
    return {"events": audit_log.history(limit=limit)}
