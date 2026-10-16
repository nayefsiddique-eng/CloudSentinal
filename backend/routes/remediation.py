import json
import logging
from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session

from backend.auth import get_current_actor
from backend.database.database import get_db
from backend.database.models import Remediation, AuditLog, Finding
from backend.services.ai import executor as ai_executor, safety_gate

logger = logging.getLogger("cloudsentinel.remediation")

router = APIRouter(
    prefix="/platform/remediation",
    tags=["Platform - Remediation"]
)

# Allowed lifecycle states
# PENDING -> APPROVED / EXECUTED / FAILED / REJECTED / BLOCKED / LEGACY_SCAN_REQUIRED
VALID_TRANSITIONS = {
    "PENDING": {"APPROVED", "EXECUTED", "FAILED", "REJECTED", "BLOCKED"},
    "BLOCKED": {"REJECTED"},
    "FAILED": {"PENDING", "REJECTED"},
    "APPROVED": {"EXECUTED", "FAILED"},
    "EXECUTED": set(),  # terminal state
    "REJECTED": set(),  # terminal state
    "LEGACY_SCAN_REQUIRED": set(), # requires a fresh scan to populate valid finding data
}


def _enrich_remediation_dict(rem: Remediation) -> dict:
    """Enriches a Remediation DB model with safety tier, implementation status,
    actionability, and manual guidance for the UI/API consumer."""
    base = {
        "id": rem.id,
        "finding_id": rem.finding_id,
        "title": rem.title,
        "description": rem.description,
        "recommendation": rem.recommendation,
        "status": rem.status,
        "approved": rem.approved,
        "created_at": rem.created_at.isoformat() if rem.created_at else None,
        "safety_tier": safety_gate.NEVER_AUTO,
        "implementation_status": safety_gate.NOT_IMPLEMENTED,
        "can_execute": False,
        "requires_approval": True,
        "reason": "Finding data unavailable.",
        "is_legacy": False,
        "resource_id": None,
        "resource_type": None,
        "severity": None,
    }

    if not rem.finding_json:
        base["is_legacy"] = True
        base["status"] = "LEGACY_SCAN_REQUIRED" if rem.status == "PENDING" else rem.status
        base["reason"] = "Legacy record without stored finding details. Run a new scan to enable remediation."
        return base

    try:
        finding = json.loads(rem.finding_json)
        base["resource_id"] = finding.get("resource_id")
        base["resource_type"] = finding.get("resource_type")
        base["severity"] = finding.get("severity")

        gate_decision = safety_gate.gate(finding)
        base["safety_tier"] = gate_decision["tier"]
        base["implementation_status"] = gate_decision["implementation_status"]
        base["can_execute"] = gate_decision["can_execute"]
        base["requires_approval"] = gate_decision["requires_approval"]
        base["reason"] = gate_decision["reason"]
        base["plan"] = gate_decision["remediation_plan"]
    except Exception as e:
        base["reason"] = f"Failed to parse finding JSON: {str(e)}"

    return base


# Get all remediation tasks
@router.get("/")
def get_remediations(db: Session = Depends(get_db)):
    remediations = (
        db.query(Remediation)
        .order_by(Remediation.created_at.desc())
        .all()
    )
    return [_enrich_remediation_dict(r) for r in remediations]


# Get single remediation task
@router.get("/{remediation_id}")
def get_remediation(remediation_id: int, db: Session = Depends(get_db)):
    remediation = (
        db.query(Remediation)
        .filter(Remediation.id == remediation_id)
        .first()
    )
    if not remediation:
        raise HTTPException(status_code=404, detail="Remediation not found")
    return _enrich_remediation_dict(remediation)


# Create remediation task manually (requires authentication)
@router.post("/")
def create_remediation(
    title: str,
    description: str = None,
    recommendation: str = None,
    finding_id: int = None,
    actor: str = Depends(get_current_actor),
    db: Session = Depends(get_db)
):
    remediation = Remediation(
        title=title,
        description=description,
        recommendation=recommendation,
        finding_id=finding_id,
        status="PENDING",
        approved=False
    )

    db.add(remediation)
    db.commit()
    db.refresh(remediation)

    return _enrich_remediation_dict(remediation)


# Approve & execute remediation
@router.put("/{remediation_id}/approve")
def approve_remediation(
    remediation_id: int,
    actor: str = Depends(get_current_actor),
    db: Session = Depends(get_db)
):

    remediation = (
        db.query(Remediation)
        .filter(Remediation.id == remediation_id)
        .first()
    )

    if not remediation:
        raise HTTPException(
            status_code=404,
            detail="Remediation not found"
        )

    # State transition & idempotency checks
    if remediation.status == "EXECUTED":
        raise HTTPException(
            status_code=409,
            detail="Remediation has already been executed."
        )

    if remediation.status == "REJECTED":
        raise HTTPException(
            status_code=409,
            detail="Cannot approve a rejected remediation."
        )

    # Handle legacy records without fabricating data
    if not remediation.finding_json:
        remediation.status = "LEGACY_SCAN_REQUIRED"
        db.commit()
        db.refresh(remediation)
        raise HTTPException(
            status_code=422,
            detail=(
                "Legacy remediation record missing raw finding payload. "
                "Trigger a fresh scan (/platform/scans/run) to review and remediate this finding."
            )
        )

    # Reconstruct the scanner finding dict
    try:
        finding = json.loads(remediation.finding_json)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Corrupt finding JSON payload: {str(e)}")

    # Authoritative Safety Gate evaluation
    decision = safety_gate.gate(finding)

    # Rule 1 & 5: NEVER_AUTO must NEVER execute
    if decision["tier"] == safety_gate.NEVER_AUTO:
        remediation.status = "BLOCKED"
        db.commit()
        db.refresh(remediation)
        raise HTTPException(
            status_code=422,
            detail=f"Safety Policy Refusal: {decision['reason']} (Tier: NEVER_AUTO)"
        )

    # Rule 3: Actions without implemented automation must not execute
    if decision["implementation_status"] != safety_gate.IMPLEMENTED:
        remediation.status = "BLOCKED"
        db.commit()
        db.refresh(remediation)
        raise HTTPException(
            status_code=422,
            detail=f"Remediation implementation is not available for this finding: {decision['remediation_plan'].get('description')}"
        )

    # Re-validate execution permissions
    if not decision["can_execute"]:
        remediation.status = "BLOCKED"
        db.commit()
        db.refresh(remediation)
        raise HTTPException(
            status_code=422,
            detail=f"Execution blocked by safety policy: {decision['reason']}"
        )

    # Mark approved before dispatching execution
    remediation.approved = True

    # Execute remediation via executor
    exec_result = ai_executor.execute_remediation(finding, approved_by=actor)

    # Enforce invariant: only transition to EXECUTED if verification actually resolved the finding
    if exec_result.get("executed") and exec_result.get("finding_status") == "RESOLVED":
        remediation.status = "EXECUTED"
    else:
        remediation.status = "FAILED"

    # Persist audit record in DB
    audit_log = AuditLog(
        action=f"[{actor}] " + ("Remediation approved and executed" if exec_result.get("executed") else "Remediation approval failed"),
        resource_type=finding.get("resource_type", "Remediation"),
        resource_id=finding.get("resource_id", str(remediation.id)),
        details=json.dumps({
            "remediation_id": remediation.id,
            "actor": actor,
            "approved_by": actor,
            "source": "platform_remediation_executor",
            "executed": exec_result.get("executed"),
            "tier": exec_result.get("tier"),
            "finding_status": exec_result.get("finding_status"),
            "verification": exec_result.get("verification"),
            "reason": exec_result.get("reason"),
            "user_details": f"Tier {exec_result.get('tier')} execution: {exec_result.get('reason') or ('Resolved' if exec_result.get('executed') else 'Failed')}"
        })
    )

    db.add(audit_log)
    db.commit()
    db.refresh(remediation)

    return {
        "remediation_id": remediation.id,
        "status": remediation.status,
        "approved": remediation.approved,
        "approved_by": actor,
        **exec_result,
    }


# Reject remediation
@router.put("/{remediation_id}/reject")
def reject_remediation(
    remediation_id: int,
    actor: str = Depends(get_current_actor),
    db: Session = Depends(get_db)
):

    remediation = (
        db.query(Remediation)
        .filter(Remediation.id == remediation_id)
        .first()
    )

    if not remediation:
        raise HTTPException(
            status_code=404,
            detail="Remediation not found"
        )

    if remediation.status == "EXECUTED":
        raise HTTPException(
            status_code=409,
            detail="Cannot reject a remediation that has already been executed."
        )

    remediation.status = "REJECTED"
    remediation.approved = False

    audit_log = AuditLog(
        action=f"[{actor}] Remediation rejected",
        resource_type="Remediation",
        resource_id=str(remediation.id),
        details=json.dumps({
            "remediation_id": remediation.id,
            "actor": actor,
            "rejected_by": actor,
            "source": "platform_remediation_reviewer",
            "title": remediation.title,
            "user_details": f"Remediation #{remediation.id} for '{remediation.title}' rejected by operator."
        })
    )

    db.add(audit_log)
    db.commit()
    db.refresh(remediation)

    return _enrich_remediation_dict(remediation)