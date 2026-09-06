import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import Remediation, AuditLog
from backend.services.ai import executor as ai_executor


router = APIRouter(
    prefix="/platform/remediation",
    tags=["Platform - Remediation"]
)


# Get all remediation tasks
@router.get("/")
def get_remediations(db: Session = Depends(get_db)):

    remediations = (
        db.query(Remediation)
        .order_by(Remediation.created_at.desc())
        .all()
    )

    return remediations


# Create remediation task
@router.post("/")
def create_remediation(
    title: str,
    description: str = None,
    recommendation: str = None,
    finding_id: int = None,
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

    return remediation


# Approve remediation — calls executor.execute_remediation() on the stored finding
@router.put("/{remediation_id}/approve")
def approve_remediation(
    remediation_id: int,
    approved_by: str = "platform_user",
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

    if not remediation.finding_json:
        raise HTTPException(
            status_code=422,
            detail=(
                "This remediation row has no finding_json — it was created before "
                "Task 3 wiring. Re-run a scan to create a new row with full finding data."
            )
        )

    # Reconstruct the scanner finding dict and call the full executor pipeline
    finding = json.loads(remediation.finding_json)

    exec_result = ai_executor.execute_remediation(finding, approved_by=approved_by)

    if exec_result.get("executed"):
        remediation.status = "EXECUTED"
        remediation.approved = True
    else:
        # Safety gate refusal or apply failure — surface reason, keep PENDING
        remediation.status = "FAILED"

    # Write execution result summary into AuditLog
    audit_log = AuditLog(
        action="Remediation approved and executed" if exec_result.get("executed") else "Remediation approval failed",
        resource_type="Remediation",
        resource_id=str(remediation.id),
        details=json.dumps({
            "executed": exec_result.get("executed"),
            "tier": exec_result.get("tier"),
            "finding_status": exec_result.get("finding_status"),
            "verification": exec_result.get("verification"),
            "reason": exec_result.get("reason"),
        })
    )

    db.add(audit_log)
    db.commit()
    db.refresh(remediation)

    return {
        "remediation_id": remediation.id,
        "status": remediation.status,
        **exec_result,
    }


# Reject remediation
@router.put("/{remediation_id}/reject")
def reject_remediation(
    remediation_id: int,
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

    remediation.status = "REJECTED"
    remediation.approved = False

    # Create audit log
    audit_log = AuditLog(
        action="Remediation rejected",
        resource_type="Remediation",
        resource_id=str(remediation.id),
        details=f"Remediation '{remediation.title}' was rejected."
    )

    db.add(audit_log)
    db.commit()
    db.refresh(remediation)

    return remediation