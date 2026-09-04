from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import Remediation, AuditLog


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


# Approve remediation
@router.put("/{remediation_id}/approve")
def approve_remediation(
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

    remediation.status = "APPROVED"
    remediation.approved = True

    # Create audit log
    audit_log = AuditLog(
        action="Remediation approved",
        resource_type="Remediation",
        resource_id=str(remediation.id),
        details=f"Remediation '{remediation.title}' was approved."
    )

    db.add(audit_log)
    db.commit()
    db.refresh(remediation)

    return remediation


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