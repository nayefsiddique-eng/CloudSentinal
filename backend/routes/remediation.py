from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.database.models import Remediation, AuditLog, Finding, Resource
from backend.database.models import Remediation, AuditLog, Finding, Resource
from backend.database.database import get_db
from backend.database.models import Remediation, AuditLog, Finding
from backend.services.remediation_engine import remediation_engine

router = APIRouter(
    prefix="/platform/remediation",
    tags=["Platform - Remediation"]
)


@router.get("/")
def get_remediations(db: Session = Depends(get_db)):
    remediations = (
        db.query(Remediation)
        .order_by(Remediation.created_at.desc())
        .all()
    )
    return remediations


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


@router.put("/{remediation_id}/approve")
def approve_remediation(
    remediation_id: int,
    db: Session = Depends(get_db)
):
    """
    Approve and execute a remediation.

    Flow:
        DB remediation
            ↓
        Finding
            ↓
        Safety/remediation plan
            ↓
        AWS modification
            ↓
        Re-scan verification
            ↓
        Audit log
    """

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

    # Prevent accidental duplicate execution
    if remediation.status in ["SUCCESS", "EXECUTING"]:
        raise HTTPException(
            status_code=409,
            detail=f"Remediation is already {remediation.status.lower()}"
        )

    if not remediation.finding_id:
        raise HTTPException(
            status_code=400,
            detail="Remediation is not linked to a finding"
        )

    finding = (
        db.query(Finding)
        .filter(Finding.id == remediation.finding_id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Associated finding not found"
        )

    # Convert SQLAlchemy finding into the dictionary format
    # expected by the remediation engine.
    finding_data = {
        "finding_id": finding.id,
        "resource_id": getattr(finding, "resource_id", None),
        "resource_type": getattr(finding, "resource_type", None),
        "finding": getattr(finding, "finding", None),
        "severity": getattr(finding, "severity", "INFO"),
        "category": getattr(finding, "category", None),
        "risk_score": getattr(finding, "risk_score", None),
        "risk_level": getattr(finding, "risk_level", None),
        "safety_classification": getattr(
            finding,
            "safety_classification",
            None
        ),
        "requires_approval": True,
        "automatically_allowed": False,
        "automatically_blocked": False,
    }

    # Mark as approved/executing before touching AWS.
    remediation.status = "EXECUTING"
    remediation.approved = True

    db.add(
        AuditLog(
            action="Remediation approved",
            resource_type="Remediation",
            resource_id=str(remediation.id),
            details=(
                f"Remediation '{remediation.title}' approved "
                f"for finding {finding.id}."
            )
        )
    )

    db.commit()
    db.refresh(remediation)

    # Execute the actual AWS remediation.
    result = remediation_engine.execute_remediation(
        finding=finding_data,
        approved_by="platform_user",
        confirm=True
    )

    # Store final state in the database.
    final_status = result.get("status", "failed").upper()

    if final_status == "SUCCESS":
        remediation.status = "SUCCESS"
    elif final_status == "FAILED":
        remediation.status = "FAILED"
    else:
        remediation.status = final_status

    remediation.approved = True

    # Audit execution result.
    db.add(
        AuditLog(
            action=f"Remediation {remediation.status}",
            resource_type=finding_data.get("resource_type"),
            resource_id=str(
                finding_data.get("resource_id", "")
            ),
            details=str({
                "remediation_id": remediation.id,
                "finding_id": finding.id,
                "result": result
            })
        )
    )

    db.commit()
    db.refresh(remediation)

    return {
        "remediation": remediation,
        "execution": result
    }


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

    if remediation.status == "SUCCESS":
        raise HTTPException(
            status_code=409,
            detail="Successful remediation cannot be rejected"
        )

    remediation.status = "REJECTED"
    remediation.approved = False

    db.add(
        AuditLog(
            action="Remediation rejected",
            resource_type="Remediation",
            resource_id=str(remediation.id),
            details=(
                f"Remediation '{remediation.title}' "
                f"was rejected."
            )
        )
    )

    db.commit()
    db.refresh(remediation)

    return remediation