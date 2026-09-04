from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import Finding


router = APIRouter(
    prefix="/platform/findings",
    tags=["Platform - Findings"]
)


# Get all findings
@router.get("/")
def get_findings(db: Session = Depends(get_db)):

    findings = (
        db.query(Finding)
        .order_by(Finding.id.desc())
        .all()
    )

    return findings


# Get a specific finding by ID
@router.get("/{finding_id}")
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db)
):

    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found"
        )

    return finding