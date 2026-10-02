from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import Finding, Resource


router = APIRouter(
    prefix="/platform/findings",
    tags=["Platform - Findings"]
)


def serialize_finding(finding: Finding):
    resource = finding.resource

    return {
        "id": finding.id,

        # Human-facing information
        "title": finding.title,
        "description": finding.description,
        "explanation": finding.explanation,
        "impact": finding.impact,
        "attack_scenario": finding.attack_scenario,
        "recommendation": finding.recommendation,

        # Risk information
        "severity": finding.severity,
        "risk_score": finding.risk_score,
        "risk_level": finding.risk_level,
        "priority": finding.priority,
        "confidence": finding.confidence,

        # Status
        "status": finding.status,

        # Actual AWS resource
        "resource_id": resource.resource_id if resource else None,
        "resource_type": resource.resource_type if resource else None,
        "resource_name": resource.resource_name if resource else None,
        "region": resource.region if resource else None,

        # Database references
        "scan_id": finding.scan_id,
    }


@router.get("/")
def get_findings(db: Session = Depends(get_db)):

    findings = (
        db.query(Finding)
        .order_by(Finding.id.desc())
        .all()
    )

    return [serialize_finding(finding) for finding in findings]


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

    return serialize_finding(finding)