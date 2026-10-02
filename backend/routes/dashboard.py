from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import Finding, Scan, Resource


router = APIRouter(
    prefix="/platform/dashboard",
    tags=["Platform - Dashboard"]
)


@router.get("/")
def get_dashboard_summary(db: Session = Depends(get_db)):

    # Get all findings
    findings = db.query(Finding).all()

    # Severity counts
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for finding in findings:
        severity = finding.severity.upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

    # Calculate security score
    score = 100
    score -= severity_counts["CRITICAL"] * 20
    score -= severity_counts["HIGH"] * 10
    score -= severity_counts["MEDIUM"] * 5
    score -= severity_counts["LOW"] * 2
    score = max(score, 0)

    # Dashboard summary
    return {
        "security_score": score,
        "total_findings": len(findings),

        "critical": severity_counts["CRITICAL"],
        "high": severity_counts["HIGH"],
        "medium": severity_counts["MEDIUM"],
        "low": severity_counts["LOW"],

        "total_scans": db.query(Scan).count(),
        "resources_scanned": db.query(Resource).count()
    }