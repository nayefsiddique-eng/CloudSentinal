from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import Finding


router = APIRouter(
    prefix="/platform/security-score",
    tags=["Platform - Security Score"]
)


@router.get("/")
def get_security_score(db: Session = Depends(get_db)):

    # Only count unresolved findings
    findings = db.query(Finding).filter(
        Finding.status != "RESOLVED"
    ).all()

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

    # Start with a perfect security score
    score = 100

    # Deduct points based on severity
    score -= severity_counts["CRITICAL"] * 20
    score -= severity_counts["HIGH"] * 10
    score -= severity_counts["MEDIUM"] * 5
    score -= severity_counts["LOW"] * 2

    # Score should never go below 0
    score = max(score, 0)

    return {
        "security_score": score,
        "total_findings": len(findings),
        "critical": severity_counts["CRITICAL"],
        "high": severity_counts["HIGH"],
        "medium": severity_counts["MEDIUM"],
        "low": severity_counts["LOW"]
    }