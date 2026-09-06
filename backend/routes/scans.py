import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import Scan, Finding, AuditLog, Remediation
from backend.schemas import ScanCreate, ScanResponse
from backend.services.scan_service import run_full_scan
from backend.services.resource_service import sync_resources
from backend.services.aws.remediation import plan_remediation


router = APIRouter(
    prefix="/platform/scans",
    tags=["Platform - Scans"]
)


# Run a complete AWS security scan
@router.post("/run")
def run_scan(db: Session = Depends(get_db)):

    # Run all AWS scanners
    result = run_full_scan()

    # Extract and save discovered AWS resources
    sync_resources(result.get("findings", []), db)

    severity = result.get("severity_summary", {})

    # Create scan record
    new_scan = Scan(
        scan_type="full_aws_scan",
        status="completed",
        total_findings=result.get("total_findings", 0),
        high_findings=severity.get("HIGH", 0),
        medium_findings=severity.get("MEDIUM", 0),
        low_findings=severity.get("LOW", 0)
    )

    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # Attach remediation plan to every finding before persisting or returning
    for f in result.get("findings", []):
        f["remediation"] = plan_remediation(f)

    # Save findings and automatically create remediation tasks
    for finding in result.get("findings", []):

        # Scanner returns: resource_id, resource_type, finding, severity, category, evidence, status
        # Map to ORM fields: title←finding text, description←"category: evidence summary"
        evidence_str = json.dumps(finding.get("evidence", {}))
        new_finding = Finding(
            title=finding.get("finding", "Unknown Finding"),
            description=f"{finding.get('category', '')} | {evidence_str}",
            severity=finding.get("severity", "INFO"),
            status="open",
            recommendation=finding.get("remediation", {}).get("description"),
            scan_id=new_scan.id
        )

        db.add(new_finding)
        db.commit()
        db.refresh(new_finding)

        # Automatically create remediation for important findings
        if finding.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]:

            # Store full scanner dict so approve_remediation() can call executor
            finding_snapshot = {k: finding.get(k) for k in [
                "resource_id", "resource_type", "finding", "severity",
                "category", "evidence", "status", "finding_id"
            ]}

            remediation = Remediation(
                title=f"Remediate: {finding.get('finding', 'Security Issue')}",
                description=f"{finding.get('category', '')} | {evidence_str}",
                recommendation=finding.get("remediation", {}).get("description"),
                finding_id=new_finding.id,
                finding_json=json.dumps(finding_snapshot),
                status="PENDING",
                approved=False
            )

            db.add(remediation)


    # Save all remediation tasks
    db.commit()

    # Create audit log
    audit_log = AuditLog(
        action="Security scan completed",
        resource_type="AWS Infrastructure",
        resource_id=str(new_scan.id),
        details=f"Full AWS security scan completed with {result.get('total_findings', 0)} findings."
    )

    db.add(audit_log)
    db.commit()

    return {
        "message": "Scan completed successfully",
        "scan_id": new_scan.id,
        "total_findings": result.get("total_findings", 0),
        "severity_summary": severity,
        "findings": result.get("findings", [])
    }


# Create a new scan record manually
@router.post("/", response_model=ScanResponse)
def create_scan(
    scan: ScanCreate,
    db: Session = Depends(get_db)
):
    new_scan = Scan(
        scan_type=scan.scan_type,
        status=scan.status,
        total_findings=scan.total_findings,
        high_findings=scan.high_findings,
        medium_findings=scan.medium_findings,
        low_findings=scan.low_findings
    )

    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    return new_scan


# Get scan history
@router.get("/", response_model=list[ScanResponse])
def get_scans(db: Session = Depends(get_db)):

    scans = (
        db.query(Scan)
        .order_by(Scan.created_at.desc())
        .all()
    )

    return scans