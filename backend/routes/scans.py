from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import Scan, Finding, AuditLog, Remediation, Resource
from backend.schemas import ScanCreate, ScanResponse
from backend.services.scan_service import run_full_scan
from backend.services.resource_service import sync_resources

router = APIRouter(prefix="/platform/scans", tags=["Platform - Scans"])


@router.post("/run")
def run_scan(db: Session = Depends(get_db)):
    result = run_full_scan()

    # Persist the complete inventory, including resources with zero findings.
    sync_resources(result.get("resources", []), db)

    # Build a lookup so every finding points at its actual DB Resource row.
    resource_lookup = {r.resource_id: r for r in db.query(Resource).all()}

    severity = result.get("severity_summary", {})
    errors = result.get("errors", [])
    scan_status = "completed" if not errors else "partial_failed"

    new_scan = Scan(
        scan_type="full_aws_scan",
        status=scan_status,
        total_findings=result.get("total_findings", 0),
        high_findings=severity.get("HIGH", 0),
        medium_findings=severity.get("MEDIUM", 0),
        low_findings=severity.get("LOW", 0),
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    for finding in result.get("findings", []):
        resource = resource_lookup.get(finding.get("resource_id"))
        new_finding = Finding(
            title=finding.get("finding", "Unknown Finding"),
            description=finding.get("finding"),
            severity=finding.get("severity", "INFO"),
            status=str(finding.get("status", "OPEN")).lower(),
            recommendation=finding.get("recommendation"),
            explanation=finding.get("explanation"),
            impact=finding.get("impact"),
            attack_scenario=finding.get("attack_scenario"),
            confidence=str(finding.get("confidence")) if finding.get("confidence") is not None else None,
            risk_score=str(finding.get("risk_score")) if finding.get("risk_score") is not None else None,
            risk_level=finding.get("risk_level"),
            priority=finding.get("priority"),
            scan_id=new_scan.id,
            resource_id=resource.id if resource else None,
        )
        db.add(new_finding)
        db.flush()

        if finding.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]:
            db.add(Remediation(
                title=f"Remediate: {finding.get('finding', 'Security Issue')}",
                description=finding.get("description") or finding.get("finding"),
                recommendation=finding.get("recommendation"),
                finding_id=new_finding.id,
                status="PENDING",
                approved=False,
            ))

    db.add(AuditLog(
        action="Security scan completed" if not errors else "Security scan completed with errors",
        resource_type="AWS Infrastructure",
        resource_id=str(new_scan.id),
        details=(
            f"AWS account {result.get('account_id', 'unknown')} scanned across "
            f"{len(result.get('regions', []))} regions. "
            f"{result.get('resource_count', 0)} resources discovered, "
            f"{result.get('total_findings', 0)} findings, {len(errors)} errors."
        ),
    ))
    db.commit()

    return {
        "message": "Scan completed" if not errors else "Scan completed with errors; inspect the errors array",
        "status": scan_status,
        "scan_id": new_scan.id,
        "account_id": result.get("account_id"),
        "regions": result.get("regions", []),
        "service_count": result.get("service_count", 0),
        "resource_count": result.get("resource_count", 0),
        "total_findings": result.get("total_findings", 0),
        "severity_summary": severity,
        "errors": errors,
        "findings": result.get("findings", []),
    }


@router.get("/aws-status")
def aws_status():
    from backend.services.aws.client import get_account_context, get_regions
    context = get_account_context()
    return {
        "connected": True,
        "account_id": context["account_id"],
        "caller_arn": context.get("arn"),
        "regions": get_regions(),
    }


@router.post("/", response_model=ScanResponse)
def create_scan(scan: ScanCreate, db: Session = Depends(get_db)):
    new_scan = Scan(
        scan_type=scan.scan_type, status=scan.status,
        total_findings=scan.total_findings, high_findings=scan.high_findings,
        medium_findings=scan.medium_findings, low_findings=scan.low_findings,
    )
    db.add(new_scan); db.commit(); db.refresh(new_scan)
    return new_scan


@router.get("/", response_model=list[ScanResponse])
def get_scans(db: Session = Depends(get_db)):
    return db.query(Scan).order_by(Scan.created_at.desc()).all()
