from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import AuditLog


router = APIRouter(
    prefix="/platform/audit-logs",
    tags=["Platform - Audit Logs"]
)


# Get all audit logs
@router.get("/")
def get_audit_logs(db: Session = Depends(get_db)):

    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .all()
    )

    return logs


# Create an audit log manually (useful for testing)
@router.post("/")
def create_audit_log(
    action: str,
    resource_type: str = None,
    resource_id: str = None,
    details: str = None,
    db: Session = Depends(get_db)
):

    new_log = AuditLog(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details
    )

    db.add(new_log)
    db.commit()
    db.refresh(new_log)

    return new_log