from typing import Optional
import json
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.auth import get_current_actor
from backend.database.database import get_db
from backend.database.models import AuditLog
from backend.schemas import AuditLogCreate, AuditLogResponse


router = APIRouter(
    prefix="/platform/audit-logs",
    tags=["Platform - Audit Logs"]
)


# Get all audit logs
@router.get("/", response_model=list[AuditLogResponse])
def get_audit_logs(db: Session = Depends(get_db)):

    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .all()
    )

    return logs


# Create an audit log manually (requires authentication)
@router.post("/", response_model=AuditLogResponse)
def create_audit_log(
    log_data: Optional[AuditLogCreate] = None,
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    resource_id: Optional[str] = Query(None),
    details: Optional[str] = Query(None),
    actor: str = Depends(get_current_actor),
    db: Session = Depends(get_db)
):
    # Support both JSON request body and query params (for backwards compatibility)
    req_action = log_data.action if log_data and log_data.action else action
    req_resource_type = log_data.resource_type if log_data and log_data.resource_type else resource_type
    req_resource_id = log_data.resource_id if log_data and log_data.resource_id else resource_id
    req_details = log_data.details if log_data and log_data.details else details

    if not req_action:
        from fastapi import HTTPException
        raise HTTPException(status_code=422, detail="Action field is required.")

    # Structure details with server-enforced, un-spoofable actor identity and metadata
    structured_details = {
        "user_details": req_details,
        "actor": actor,
        "source": "api_manual_entry"
    }

    new_log = AuditLog(
        action=f"[{actor}] {req_action}",
        resource_type=req_resource_type,
        resource_id=req_resource_id,
        details=json.dumps(structured_details)
    )

    db.add(new_log)
    db.commit()
    db.refresh(new_log)

    return new_log