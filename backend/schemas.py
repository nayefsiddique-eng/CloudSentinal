from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Optional


class ScanCreate(BaseModel):
    scan_type: str
    status: Optional[str] = "completed"

    total_findings: Optional[int] = 0
    high_findings: Optional[int] = 0
    medium_findings: Optional[int] = 0
    low_findings: Optional[int] = 0


class ScanResponse(ScanCreate):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ResourceResponse(BaseModel):
    id: int
    resource_type: str
    resource_name: str
    resource_id: str
    region: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditLogCreate(BaseModel):
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    details: Optional[str] = None


class AuditLogResponse(BaseModel):
    id: int
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    details: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)