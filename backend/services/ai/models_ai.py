"""Request models for backend/services/ai/routes.py. Kept separate from
Nayef's backend/models.py since these are Masooma's endpoints' contracts;
merge into the shared file if/when Sireen wires OpenAPI codegen for the
frontend."""

from typing import Optional
from pydantic import BaseModel


class AnalyzeFindingRequest(BaseModel):
    finding: dict


class RemediationApplyRequest(BaseModel):
    finding: dict
    confirm: bool = False
    approved_by: Optional[str] = None


class RollbackRequest(BaseModel):
    finding_id: str
