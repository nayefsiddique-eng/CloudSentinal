"""
Response schema contract for /scan and /scan/<service>.

This is the exact shape described in HANDOFF.md, formalized so FastAPI
validates it and shows it in /docs -- Masooma's risk engine and Sireen's
DB schema should both be built against these fields, not a hand-copied
JSON example.
"""

from typing import Literal, Optional
from pydantic import BaseModel


ResourceType = Literal[
    "s3_bucket", "iam_user", "iam_account", "security_group", "cloudtrail", "lambda_function"
]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
Category = Literal[
    "PUBLIC_ACCESS", "DATA_PROTECTION", "IDENTITY_SECURITY", "EXCESSIVE_PERMISSIONS",
    "CREDENTIAL_HYGIENE", "NETWORK_SECURITY", "LOGGING_MONITORING", "SCAN_ERROR",
]
Status = Literal["OPEN", "RESOLVED", "ERROR"]
RemediationKind = Literal["automatable", "manual_action_required", "no_action_needed"]


class RemediationPlan(BaseModel):
    kind: RemediationKind
    description: str
    risk: Optional[str] = None


class Finding(BaseModel):
    finding_id: str
    resource_id: str
    resource_type: ResourceType
    finding: str
    severity: Severity
    category: Category
    evidence: dict
    status: Status
    remediation: Optional[RemediationPlan] = None


class ScanError(BaseModel):
    scanner: str
    error: str


class SeveritySummary(BaseModel):
    CRITICAL: int
    HIGH: int
    MEDIUM: int
    LOW: int
    INFO: int


class ScanResult(BaseModel):
    total_findings: int
    severity_summary: SeveritySummary
    findings: list[Finding]
    errors: list[ScanError]


class SingleScannerResult(BaseModel):
    findings: list[Finding]
    errors: list[ScanError]
