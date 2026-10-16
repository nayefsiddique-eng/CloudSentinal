import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.routes import scans
from backend.routes import findings
from backend.routes import security_score
from backend.routes import dashboard
from backend.routes import resources
from backend.routes import audit_logs
from backend.routes import remediation
from backend.services.scan_service import run_full_scan
from backend.services.aws.s3 import scan_s3_buckets
from backend.services.aws.iam import scan_iam_users
from backend.services.aws.ec2 import scan_security_groups
from backend.services.aws.cloudtrail import scan_cloudtrail
from backend.services.aws.lambda_scanner import scan_lambda_functions
from backend.services.aws.remediation import plan_remediation
from backend.services.ai.routes import router as ai_router
from backend.database.database import Base, engine
from backend.database import models
from backend.models import ScanResult, SingleScannerResult

Base.metadata.create_all(bind=engine)

DEFAULT_DEV_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000"
]


def get_allowed_origins() -> list[str]:
    """
    Parses and validates allowed frontend origins for CORS.
    - If ALLOWED_ORIGINS is provided, splits by comma, trims whitespace, and ignores empty entries.
    - Strictly rejects wildcard '*' when credentials are enabled.
    - In production (ENVIRONMENT=production/prod), refuses to start or fall back silently if ALLOWED_ORIGINS is missing or empty.
    - In development/local mode, falls back to standard localhost origins if ALLOWED_ORIGINS is unset.
    """
    env_origins = os.getenv("ALLOWED_ORIGINS")
    is_prod = os.getenv("ENVIRONMENT", "").lower() in ("production", "prod")

    if env_origins is not None:
        parsed = [o.strip() for o in env_origins.split(",") if o.strip()]
        if any(o == "*" for o in parsed):
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: Wildcard '*' origin is prohibited when credentials are enabled."
            )
        if not parsed:
            if is_prod:
                raise RuntimeError(
                    "CRITICAL SECURITY CONFIGURATION ERROR: ALLOWED_ORIGINS is empty in production mode. "
                    "Explicit trusted frontend origin(s) must be configured."
                )
            return DEFAULT_DEV_ORIGINS
        return parsed

    if is_prod:
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: ALLOWED_ORIGINS must be configured in production mode. "
            "Silently falling back to localhost is prohibited in production."
        )

    return DEFAULT_DEV_ORIGINS


app = FastAPI(title="CloudSentinel")

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRF-Token", "X-API-Key", "Authorization", "Accept"],
)

from backend.auth import auth_router

app.include_router(auth_router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(security_score.router)
app.include_router(dashboard.router)
app.include_router(resources.router)
app.include_router(audit_logs.router)
app.include_router(remediation.router)
app.include_router(ai_router)

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/scan", response_model=ScanResult)
def scan_all():
    result = run_full_scan()
    for f in result.get("findings", []):
        f["remediation"] = plan_remediation(f)
    return result


def _attach_remediation(findings_list: list) -> list:
    """Attach finding_id and plan_remediation to each finding from a single-scanner result."""
    from backend.services.scan_service import _make_finding_id
    for f in findings_list:
        if "finding_id" not in f:
            f["finding_id"] = _make_finding_id(f)
        f["remediation"] = plan_remediation(f)
    return findings_list



@app.get("/scan/s3", response_model=SingleScannerResult)
def scan_s3():
    findings_list = scan_s3_buckets()
    _attach_remediation(findings_list)
    return {"findings": findings_list, "errors": []}


@app.get("/scan/iam", response_model=SingleScannerResult)
def scan_iam():
    findings_list = scan_iam_users()
    _attach_remediation(findings_list)
    return {"findings": findings_list, "errors": []}


@app.get("/scan/ec2", response_model=SingleScannerResult)
def scan_ec2():
    findings_list = scan_security_groups()
    _attach_remediation(findings_list)
    return {"findings": findings_list, "errors": []}


@app.get("/scan/cloudtrail", response_model=SingleScannerResult)
def scan_ct():
    findings_list = scan_cloudtrail()
    _attach_remediation(findings_list)
    return {"findings": findings_list, "errors": []}


@app.get("/scan/lambda", response_model=SingleScannerResult)
def scan_lambda():
    findings_list = scan_lambda_functions()
    _attach_remediation(findings_list)
    return {"findings": findings_list, "errors": []}

