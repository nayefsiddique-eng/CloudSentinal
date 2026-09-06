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

app = FastAPI(title="CloudSentinel")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

