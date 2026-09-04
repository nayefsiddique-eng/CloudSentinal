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
from backend.database.database import Base, engine
from backend.database import models

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

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/scan")
def scan_all():
    return run_full_scan()


@app.get("/scan/s3")
def scan_s3():
    return {"findings": scan_s3_buckets()}


@app.get("/scan/iam")
def scan_iam():
    return {"findings": scan_iam_users()}


@app.get("/scan/ec2")
def scan_ec2():
    return {"findings": scan_security_groups()}


@app.get("/scan/cloudtrail")
def scan_ct():
    return {"findings": scan_cloudtrail()}


@app.get("/scan/lambda")
def scan_lambda():
    return {"findings": scan_lambda_functions()}
