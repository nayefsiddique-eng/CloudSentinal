from fastapi import FastAPI
from backend.services.scan_service import run_full_scan
from backend.services.aws.s3 import scan_s3_buckets
from backend.services.aws.iam import scan_iam_users
from backend.services.aws.ec2 import scan_security_groups
from backend.services.aws.cloudtrail import scan_cloudtrail

app = FastAPI(title="CloudSentinel")


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
