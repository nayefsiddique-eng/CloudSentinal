from fastapi import FastAPI
from backend.services.scan_service import run_full_scan
from backend.services.aws.s3 import scan_s3_buckets
from backend.services.aws.iam import scan_iam_users
from backend.services.aws.ec2 import scan_security_groups
from backend.services.aws.cloudtrail import scan_cloudtrail
from backend.services.aws.lambda_scanner import scan_lambda_functions

app = FastAPI(title="CloudSentinel")


def _run_scanner(name: str, scanner_fn):
    """Run a single scanner and return a findings/errors payload instead of
    letting an unhandled AWS/boto3 exception surface as a raw 500 traceback."""
    try:
        return {"findings": scanner_fn(), "errors": []}
    except Exception as e:
        return {"findings": [], "errors": [{"scanner": name, "error": str(e)}]}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/scan")
def scan_all():
    return run_full_scan()


@app.get("/scan/s3")
def scan_s3():
    return _run_scanner("s3", scan_s3_buckets)


@app.get("/scan/iam")
def scan_iam():
    return _run_scanner("iam", scan_iam_users)


@app.get("/scan/ec2")
def scan_ec2():
    return _run_scanner("ec2", scan_security_groups)


@app.get("/scan/cloudtrail")
def scan_ct():
    return _run_scanner("cloudtrail", scan_cloudtrail)


@app.get("/scan/lambda")
def scan_lambda():
    return _run_scanner("lambda", scan_lambda_functions)
