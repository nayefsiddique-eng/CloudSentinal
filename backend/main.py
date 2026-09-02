from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from backend.services.scan_service import run_full_scan, _make_finding_id
from backend.services.aws.s3 import scan_s3_buckets
from backend.services.aws.iam import scan_iam_users
from backend.services.aws.ec2 import scan_security_groups
from backend.services.aws.cloudtrail import scan_cloudtrail
from backend.services.aws.lambda_scanner import scan_lambda_functions
from backend.services.aws.remediation import plan_remediation, apply_remediation
from backend.models import ScanResult, SingleScannerResult

app = FastAPI(title="CloudSentinel")


class RemediationRequest(BaseModel):
    finding: dict
    confirm: bool = False


def _run_scanner(name: str, scanner_fn):
    """Run a single scanner and return a findings/errors payload instead of
    letting an unhandled AWS/boto3 exception surface as a raw 500 traceback."""
    try:
        findings = scanner_fn()
        for f in findings:
            f["finding_id"] = _make_finding_id(f)
            f["remediation"] = plan_remediation(f)
        return {"findings": findings, "errors": []}
    except Exception as e:
        return {"findings": [], "errors": [{"scanner": name, "error": str(e)}]}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/scan", response_model=ScanResult)
def scan_all():
    """Detect + attach a remediation plan to every finding, so the UI can
    show a single 'Fix' button per finding without a second round trip."""
    result = run_full_scan()
    for f in result["findings"]:
        f["remediation"] = plan_remediation(f)
    return result


@app.post("/remediate")
def remediate(req: RemediationRequest):
    """The single human-click approval endpoint.

    Frontend flow: user sees a finding (with its attached remediation plan
    from /scan) and clicks "Fix". That click sends this exact finding back
    here with confirm=true. Nothing is ever applied without confirm=true,
    and findings that aren't safely automatable are refused even then.
    """
    if not req.confirm:
        raise HTTPException(status_code=400, detail="confirm=true is required to apply a fix.")

    plan = plan_remediation(req.finding)
    if plan["kind"] != "automatable":
        raise HTTPException(status_code=422, detail=plan["description"])

    result = apply_remediation(req.finding)
    if not result.get("applied"):
        raise HTTPException(status_code=502, detail=result.get("error") or result.get("reason", "Fix failed."))

    return {"finding": req.finding, "plan": plan, "result": result}


@app.get("/scan/s3", response_model=SingleScannerResult)
def scan_s3():
    return _run_scanner("s3", scan_s3_buckets)


@app.get("/scan/iam", response_model=SingleScannerResult)
def scan_iam():
    return _run_scanner("iam", scan_iam_users)


@app.get("/scan/ec2", response_model=SingleScannerResult)
def scan_ec2():
    return _run_scanner("ec2", scan_security_groups)


@app.get("/scan/cloudtrail", response_model=SingleScannerResult)
def scan_ct():
    return _run_scanner("cloudtrail", scan_cloudtrail)


@app.get("/scan/lambda", response_model=SingleScannerResult)
def scan_lambda():
    return _run_scanner("lambda", scan_lambda_functions)
