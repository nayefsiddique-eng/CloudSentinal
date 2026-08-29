# Handoff Notes - Detection Module (Nayef)

## What is done and working

14 detection rules across 5 AWS services, all verified true-positive and
true-negative against a live AWS account. Exposed via FastAPI.

## What Masooma needs (Risk & AI Engine)

Call `GET /scan` to get the full findings list. Each finding follows this
exact schema - build the risk engine and AI prompts against this shape:

```json
{
  "resource_id": "string",
  "resource_type": "s3_bucket | iam_user | security_group | cloudtrail | lambda_function",
  "finding": "human-readable description",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "category": "PUBLIC_ACCESS | DATA_PROTECTION | IDENTITY_SECURITY | EXCESSIVE_PERMISSIONS | CREDENTIAL_HYGIENE | NETWORK_SECURITY | LOGGING_MONITORING",
  "evidence": { "...rule-specific data..." },
  "status": "OPEN | RESOLVED"
}
```

The `severity` field here is a rule-assigned default, not yet a computed
risk score - that is what the risk engine should turn into a numeric
0-10 score using severity x exposure x asset criticality x confidence.

Labeled dataset for evaluation is in `dataset/secure/`, `dataset/vulnerable/`,
and `dataset/labels/ground_truth.json` (240 configs).

## What Sireen needs (Platform & Dashboard)

- `GET /scan` returns `{ total_findings, severity_summary, findings, errors }`
  - `severity_summary` is ready to drop straight into dashboard summary cards
  - `errors` shows which scanners failed (partial-failure safe, does not
    crash the whole response)
- Per-service endpoints also exist if you want to filter by tab:
  `/scan/s3`, `/scan/iam`, `/scan/ec2`, `/scan/cloudtrail`, `/scan/lambda`
- Swagger docs at `/docs` for live testing against the running server
- Unit tests live in `tests/test_scanners.py` (pytest) - run with `pytest -v`

## Known limitations / things to watch

- Lambda scanner is untested against a real function (account currently has
  zero Lambda functions) - logic is written the same way as the other
  scanners, but flag it if something looks off once a real function exists
- CloudTrail is not yet set up for real in this AWS account (deferred)
- Scanner identity (cloudsentinel-dev) is read-only by design - anything
  that needs write access (remediation) must use a separate, more
  privileged identity, following the same pattern as the `admin` profile
  used for test-lab setup
