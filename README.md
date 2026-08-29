# CloudSentinel

AI-powered AWS cloud security scanning and auto-remediation platform.

## Team
- Masooma / Nayef / Sireen (CyberSentinel)

## Status
Base scanner + API layer complete: S3, IAM, EC2, CloudTrail detection rules,
exposed via FastAPI (/scan, /scan/s3, /scan/iam, /scan/ec2, /scan/cloudtrail).

## Setup

python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
uvicorn backend.main:app --reload

Visit http://127.0.0.1:8000/docs for the interactive API explorer.

## Structure

backend/
  main.py                 FastAPI app and routes
  services/
    scan_service.py        Aggregates all scanners
    aws/                    AWS connector and per-service scanners
dataset/                  Labeled configs for evaluation (secure/vulnerable)
tests/                    Unit tests
