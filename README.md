# CloudSentinel

AI-Powered AWS Cloud Security Scanning and Auto-Remediation Platform

Team: CyberSentinel - Nayef, Masooma, Sireen

---

## Overview

CloudSentinel discovers AWS resources, detects security misconfigurations
across IAM, S3, EC2, and CloudTrail, and (in later phases) uses AI to
explain findings and generate safe, verified auto-remediation.

Pipeline:

Scan -> Detect -> Score Risk -> AI Explains -> AI Proposes Fix -> Safety Gate -> Approve/Auto-Apply -> Re-scan -> Verify

---

## Status

| Module          | Status       | Notes                                    |
|-----------------|--------------|-------------------------------------------|
| AWS Connector   | Done         | Authenticated boto3 session               |
| S3 Scanner      | Done         | 3 rules: public bucket, versioning, encryption |
| IAM Scanner     | Done         | 3 rules: MFA, wildcard perms, old keys     |
| EC2 Scanner     | Done         | 2 rules: SSH/RDP exposed, unrestricted inbound |
| CloudTrail Scanner | Done      | 1 rule: logging disabled                   |
| FastAPI Layer   | Done         | /scan, /scan/s3, /scan/iam, /scan/ec2, /scan/cloudtrail |
| Risk Engine     | Planned      | Owned by Masooma                           |
| AI Engine       | Planned      | Owned by Masooma                           |
| Remediation     | Planned      | Owned by Masooma                           |
| Dashboard       | Planned      | Owned by Sireen                            |

Total working detection rules: 9
Verified true positive and true negative against live AWS resources.

---

## Tech Stack

- Backend: Python, FastAPI
- AWS SDK: boto3
- Frontend (planned): React + Vite
- Database (planned): PostgreSQL
- AI Layer (planned): API-based LLM

---

## Quick Start

1. Clone and enter the repo
   git clone https://github.com/nayefsiddique-eng/CloudSentinal.git
   cd CloudSentinal

2. Create and activate a virtual environment
   python -m venv venv
   .\venv\Scripts\Activate.ps1

3. Install dependencies
   pip install -r requirements.txt

4. Configure AWS credentials
   copy .env.example .env
   (edit .env and fill in your AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY)

5. Run the server
   uvicorn backend.main:app --reload

6. Open the interactive API docs
   http://127.0.0.1:8000/docs

---

## API Endpoints

| Method | Endpoint          | Description                          |
|--------|-------------------|----------------------------------------|
| GET    | /health           | Health check                           |
| GET    | /scan             | Runs all scanners, returns combined findings + severity summary |
| GET    | /scan/s3          | S3 bucket findings only                |
| GET    | /scan/iam         | IAM user findings only                 |
| GET    | /scan/ec2         | EC2 security group findings only       |
| GET    | /scan/cloudtrail  | CloudTrail findings only               |

Example response shape:

{
  "resource_id": "example-bucket",
  "resource_type": "s3_bucket",
  "finding": "Bucket is publicly accessible",
  "severity": "HIGH",
  "category": "PUBLIC_ACCESS",
  "evidence": { "public": true },
  "status": "OPEN"
}

Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO

---

## Project Structure

CloudSentinel/
  backend/
    main.py                    FastAPI app and routes
    services/
      scan_service.py          Aggregates all scanners into one report
      aws/
        client.py              Authenticated boto3 session
        account.py             Account identity check
        s3.py                  S3 scanner
        iam.py                 IAM scanner
        ec2.py                 EC2 security group scanner
        cloudtrail.py          CloudTrail scanner
  dataset/
    secure/                    Labeled secure configs (for evaluation)
    vulnerable/                Labeled vulnerable configs (for evaluation)
  tests/                       Unit tests
  .env.example                 Template for required environment variables
  requirements.txt

---

## Team Roles

- Nayef: AWS Security and Detection Lead - resource discovery, security rules, dataset
- Masooma: AI and Remediation Lead - risk scoring, AI analysis, remediation, safety controls, verification
- Sireen: Platform and Research Lead - backend APIs, database, dashboard, testing, evaluation

---

## Security Notes

- The scanner identity (cloudsentinel-dev) is intentionally read-only.
- A separate admin identity is used only for test-lab setup, never by the scanner code.
- Dangerous remediation actions will always require manual approval; nothing
  with high blast radius will ever auto-execute.
