## 1. Overview

CloudSentinel follows a modular architecture that integrates AWS security scanners, a FastAPI backend, PostgreSQL database, React frontend, AI-assisted analysis, and remediation capabilities.

The architecture separates security detection, data management, analysis, and user interaction into independent components.

---

## 2. High-Level Architecture

```text
                         ┌───────────────┐
                         │     User      │
                         └───────┬───────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │   React Frontend       │
                    │   Security Dashboard   │
                    └───────────┬────────────┘
                                │ REST API
                                ▼
                    ┌────────────────────────┐
                    │   FastAPI Backend      │
                    │   Platform API Layer   │
                    └───────────┬────────────┘
                                │
          ┌─────────────────────┼──────────────────────┐
          │                     │                      │
          ▼                     ▼                      ▼
 ┌────────────────┐    ┌────────────────┐    ┌────────────────┐
 │ AWS Security   │    │ PostgreSQL     │    │ AI Analysis    │
 │ Scanners       │    │ Database       │    │ Engine         │
 └───────┬────────┘    └────────────────┘    └────────────────┘
         │
         ▼
 ┌─────────────────────────────────────────────────────┐
 │                    AWS Services                     │
 │                                                     │
 │   S3 • IAM • EC2 • Lambda • CloudTrail             │
 └─────────────────────────────────────────────────────┘
```

---

# 3. Frontend Architecture

The frontend is developed using React.

It provides a centralized interface for users to monitor their cloud security posture.

### Main frontend modules:

* Dashboard
* Findings
* Scan History
* Resources
* Audit Logs
* Remediation Center

The frontend communicates with the FastAPI backend using REST APIs.

Example API flow:

```text
React Frontend
      │
      │ HTTP Request
      ▼
FastAPI API Endpoint
      │
      ▼
Database / AWS Scanner
      │
      ▼
JSON Response
      │
      ▼
React Dashboard
```

---

# 4. Backend Architecture

The backend is developed using FastAPI.

The backend acts as the central communication layer between:

* AWS security scanners
* PostgreSQL database
* Frontend dashboard
* AI analysis engine
* Remediation system

### Backend Modules

```text
backend/
│
├── routes/
│   ├── dashboard.py
│   ├── findings.py
│   ├── scans.py
│   ├── resources.py
│   ├── audit_logs.py
│   ├── remediation.py
│   └── security_score.py
│
├── services/
│   ├── scan_service.py
│   ├── resource_service.py
│   └── aws/
│
├── database/
│   ├── database.py
│   ├── models.py
│   └── init_db.py
│
└── main.py
```

---

# 5. AWS Security Scanning Architecture

CloudSentinel performs security scanning across multiple AWS services.

The supported services include:

```text
AWS Account
     │
     ▼
AWS Scanner Engine
     │
 ┌───┼────┬──────┬────────┬───────────┐
 ▼   ▼    ▼      ▼        ▼
S3  IAM  EC2   Lambda  CloudTrail
 │   │    │      │        │
 └───┴────┴──────┴────────┘
              │
              ▼
        Security Findings
              │
              ▼
         FastAPI Backend
```

The scanner output contains detected findings and severity information.

---

# 6. Database Architecture

CloudSentinel uses PostgreSQL to store platform and security-related information.

The database manages:

* Users
* AWS Resources
* Security Scans
* Findings
* Risk Scores
* Remediation Tasks
* Remediation Logs
* Audit Logs

### Database Flow

```text
AWS Scan
   │
   ▼
Security Findings
   │
   ▼
FastAPI Backend
   │
   ▼
PostgreSQL Database
   │
   ├── Scans
   ├── Findings
   ├── Resources
   ├── Remediation
   └── Audit Logs
```

---

# 7. Security Score Architecture

The security score provides an overall representation of cloud security posture.

The system begins with a score of 100 and deducts points depending on detected security findings.

Current deduction logic:

```text
Critical Finding → -20 points
High Finding     → -10 points
Medium Finding   → -5 points
Low Finding      → -2 points
```

The final score cannot fall below zero.

---

# 8. AI Analysis Integration

The AI Analysis Engine enhances traditional rule-based findings.

The AI system is designed to process security findings and generate:

* Plain-English explanation
* Security impact
* Possible attack scenario
* Recommended remediation

Architecture:

```text
Security Finding
       │
       ▼
AI Analysis Engine
       │
       ├── Explanation
       ├── Impact Analysis
       ├── Attack Scenario
       └── Recommended Fix
               │
               ▼
        CloudSentinel Platform
```

---

# 9. Remediation Architecture

The remediation system manages security fixes through controlled approval.

```text
Security Finding
       │
       ▼
Remediation Recommendation
       │
       ▼
Remediation Task
       │
       ├── Pending
       │
       ├── Approved
       │
       └── Rejected
```

Future architecture supports:

* Automated remediation
* Policy-based approval
* AWS API execution
* Configuration backup
* Rollback
* Post-remediation verification

---

# 10. Evaluation Architecture

CloudSentinel supports comparison between three detection approaches.

```text
                 Security Dataset
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
   Rule-Based       AI-Only       Hybrid System
         │             │             │
         └─────────────┼─────────────┘
                       ▼
              Evaluation Engine
                       │
           ┌───────────┼───────────┐
           ▼           ▼           ▼
       Precision     Recall      F1 Score
```

The hybrid CloudSentinel approach combines deterministic security detection with AI-assisted analysis.


