# CloudSentinel System Diagrams

## 1. High-Level System Architecture

```mermaid
flowchart TD
    U[User] --> F[React Frontend Dashboard]
    F --> B[FastAPI Backend]

    B --> S[AWS Security Scanner Engine]
    B --> DB[(PostgreSQL Database)]
    B --> AI[AI Analysis Engine]
    B --> R[Remediation Engine]

    S --> AWS[AWS Account]

    AWS --> S3[S3]
    AWS --> IAM[IAM]
    AWS --> EC2[EC2]
    AWS --> L[Lambda]
    AWS --> CT[CloudTrail]

    S --> B
    AI --> B
    R --> B
```

---

## 2. Security Scan Data Flow

```mermaid
flowchart LR
    U[User] -->|Run Security Scan| FE[React Frontend]
    FE -->|POST Request| API[FastAPI Backend]
    API --> SCAN[Scan Service]

    SCAN --> S3[S3 Scanner]
    SCAN --> IAM[IAM Scanner]
    SCAN --> EC2[EC2 Scanner]
    SCAN --> LAMBDA[Lambda Scanner]
    SCAN --> CT[CloudTrail Scanner]

    S3 --> FIND[Security Findings]
    IAM --> FIND
    EC2 --> FIND
    LAMBDA --> FIND
    CT --> FIND

    FIND --> DB[(PostgreSQL)]
    FIND --> SCORE[Security Score]
    SCORE --> API
    DB --> API
    API --> FE
```

---

## 3. Use Case Diagram

```mermaid
flowchart LR
    USER[Security Analyst / Cloud Administrator]

    USER --> SCAN[Run Security Scan]
    USER --> DASH[View Security Dashboard]
    USER --> FIND[View Security Findings]
    USER --> RES[View AWS Resources]
    USER --> HIST[View Scan History]
    USER --> AUDIT[View Audit Logs]
    USER --> REM[Manage Remediation]

    REM --> APPROVE[Approve Remediation]
    REM --> REJECT[Reject Remediation]

    SCAN --> AWS[AWS Cloud Infrastructure]
```

---

## 4. Security Scan Sequence

```mermaid
sequenceDiagram
    actor User
    participant Frontend
    participant Backend
    participant Scanner
    participant AWS
    participant Database

    User->>Frontend: Click Run Security Scan
    Frontend->>Backend: POST /platform/scans/run
    Backend->>Scanner: run_full_scan()
    Scanner->>AWS: Request resource configurations
    AWS-->>Scanner: AWS configuration data
    Scanner-->>Backend: Security findings
    Backend->>Database: Store scan and resources
    Backend-->>Frontend: Scan results
    Frontend-->>User: Display updated dashboard
```

---

## 5. Evaluation Workflow

```mermaid
flowchart TD
    D[Security Dataset] --> RB[Rule-Based Detection]
    D --> AI[AI-Only Analysis]
    D --> HY[Full CloudSentinel Hybrid]

    RB --> E[Evaluation Metrics]
    AI --> E
    HY --> E

    E --> P[Precision]
    E --> R[Recall]
    E --> F[F1 Score]
```


