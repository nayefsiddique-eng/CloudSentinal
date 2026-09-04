Software Requirements Specification (SRS)
CloudSentinel — AWS Cloud Security Scanning & Auto-Remediation Platform
1. Introduction
1.1 Purpose

CloudSentinel is an AWS Cloud Security Scanning and Auto-Remediation Platform designed to identify security misconfigurations in cloud infrastructure, analyze their severity, calculate security posture, and provide remediation recommendations.

The system combines rule-based AWS security scanning with AI-assisted analysis to help users understand security findings and prioritize remediation actions.

1.2 Scope

CloudSentinel monitors AWS cloud resources and detects security misconfigurations across supported AWS services.

The platform provides:

AWS security scanning
Detection of security misconfigurations
Severity classification
Security score calculation
Findings management
AWS resource monitoring
Scan history
Audit logging
Remediation management
AI-assisted security analysis
Evaluation of detection approaches
1.3 Target Users

The primary users of CloudSentinel include:

Cloud administrators
Security analysts
DevOps engineers
AWS infrastructure teams
2. Overall Description
2.1 Product Perspective

CloudSentinel is a cloud security monitoring platform that connects to AWS infrastructure and analyzes resources using predefined security detection rules.

The system collects findings from AWS services and stores security-related information in a PostgreSQL database. A FastAPI backend exposes APIs that communicate with a React-based frontend dashboard.

The AI component enhances findings by generating understandable security explanations, potential impacts, and remediation recommendations.

2.2 System Components

CloudSentinel consists of the following major components:

AWS Security Scanners
FastAPI Backend
PostgreSQL Database
React Frontend Dashboard
AI Analysis Engine
Remediation Engine
Evaluation Module
3. Functional Requirements
FR1 — AWS Security Scanning

The system shall scan supported AWS services for security misconfigurations.

Supported services include:

Amazon S3
AWS IAM
Amazon EC2
AWS Lambda
AWS CloudTrail

The scanning module shall detect predefined security risks and generate findings.

FR2 — Findings Management

The system shall store detected security findings.

Each finding should contain information such as:

Finding title
Description
Severity
Resource type
Resource identifier
Status
Recommendation
FR3 — Security Score

The system shall calculate an overall cloud security score.

The score shall be calculated based on the severity and number of detected findings.

Severity levels include:

Critical
High
Medium
Low
FR4 — Dashboard

The system shall provide a centralized security dashboard.

The dashboard shall display:

Security score
Total findings
Severity distribution
Total scans
Resources scanned
Recent findings
FR5 — Scan History

The system shall maintain a history of completed security scans.

Each scan record shall include:

Scan ID
Scan type
Scan status
Total findings
Severity counts
Scan timestamp
FR6 — Resource Monitoring

The system shall maintain information about discovered AWS resources.

The system shall allow users to view monitored cloud resources.

FR7 — Audit Logging

The system shall maintain audit logs for important platform activities.

Examples include:

Security scan completion
Resource changes
Remediation approval
Remediation rejection
FR8 — Remediation Management

The system shall allow remediation tasks to be created for security findings.

Users shall be able to:

View remediation tasks
Approve remediation actions
Reject remediation actions
Track remediation status
FR9 — AI-Assisted Security Analysis

The system shall support integration with an AI analysis engine.

The AI component shall provide:

Plain-English explanation of security findings
Potential security impact
Possible attack scenario
Recommended remediation actions
FR10 — Evaluation Module

The system shall support evaluation of different security detection approaches.

The evaluation compares:

Rule-based detection
AI-only analysis
Hybrid CloudSentinel approach

The evaluation metrics include:

Precision
Recall
F1-score
4. Non-Functional Requirements
NFR1 — Performance

The system should process security scans efficiently and display results without unnecessary delay.

NFR2 — Security

AWS credentials shall be securely managed using environment variables and shall not be exposed in source code.

NFR3 — Scalability

The platform architecture should support additional AWS services and security detection rules in the future.

NFR4 — Usability

The frontend dashboard should provide a simple and understandable interface for viewing cloud security information.

NFR5 — Reliability

The system should handle scanner failures gracefully and continue processing available AWS services.

NFR6 — Maintainability

The system should follow a modular architecture to allow independent updates to scanners, backend APIs, AI modules, and frontend components.

5. System Constraints

CloudSentinel depends on:

AWS account access
AWS API permissions
Internet connectivity
PostgreSQL database availability
Python runtime environment
Node.js environment for the frontend
6. Future Enhancements

Future versions of CloudSentinel may include:

Automated remediation execution
Rollback functionality
Post-remediation verification scans
Advanced AI risk scoring
Additional AWS service support
Real-time alerts
Role-based access control
Cloud deployment