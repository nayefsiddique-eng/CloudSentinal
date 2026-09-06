# CloudSentinel Evaluation

## 1. Evaluation Objective

The purpose of the evaluation is to compare different approaches for identifying cloud security threats and determine the effectiveness of the CloudSentinel hybrid architecture.

The evaluation compares:

* Rule-Based Detection
* AI-Only Analysis
* Full CloudSentinel Hybrid Approach

The evaluation module was created as part of the Platform & Research responsibilities, which require comparison using precision, recall, and F1-score. 

---

## 2. Evaluation Approaches

### 2.1 Rule-Based Detection

The rule-based approach uses predefined AWS security rules to identify misconfigurations.

Examples include:

* Publicly accessible S3 buckets
* Missing MFA configuration
* Exposed SSH/RDP ports
* Disabled CloudTrail logging
* Excessive Lambda permissions

The project's scanning foundation covers 17 detection rules across S3, IAM, EC2, CloudTrail, and Lambda. 

---

### 2.2 AI-Only Analysis

The AI-only approach analyzes security-related information using the integrated AI Analysis Engine (`backend/services/ai/ai_engine.py` and `groq_client.py`).

The AI component provides:

* Plain-English explanation of security findings
* Security impact and potential threat context
* Concrete attack scenario illustration
* Actionable remediation recommendations

The AI engine uses the Groq LLM API (`llama-3.3-70b`) with an automatic, deterministic template fallback mechanism if `GROQ_API_KEY` is not set.

---

### 2.3 Full CloudSentinel

The full CloudSentinel approach combines:

```text
Rule-Based Detection
        +
Risk Scoring Engine (severity_weight × exposure × criticality × confidence)
        +
3-Tier Safety Gate (AUTO_ALLOWED / APPROVAL_REQUIRED / NEVER_AUTO)
        +
AI-Assisted Contextual Analysis
        ↓
Hybrid CloudSentinel Pipeline
```

The hybrid architecture combines deterministic detection rules, dynamic risk scoring, safety-gated execution, and AI-generated contextual analysis.

---

# 3. Implemented AI & Remediation Architecture

### 3.1 Risk Scoring Formula
Risk score is dynamically calculated for each finding using the formula:

$$\text{Risk Score} = \text{Severity Weight} \times \text{Exposure Multiplier} \times \text{Asset Criticality} \times \text{Confidence}$$

- **Severity Weight**: CRITICAL (10), HIGH (7), MEDIUM (4), LOW (1), INFO (0)
- **Exposure Multiplier**: Public (2.0), Internal (1.0)
- **Asset Criticality**: Root/Admin (1.5), Production (1.2), Standard (1.0)
- **Confidence**: High (1.0), Medium (0.8), Low (0.5)

### 3.2 3-Tier Safety Gate
Every finding is classified before remediation execution:
1. `AUTO_ALLOWED`: Purely additive, low-risk, reversible fixes (e.g. enabling S3 block public access, versioning, default encryption).
2. `APPROVAL_REQUIRED`: Reversible fixes that could impact active workloads (e.g. ACL resets, deactivating 90+ day access keys).
3. `NEVER_AUTO`: Identity/access changes with potential lock-out risk (e.g. MFA enforcement, root account changes, wildcard permission removal).

### 3.3 Backup, Verification, and Rollback Loop
The remediation execution pipeline (`backend/services/ai/executor.py`) follows a robust 5-step loop:
1. **Safety Gate Verification**: Ensures tier permission and human approval if required.
2. **State Backup**: Pre-remediation configuration snapshot is stored.
3. **Fix Application**: Executes the remediation handler (`apply_remediation()`).
4. **Post-Fix Verification**: Re-runs specific control checks to confirm resolution.
5. **Automatic Rollback & Audit**: Restores previous snapshot automatically if verification fails; logs audit trail.

---

# 4. Evaluation Metrics


The following metrics are used.

## Precision

Precision measures how many detected threats were actually threats.

```text
Precision = TP / (TP + FP)
```

Where:

* TP = True Positive
* FP = False Positive

---

## Recall

Recall measures how many actual threats were correctly detected.

```text
Recall = TP / (TP + FN)
```

Where:

* FN = False Negative

---

## F1 Score

The F1-score combines Precision and Recall.

```text
F1 = 2 × (Precision × Recall) / (Precision + Recall)
```

---

# 4. Evaluation Dataset

The evaluation pipeline currently uses a structured test dataset containing:

* Resource type
* Expected security label
* Rule-based prediction
* AI prediction
* Hybrid system prediction

The project also has a labeled dataset of AWS configurations intended for later evaluation. 

---

# 5. Initial Prototype Results

The current evaluation pipeline produced the following results using the prototype test dataset:

| Approach           | Precision | Recall | F1 Score |
| ------------------ | --------: | -----: | -------: |
| Rule-Based         |      0.80 |   0.80 |     0.80 |
| AI-Only            |      0.83 |   1.00 |     0.91 |
| Full CloudSentinel |      1.00 |   1.00 |     1.00 |

## Important Note

These results are **initial prototype validation results generated using the current test dataset**.

They should not be presented as final large-scale benchmark results. A complete evaluation should use the team's labeled AWS configuration dataset and actual outputs from all three approaches.

---

# 6. Remediation Success Rate

The project task breakdown also requires measuring remediation success rate. 

The metric is calculated as:

```text
Remediation Success Rate =
Successful Verified Remediations
──────────────────────────────── × 100
Total Remediation Attempts
```

A remediation should only be considered successful after the system verifies that the underlying security issue has been resolved.

---

# 7. Evaluation Workflow

```text
Labeled Security Dataset
          │
          ▼
 ┌────────┼─────────┐
 ▼        ▼         ▼
Rule     AI      Hybrid
Based   Only   CloudSentinel
 │        │         │
 └────────┼─────────┘
          ▼
   Compare Predictions
          │
          ▼
 Precision / Recall / F1
```

---

# 8. Future Evaluation

Future evaluation will include:

* Testing against the complete labeled AWS dataset
* Automated generation of predictions
* Comparison of all three approaches
* Measurement of remediation success rate
* Post-remediation verification
* Larger-scale performance testing
