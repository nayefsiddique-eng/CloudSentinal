"""
Remediation Execution.

The only function here that actually changes AWS. Sequence, per Team Plan
sections 5-7:

    Safety Gate check
      -> Backup (snapshot current state)
      -> Apply fix (Nayef's apply_remediation)
      -> Verify (re-check the specific control)
      -> if verification fails: automatic Rollback
      -> Audit log every step (who/what/when/before/after/result)

`approved_by` stands in for Sireen's future auth/user system -- pass a
name/identifier string for anything in the APPROVAL_REQUIRED tier. AUTO_
ALLOWED findings don't need it. NEVER_AUTO findings are refused no matter
what is passed.
"""

from backend.services.aws.remediation import apply_remediation
from backend.services.ai import safety_gate, backup, verification, audit_log


def execute_remediation(finding: dict, approved_by: str | None = None) -> dict:
    decision = safety_gate.gate(finding)

    if decision["tier"] == safety_gate.NEVER_AUTO:
        audit_log.record({
            "finding_id": finding.get("finding_id"), "resource_id": finding.get("resource_id"),
            "action": "remediation_refused", "tier": decision["tier"], "reason": decision["reason"],
        })
        return {"executed": False, "reason": decision["reason"], "tier": decision["tier"]}

    if not decision["has_coded_fix"]:
        return {"executed": False, "reason": decision["remediation_plan"]["description"], "tier": decision["tier"]}

    if decision["tier"] == safety_gate.APPROVAL_REQUIRED and not approved_by:
        return {
            "executed": False,
            "reason": "This action needs human approval before it can run.",
            "tier": decision["tier"],
            "requires_approval": True,
        }

    # --- Backup ---
    before = backup.snapshot(finding)

    # --- Apply ---
    apply_result = apply_remediation(finding)

    if not apply_result.get("applied"):
        audit_log.record({
            "finding_id": finding.get("finding_id"), "resource_id": finding.get("resource_id"),
            "action": "remediation_apply_failed", "approved_by": approved_by,
            "before": before["state"], "result": apply_result,
        })
        return {"executed": False, "reason": apply_result.get("error") or apply_result.get("reason"),
                "tier": decision["tier"]}

    # --- Verify ---
    verify_result = verification.verify_finding(finding)

    rollback_result = None
    if verify_result["status"] == verification.VERIFICATION_FAILED:
        rollback_result = backup.restore(finding.get("finding_id"))

    audit_log.record({
        "finding_id": finding.get("finding_id"),
        "resource_id": finding.get("resource_id"),
        "resource_type": finding.get("resource_type"),
        "action": "remediation_applied",
        "tier": decision["tier"],
        "approved_by": approved_by,
        "before": before["state"],
        "apply_result": apply_result,
        "verification": verify_result,
        "rollback": rollback_result,
    })

    return {
        "executed": True,
        "tier": decision["tier"],
        "apply_result": apply_result,
        "verification": verify_result,
        "rollback": rollback_result,
        "finding_status": "RESOLVED" if verify_result["status"] == verification.VERIFICATION_PASSED else "STILL_OPEN",
    }


def rollback_remediation(finding_id: str) -> dict:
    result = backup.restore(finding_id)
    audit_log.record({"finding_id": finding_id, "action": "manual_rollback", "result": result})
    return result
