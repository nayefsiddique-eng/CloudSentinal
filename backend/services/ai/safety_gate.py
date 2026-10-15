"""
Safety / Policy Gate.

Classifies every finding into exactly one of three tiers (Team Plan
section 4). This is the ONLY thing that decides whether executor.py is
allowed to touch AWS -- it never consults the AI Analysis Engine's output,
only the deterministic finding/category/evidence, so a bad LLM response
can never talk its way into a higher-privilege action.

  AUTO_ALLOWED     -- reversible, additive, no-blast-radius. Executor may
                      apply immediately.
  APPROVAL_REQUIRED-- reversible but could break something in active use.
                      Executor requires an explicit `approved=True` from
                      a human click (Sireen's "Approve & Apply" button).
  NEVER_AUTO       -- irreversible or identity/access-altering at a level
                      that could lock someone out or break production.
                      Executor refuses unconditionally, always.

Separation of Concerns:
- Safety Tier: AUTO_ALLOWED, APPROVAL_REQUIRED, NEVER_AUTO
- Implementation Status: IMPLEMENTED vs NOT_IMPLEMENTED
- Execution Eligibility: can_execute is True ONLY IF implementation is IMPLEMENTED
  and tier is not NEVER_AUTO.
"""

from backend.services.aws.remediation import plan_remediation

AUTO_ALLOWED = "AUTO_ALLOWED"
APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
NEVER_AUTO = "NEVER_AUTO"

IMPLEMENTED = "IMPLEMENTED"
NOT_IMPLEMENTED = "NOT_IMPLEMENTED"

# Finding-text substrings that are safe to auto-apply once a coded
# fix exists -- purely additive controls with minimal risk of breaking a
# workload (enabling something, never removing/restricting access).
_AUTO_ALLOWED_MARKERS = (
    "Block Public Access is disabled",
    "Versioning is disabled",
    "Encryption is disabled",
    "Weak password policy",
)

# Findings that change/restrict something a live workload might depend on.
# Reversible, but needs a human's "yes, apply it" click.
_APPROVAL_REQUIRED_MARKERS = (
    "Bucket is publicly accessible",   # ACL reset to private -- could break a public site
    "access key(s) older than 90 days",  # deactivating a key in active use breaks it
)

# Never auto-applied, ever, regardless of confirm=true -- identity/access
# changes with real lock-out or break-everything blast radius, or resource
# types with high risk (e.g., wildcards, MFA).
_NEVER_AUTO_MARKERS = (
    "Root account MFA",
    "MFA is not enabled",
    "wildcard",
)


def classify_safety(finding: dict) -> dict:
    """Return {"tier", "reason"} for a finding, independent of whether a
    coded fix exists yet."""
    text = finding.get("finding", "")

    if finding.get("status") != "OPEN" or finding.get("category") == "SCAN_ERROR":
        return {"tier": NEVER_AUTO, "reason": "Not an open, actionable finding."}

    for marker in _NEVER_AUTO_MARKERS:
        if marker.lower() in text.lower():
            return {"tier": NEVER_AUTO, "reason": f"Identity/access change ('{marker}') -- always requires a human."}

    for marker in _APPROVAL_REQUIRED_MARKERS:
        if marker.lower() in text.lower():
            return {"tier": APPROVAL_REQUIRED, "reason": "Reversible, but could affect an active workload -- needs approval."}

    for marker in _AUTO_ALLOWED_MARKERS:
        if marker.lower() in text.lower():
            return {"tier": AUTO_ALLOWED, "reason": "Purely additive, reversible control -- safe to auto-apply."}

    # Fallback: if not identified as auto-allowed or never-auto, mark as approval-required for safety
    return {"tier": APPROVAL_REQUIRED, "reason": "Requires human review and approval."}


def gate(finding: dict) -> dict:
    """Full gate decision: combines the safety tier with whether a real,
    reviewed remediation implementation exists for this finding."""
    plan = plan_remediation(finding)
    safety = classify_safety(finding)

    has_coded_fix = plan.get("kind") == "automatable"
    impl_status = IMPLEMENTED if has_coded_fix else NOT_IMPLEMENTED

    # Execution is strictly prohibited if NEVER_AUTO or if no implementation exists
    can_execute = (impl_status == IMPLEMENTED) and (safety["tier"] in (AUTO_ALLOWED, APPROVAL_REQUIRED))

    return {
        "tier": safety["tier"],
        "reason": safety["reason"],
        "implementation_status": impl_status,
        "has_coded_fix": has_coded_fix,
        "requires_approval": safety["tier"] == APPROVAL_REQUIRED,
        "can_execute": can_execute,
        "remediation_plan": plan,
    }
