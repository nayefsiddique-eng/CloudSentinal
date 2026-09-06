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

We reuse Nayef's `plan_remediation()` (backend/services/aws/remediation.py)
as the source of truth for *whether a coded fix exists at all* -- this
module only adds the finer-grained tiering on top of that, per the Team
Plan's 3-tier model (Nayef's is a simpler 2-tier automatable/manual split).
"""

from backend.services.aws.remediation import plan_remediation

AUTO_ALLOWED = "AUTO_ALLOWED"
APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
NEVER_AUTO = "NEVER_AUTO"

# Finding-text substrings that are always safe to auto-apply once a coded
# fix exists -- purely additive controls with no risk of breaking a
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
# types with no vetted remediation logic yet.
_NEVER_AUTO_MARKERS = (
    "Root account MFA",
    "MFA is not enabled",
    "wildcard",
)


def classify_safety(finding: dict) -> dict:
    """Return {"tier", "reason"} for a finding, independent of whether a
    coded fix exists yet (that's `plan.kind == "automatable"`)."""
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

    # security_group, cloudtrail, lambda_function: no vetted remediation
    # logic exists in remediation.py yet -- default to requiring approval
    # rather than silently no-op'ing (matches Nayef's manual_action_required
    # default), so these still surface for a human decision.
    return {"tier": APPROVAL_REQUIRED, "reason": "No auto-safe remediation vetted for this finding type yet."}


def gate(finding: dict) -> dict:
    """Full gate decision: combines the safety tier with whether Nayef's
    remediation.py actually has a coded fix for this finding. `can_execute`
    is only True when both agree."""
    plan = plan_remediation(finding)
    safety = classify_safety(finding)

    has_coded_fix = plan["kind"] == "automatable"
    can_execute = has_coded_fix and safety["tier"] in (AUTO_ALLOWED, APPROVAL_REQUIRED)

    return {
        "tier": safety["tier"],
        "reason": safety["reason"],
        "has_coded_fix": has_coded_fix,
        "requires_approval": safety["tier"] == APPROVAL_REQUIRED,
        "can_execute": can_execute,
        "remediation_plan": plan,
    }
