"""
CloudSentinel Remediation Engine

Responsible for:
1. Creating a remediation plan
2. Enforcing safety classification
3. Executing approved automated remediation
4. Verifying the AWS change through re-scanning
5. Recording remediation audit history
"""

import json
import logging
from typing import Dict, Any
from datetime import datetime
from enum import Enum

from backend.services.aws.remediation import (
    plan_remediation,
    apply_remediation,
)
from backend.services.verification_engine import verification_engine
from backend.database import models
from backend.database.database import SessionLocal

logger = logging.getLogger(__name__)


class RemediationStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"


class RemediationEngine:

    def __init__(self):
        self.db = SessionLocal()

    def __del__(self):
        try:
            if hasattr(self, "db"):
                self.db.close()
        except Exception:
            pass

    # ============================================================
    # PLAN
    # ============================================================

    def create_remediation_plan(
        self,
        finding: Dict[str, Any]
    ) -> Dict[str, Any]:

        remediation_plan = plan_remediation(finding)

        return {
            "finding_id": finding.get("finding_id"),
            "resource_id": finding.get("resource_id"),
            "resource_type": finding.get("resource_type"),
            "finding": finding.get("finding"),
            "severity": finding.get("severity"),
            "risk_score": finding.get("risk_score"),
            "risk_level": finding.get("risk_level"),

            "remediation_plan": remediation_plan,

            "safety_classification": finding.get(
                "safety_classification"
            ),

            "requires_approval": finding.get(
                "requires_approval",
                False
            ),

            "automatically_allowed": finding.get(
                "automatically_allowed",
                False
            ),

            "automatically_blocked": finding.get(
                "automatically_blocked",
                False
            ),

            "recommended_action": (
                remediation_plan.get("description")
                if remediation_plan
                else None
            ),

            "created_at": datetime.utcnow().isoformat(),

            "status": RemediationStatus.PENDING.value,
        }

    # ============================================================
    # EXECUTION
    # ============================================================

    def execute_remediation(
        self,
        finding: Dict[str, Any],
        approved_by: str = None,
        confirm: bool = False
    ) -> Dict[str, Any]:

        plan = self.create_remediation_plan(finding)

        # --------------------------------------------------------
        # Safety check BEFORE touching AWS
        # --------------------------------------------------------

        if not self._can_execute(
            plan,
            approved_by=approved_by,
            confirm=confirm
        ):
            plan["status"] = RemediationStatus.CANCELLED.value

            return {
                "success": False,
                "message": (
                    "Remediation execution not allowed."
                ),
                "plan": plan,
                "requires_approval": plan[
                    "requires_approval"
                ],
            }

        try:

            # ----------------------------------------------------
            # EXECUTING
            # ----------------------------------------------------

            plan["status"] = (
                RemediationStatus.EXECUTING.value
            )

            plan["started_at"] = (
                datetime.utcnow().isoformat()
            )

            if approved_by:
                plan["approved_by"] = approved_by
                plan["approved_at"] = (
                    datetime.utcnow().isoformat()
                )

            # ----------------------------------------------------
            # Capture pre-remediation state
            # ----------------------------------------------------

            pre_state = self._capture_pre_state(
                finding
            )

            plan["pre_state"] = pre_state

            # ----------------------------------------------------
            # ACTUAL AWS REMEDIATION
            # ----------------------------------------------------

            result = apply_remediation(finding)

            plan["aws_result"] = result

            plan.update(result)

            plan["completed_at"] = (
                datetime.utcnow().isoformat()
            )

            # ----------------------------------------------------
            # AWS CHANGE SUCCESS
            # ----------------------------------------------------

            if result.get("applied") is True:

                # Temporarily mark successful AWS execution.
                plan["status"] = (
                    RemediationStatus.SUCCESS.value
                )

                # ------------------------------------------------
                # REAL VERIFICATION
                # ------------------------------------------------

                verification_result = (
                    self.verify_remediation(
                        finding,
                        plan
                    )
                )

                plan["verification"] = (
                    verification_result
                )

                # -----------------------------------------------
                # Verification determines final result
                # -----------------------------------------------

                if verification_result.get(
                    "verified"
                ) is True:

                    plan["status"] = (
                        RemediationStatus.SUCCESS.value
                    )

                    plan["verification_status"] = "PASSED"

                else:

                    plan["status"] = (
                        RemediationStatus.FAILED.value
                    )

                    plan["verification_status"] = "FAILED"

                    # -------------------------------------------
                    # Attempt rollback if verification fails
                    # -------------------------------------------

                    rollback_result = (
                        self.rollback_remediation(
                            finding,
                            pre_state
                        )
                    )

                    plan["rollback"] = (
                        rollback_result
                    )

            # ----------------------------------------------------
            # AWS CHANGE FAILED
            # ----------------------------------------------------

            else:

                plan["status"] = (
                    RemediationStatus.FAILED.value
                )

                plan["verification_status"] = (
                    "NOT_RUN"
                )

                # Rollback only if we have a captured state.
                if pre_state:
                    rollback_result = (
                        self.rollback_remediation(
                            finding,
                            pre_state
                        )
                    )

                    plan["rollback"] = (
                        rollback_result
                    )

            # ----------------------------------------------------
            # AUDIT
            # ----------------------------------------------------

            self._log_remediation_action(plan)

            return plan

        except Exception as e:

            logger.exception(
                "Error executing remediation"
            )

            plan["status"] = (
                RemediationStatus.FAILED.value
            )

            plan["error"] = str(e)

            plan["completed_at"] = (
                datetime.utcnow().isoformat()
            )

            self._log_remediation_action(plan)

            return plan

    # ============================================================
    # SAFETY
    # ============================================================

    def _can_execute(
        self,
        plan: Dict[str, Any],
        approved_by: str = None,
        confirm: bool = False
    ) -> bool:

        remediation_plan = plan.get(
            "remediation_plan",
            {}
        )

        # NEVER automatically execute manual actions.
        if remediation_plan.get("kind") != "automatable":
            logger.warning(
                "Remediation blocked: "
                "plan is not automatable."
            )
            return False

        # Explicit safety block.
        if plan.get("automatically_blocked"):
            logger.warning(
                "Remediation blocked by safety gate."
            )
            return False

        # Approval is mandatory for this route.
        if plan.get("requires_approval"):

            if not approved_by:
                logger.warning(
                    "Remediation requires approval."
                )
                return False

        # Explicit confirmation required.
        if not confirm:
            logger.warning(
                "Remediation requires confirmation."
            )
            return False

        return True

    # ============================================================
    # PRE-STATE
    # ============================================================

    def _capture_pre_state(
        self,
        finding: Dict[str, Any]
    ) -> Dict[str, Any]:

        """
        Capture metadata before remediation.

        NOTE:
        This currently records remediation context rather than
        a complete AWS configuration snapshot.

        Full resource-specific rollback should be implemented
        in the AWS remediation layer.
        """

        return {
            "finding_id": finding.get(
                "finding_id"
            ),

            "resource_id": finding.get(
                "resource_id"
            ),

            "resource_type": finding.get(
                "resource_type"
            ),

            "finding": finding.get(
                "finding"
            ),

            "severity": finding.get(
                "severity"
            ),

            "timestamp": datetime.utcnow().isoformat(),

            "resource_config": (
                f"Pre-remediation state captured "
                f"for {finding.get('resource_id')}"
            ),
        }

    # ============================================================
    # VERIFICATION
    # ============================================================

    def verify_remediation(
        self,
        finding: Dict[str, Any],
        remediation_plan: Dict[str, Any]
    ) -> Dict[str, Any]:

        """
        Perform real verification by invoking the
        VerificationEngine, which re-scans AWS.
        """

        try:

            verification_result = (
                verification_engine.verify_remediation(
                    original_finding=finding,
                    remediation_action=remediation_plan
                )
            )

            return verification_result

        except Exception as e:

            logger.exception(
                "Verification failed"
            )

            return {
                "status": "error",
                "verified": False,
                "verification_timestamp": (
                    datetime.utcnow().isoformat()
                ),
                "method": "re_scan_and_compare",
                "error": str(e),
            }

    # ============================================================
    # ROLLBACK
    # ============================================================

    def rollback_remediation(
        self,
        finding: Dict[str, Any],
        pre_state: Dict[str, Any]
    ) -> Dict[str, Any]:

        """
        Rollback hook.

        The current AWS remediation layer does not yet expose
        resource-specific restoration APIs, so this records the
        rollback attempt instead of falsely claiming that AWS
        state was restored.
        """

        logger.warning(
            "Rollback requested for %s, but resource-specific "
            "AWS restoration is not implemented yet.",
            finding.get("resource_id")
        )

        return {
            "rolled_back": False,

            "rollback_timestamp": (
                datetime.utcnow().isoformat()
            ),

            "method": "rollback_hook",

            "details": (
                "Rollback was requested, but actual AWS "
                "state restoration is not implemented yet."
            ),

            "restored_state": False,

            "pre_state": pre_state,
        }

    # ============================================================
    # AUDIT
    # ============================================================

    def _log_remediation_action(
        self,
        plan: Dict[str, Any]
    ):

        try:

            audit_log = models.AuditLog(
                action=(
                    f"Remediation "
                    f"{plan.get('status', 'unknown')}"
                ),

                resource_type=plan.get(
                    "resource_type"
                ),

                resource_id=str(
                    plan.get(
                        "resource_id",
                        ""
                    )
                ),

                details=json.dumps(
                    {
                        "finding_id": plan.get(
                            "finding_id"
                        ),

                        "finding": plan.get(
                            "finding"
                        ),

                        "severity": plan.get(
                            "severity"
                        ),

                        "risk_score": plan.get(
                            "risk_score"
                        ),

                        "remediation_status": plan.get(
                            "status"
                        ),

                        "approved_by": plan.get(
                            "approved_by"
                        ),

                        "execution_timestamp": plan.get(
                            "completed_at"
                        ),

                        "verification": plan.get(
                            "verification"
                        ),

                        "rollback": plan.get(
                            "rollback"
                        ),
                    },
                    default=str
                )
            )

            self.db.add(audit_log)
            self.db.commit()

        except Exception as e:

            logger.error(
                "Failed to log remediation action: %s",
                e
            )

            self.db.rollback()

    # ============================================================
    # HISTORY
    # ============================================================

    def get_remediation_history(
        self,
        resource_id=None,
        limit=100
    ):

        try:

            query = self.db.query(
                models.RemediationLog
            )

            if resource_id:
                query = query.filter(
                    models.RemediationLog.resource_id
                    == resource_id
                )

            logs = (
                query
                .order_by(
                    models.RemediationLog.created_at.desc()
                )
                .limit(limit)
                .all()
            )

            history = []

            for log in logs:

                history.append(
                    {
                        "id": log.id,
                        "action": log.action,
                        "resource_type": log.resource_type,
                        "resource_id": log.resource_id,
                        "details": log.details,
                        "timestamp": (
                            log.created_at.isoformat()
                            if log.created_at
                            else None
                        ),
                    }
                )

            return history

        except Exception as e:

            logger.error(
                "Failed to get remediation history: %s",
                e
            )

            return []


# ================================================================
# GLOBAL INSTANCE
# ================================================================

remediation_engine = RemediationEngine()