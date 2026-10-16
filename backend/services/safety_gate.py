"""
Safety/Policy Gate for CloudSentinel
Implements a three-tier system for remediation actions:
- Automatically allowed: Safe actions that can be applied without approval
- Approval required: Actions that need human approval before execution
- Automatically blocked: Actions that are never allowed to be automated
"""

from typing import Dict, Any, Optional, List
from enum import Enum
from backend.models import ResourceType, Category


class ActionTier(str, Enum):
    AUTOMATICALLY_ALLOWED = "automatically_allowed"
    APPROVAL_REQUIRED = "approval_required"
    AUTOMATICALLY_BLOCKED = "automatically_blocked"


class SafetyGate:
    """Implements safety/policy gate for remediation actions."""

    def __init__(self):
        # Define which actions are automatically allowed
        self.automatically_allowed = {
            # S3 actions
            ("s3_bucket", "PUBLIC_ACCESS", "block_public_access_disabled"): {
                "action": "enable_block_public_access",
                "description": "Enable S3 Block Public Access settings",
                "safe": True
            },
            ("s3_bucket", "PUBLIC_ACCESS", "bucket_publicly_accessible"): {
                "action": "reset_bucket_acl_to_private",
                "description": "Reset S3 bucket ACL to private",
                "safe": True  # Note: Has limitations with bucket policies
            },
            ("s3_bucket", "DATA_PROTECTION", "versioning_disabled"): {
                "action": "enable_versioning",
                "description": "Enable S3 bucket versioning",
                "safe": True
            },
            ("s3_bucket", "DATA_PROTECTION", "encryption_disabled"): {
                "action": "enable_default_encryption",
                "description": "Enable default S3 bucket encryption (SSE-S3)",
                "safe": True
            },

            # IAM actions
            ("iam_account", "CREDENTIAL_HYGIENE", "weak_password_policy"): {
                "action": "strengthen_password_policy",
                "description": "Strengthen IAM password policy (length >=14, require symbols, numbers, mixed case)",
                "safe": True
            },
            ("iam_account", "CREDENTIAL_HYGIENE", "old_access_keys"): {
                "action": "deactivate_old_access_keys",
                "description": "Deactivate IAM access keys older than 90 days",
                "safe": True
            }
        }

        # Define which actions require approval
        self.approval_required = {
            # IAM actions that need careful consideration
            ("iam_user", "IDENTITY_SECURITY", "root_account_mfa_disabled"): {
                "action": "enable_root_mfa_console_only",
                "description": "Enable MFA for root account (must be done in AWS console)",
                "safe": False  # Cannot be done via API
            },
            ("iam_user", "IDENTITY_SECURITY", "mfa_disabled"): {
                "action": "enable_user_mfa",
                "description": "Enable MFA for IAM user (requires user cooperation)",
                "safe": False  # User must participate
            },
            ("iam_role", "EXCESSIVE_PERMISSIONS", "wildcard_permissions"): {
                "action": "review_wildcard_permissions",
                "description": "Review wildcard IAM permissions (too risky to auto-revoke)",
                "safe": False  # Could break workloads
            },

            # EC2, CloudTrail, Lambda findings (no specific remediation logic yet)
            ("ec2", "NETWORK_SECURITY", "unrestricted_ssh_rdp"): {
                "action": "restrict_security_group_rules",
                "description": "Restrict security group rules allowing unrestricted SSH/RDP",
                "safe": False  # Need to specify replacement rules
            },
            ("cloudtrail", "LOGGING_MONITORING", "logging_disabled"): {
                "action": "enable_cloudtrail_logging",
                "description": "Enable CloudTrail logging",
                "safe": True  # Actually safe, but putting in approval for consistency
            },
            ("lambda_function", "EXCESSIVE_PERMISSIONS", "excessive_function_permissions"): {
                "action": "review_function_permissions",
                "description": "Review excessive Lambda function permissions",
                "safe": False  # Need careful review
            },
            ("lambda_function", "CREDENTIAL_HYGIENE", "secrets_in_env_vars"): {
                "action": "remove_secrets_from_env",
                "description": "Remove secrets from Lambda environment variables",
                "safe": False  # Might break function if not done carefully
            },
            ("lambda_function", "ENCRYPTION", "missing_kms_encryption"): {
                "action": "enable_kms_encryption",
                "description": "Enable KMS encryption for Lambda function",
                "safe": True  # Actually safe, but conservative approach
            }
        }

        # Define which actions are automatically blocked
        self.automatically_blocked = {
            # High-risk IAM actions
            ("iam_user", "IDENTITY_SECURITY", "modify_admin_permissions"): {
                "action": "modify_administrator_iam_permissions",
                "description": "Modify administrator IAM permissions",
                "blocked_reason": "Too high-risk - could lock out administrators"
            },
            ("iam_user", "IDENTITY_SECURITY", "delete_critical_resources"): {
                "action": "delete_iam_users_or_roles",
                "description": "Delete IAM users or roles",
                "blocked_reason": "Could cause service disruption or lockout"
            },
            ("s3_bucket", "DATA_PROTECTION", "delete_s3_bucket"): {
                "action": "delete_s3_bucket",
                "description": "Delete S3 bucket",
                "blocked_reason": "Data loss risk - requires explicit confirmation"
            },
            ("ec2", "NETWORK_SECURITY", "terminate_ec2_instance"): {
                "action": "terminate_ec2_instance",
                "description": "Terminate EC2 instance",
                "blocked_reason": "Service disruption risk"
            }
        }

        # Build lookup dictionaries for faster access
        self._build_lookup_tables()

    def _build_lookup_tables(self):
        """Build lookup tables for quick action classification."""
        self.allowed_lookup = {}
        self.approval_lookup = {}
        self.blocked_lookup = {}

        for (resource_type, category, finding_type), action_info in self.automatically_allowed.items():
            key = (resource_type, category, finding_type)
            self.allowed_lookup[key] = action_info

        for (resource_type, category, finding_type), action_info in self.approval_required.items():
            key = (resource_type, category, finding_type)
            self.approval_lookup[key] = action_info

        for (resource_type, category, finding_type), action_info in self.automatically_blocked.items():
            key = (resource_type, category, finding_type)
            self.blocked_lookup[key] = action_info

    def classify_action(self, resource_type: str, category: str, finding_type: str) -> Dict[str, Any]:
        """
        Classify an action into one of the three tiers.

        Args:
            resource_type: Type of resource (s3_bucket, iam_user, etc.)
            category: Finding category (PUBLIC_ACCESS, DATA_PROTECTION, etc.)
            finding_type: Specific finding identifier

        Returns:
            Dictionary with tier, action info, and classification details
        """
        key = (resource_type, category, finding_type)

        # Check if automatically blocked
        if key in self.blocked_lookup:
            return {
                "tier": ActionTier.AUTOMATICALLY_BLOCKED,
                "action_info": self.blocked_lookup[key],
                "allowed": False,
                "requires_approval": False
            }

        # Check if automatically allowed
        if key in self.allowed_lookup:
            return {
                "tier": ActionTier.AUTOMATICALLY_ALLOWED,
                "action_info": self.allowed_lookup[key],
                "allowed": True,
                "requires_approval": False
            }

        # Check if approval required
        if key in self.approval_lookup:
            return {
                "tier": ActionTier.APPROVAL_REQUIRED,
                "action_info": self.approval_lookup[key],
                "allowed": False,
                "requires_approval": True
            }

        # Default to approval required for unknown actions
        return {
            "tier": ActionTier.APPROVAL_REQUIRED,
            "action_info": {
                "action": "manual_review_required",
                "description": "Manual review required - no automated remediation available",
                "safe": False
            },
            "allowed": False,
            "requires_approval": True
        }

    def is_action_allowed(self, resource_type: str, category: str, finding_type: str) -> bool:
        """
        Check if an action is automatically allowed (can be executed without approval).

        Args:
            resource_type: Type of resource
            category: Finding category
            finding_type: Specific finding identifier

        Returns:
            True if action is automatically allowed, False otherwise
        """
        classification = self.classify_action(resource_type, category, finding_type)
        return classification["tier"] == ActionTier.AUTOMATICALLY_ALLOWED

    def requires_approval(self, resource_type: str, category: str, finding_type: str) -> bool:
        """
        Check if an action requires human approval.

        Args:
            resource_type: Type of resource
            category: Finding category
            finding_type: Specific finding identifier

        Returns:
            True if action requires approval, False otherwise
        """
        classification = self.classify_action(resource_type, category, finding_type)
        return classification["requires_approval"]

    def is_action_blocked(self, resource_type: str, category: str, finding_type: str) -> bool:
        """
        Check if an action is automatically blocked (never allowed to be automated).

        Args:
            resource_type: Type of resource
            category: Finding category
            finding_type: Specific finding identifier

        Returns:
            True if action is automatically blocked, False otherwise
        """
        classification = self.classify_action(resource_type, category, finding_type)
        return classification["tier"] == ActionTier.AUTOMATICALLY_BLOCKED

    def get_action_info(self, resource_type: str, category: str, finding_type: str) -> Optional[Dict[str, Any]]:
        """
        Get action information for a specific finding.

        Args:
            resource_type: Type of resource
            category: Finding category
            finding_type: Specific finding identifier

        Returns:
            Action information dictionary or None if not found
        """
        classification = self.classify_action(resource_type, category, finding_type)
        return classification.get("action_info")

    def get_safe_remediation_actions(self) -> List[Dict[str, Any]]:
        """
        Get a list of all automatically allowed remediation actions.

        Returns:
            List of automatically allowed actions with their details
        """
        actions = []
        for (resource_type, category, finding_type), action_info in self.automatically_allowed.items():
            actions.append({
                "resource_type": resource_type,
                "category": category,
                "finding_type": finding_type,
                "action": action_info["action"],
                "description": action_info["description"],
                "safe": action_info["safe"]
            })
        return actions