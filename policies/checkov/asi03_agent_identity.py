"""
Custom Checkov policy
OWASP ASI03:2026 - Identity and Privilege Abuse

Agents inherit credentials and act on their own, so a long-lived, broadly
scoped token is a direct path to privilege abuse. This check fails any IAM
role used by an agent (tagged role = "agent") whose max session duration is
longer than one hour, pushing toward short-lived, frequently rotated creds.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

MAX_SESSION_SECONDS = 3600


class AgentRoleShortLived(BaseResourceCheck):
    def __init__(self):
        name = "Agent IAM role must use short-lived sessions <= 1h (OWASP ASI03)"
        id = "CKV_ASI03_1"
        supported_resources = ["aws_iam_role"]
        categories = [CheckCategories.IAM]
        super().__init__(
            name=name,
            id=id,
            categories=categories,
            supported_resources=supported_resources,
        )

    def scan_resource_conf(self, conf):
        tags = conf.get("tags")
        if isinstance(tags, list):
            tags = tags[0] if tags else {}
        # Only applies to roles explicitly marked as agent identities.
        if not isinstance(tags, dict) or tags.get("role") != "agent":
            return CheckResult.PASSED

        duration = conf.get("max_session_duration")
        if isinstance(duration, list):
            duration = duration[0] if duration else None

        # Default IAM session is 3600s; require the attribute to be set and
        # within the cap so the intent is explicit.
        if duration is None or int(duration) > MAX_SESSION_SECONDS:
            return CheckResult.FAILED
        return CheckResult.PASSED


check = AgentRoleShortLived()
