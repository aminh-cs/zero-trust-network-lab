
from .models import AccessDecision, AccessRequest


ALLOWED_ACTIONS = {"read", "write", "delete"}


# Explicit permissions: (role, resource_id, action)
DEFAULT_POLICIES = {
    ("analyst", "security-dashboard", "read"),
    ("admin", "security-dashboard", "read"),
    ("admin", "security-dashboard", "write"),
    ("admin", "security-dashboard", "delete"),
    ("analyst", "incident-reports", "read"),
    ("admin", "incident-reports", "read"),
    ("admin", "incident-reports", "write"),
}


def evaluate_access(request: AccessRequest) -> AccessDecision:
    """Evaluate an access request using default-deny rules."""

    if not request.identity.authenticated:
        return AccessDecision(
            allowed=False,
            reason="Identity is not authenticated",
            policy_id="ZT-001",
        )

    if not request.device.managed:
        return AccessDecision(
            allowed=False,
            reason="Device is not managed",
            policy_id="ZT-002",
        )

    if not request.device.compliant:
        return AccessDecision(
            allowed=False,
            reason="Device is not compliant",
            policy_id="ZT-003",
        )

    if request.action not in ALLOWED_ACTIONS:
        return AccessDecision(
            allowed=False,
            reason="Requested action is not recognized",
            policy_id="ZT-004",
        )

    permission = (
        request.identity.role,
        request.resource.resource_id,
        request.action,
    )

    if permission not in DEFAULT_POLICIES:
        return AccessDecision(
            allowed=False,
            reason="No explicit policy permits this request",
            policy_id="ZT-005",
        )

    return AccessDecision(
        allowed=True,
        reason="Authenticated identity, compliant device, and explicit policy",
        policy_id="ZT-ALLOW",
    )
