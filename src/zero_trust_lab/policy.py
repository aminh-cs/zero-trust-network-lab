
from .models import AccessDecision, AccessRequest


ALLOWED_ACTIONS = {"read", "write", "delete"}
VALID_SENSITIVITY_LEVELS = {"public", "internal", "restricted"}

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
            False, "Identity is not authenticated", "ZT-001"
        )

    if not request.device.managed:
        return AccessDecision(
            False, "Device is not managed", "ZT-002"
        )

    if not request.device.compliant:
        return AccessDecision(
            False, "Device is not compliant", "ZT-003"
        )

    if request.action not in ALLOWED_ACTIONS:
        return AccessDecision(
            False, "Requested action is not recognized", "ZT-004"
        )

    if request.resource.sensitivity not in VALID_SENSITIVITY_LEVELS:
        return AccessDecision(
            False, "Resource sensitivity is not recognized", "ZT-006"
        )

    if (
        request.resource.sensitivity == "restricted"
        and request.identity.role != "admin"
    ):
        return AccessDecision(
            False,
            "Restricted resources require the admin role",
            "ZT-007",
        )

    permission = (
        request.identity.role,
        request.resource.resource_id,
        request.action,
    )

    if permission not in DEFAULT_POLICIES:
        return AccessDecision(
            False, "No explicit policy permits this request", "ZT-005"
        )

    return AccessDecision(
        True,
        "All checks passed and an explicit policy permits this request",
        "ZT-ALLOW",
    )
