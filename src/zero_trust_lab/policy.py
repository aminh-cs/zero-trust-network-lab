
from pathlib import Path

from .models import AccessDecision, AccessRequest
from .policy_config import PolicyConfig, load_policy_config


ALLOWED_ACTIONS = {"read", "write", "delete"}
VALID_SENSITIVITY_LEVELS = {"public", "internal", "restricted"}

DEFAULT_CONFIG_PATH = (
    Path(__file__).resolve().parents[2] / "config" / "policies.json"
)


def get_default_policy_config() -> PolicyConfig:
    """Load the default policy configuration from the project config folder."""
    return load_policy_config(DEFAULT_CONFIG_PATH)


def evaluate_access(
    request: AccessRequest,
    policy_config: PolicyConfig | None = None,
) -> AccessDecision:
    """Evaluate an access request using configurable default-deny rules."""

    if policy_config is None:
        policy_config = get_default_policy_config()

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
        and request.identity.role
        not in policy_config.restricted_resource_roles
    ):
        return AccessDecision(
            False,
            "Restricted resources require an authorized role",
            "ZT-007",
        )

    permission = (
        request.identity.role,
        request.resource.resource_id,
        request.action,
    )

    if permission not in policy_config.permissions:
        return AccessDecision(
            False, "No explicit policy permits this request", "ZT-005"
        )

    return AccessDecision(
        True,
        "All checks passed and an explicit policy permits this request",
        "ZT-ALLOW",
    )
