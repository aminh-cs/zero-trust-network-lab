
from pathlib import Path

from .models import AccessDecision, AccessRequest, PolicyCheck
from .policy_config import PolicyConfig, load_policy_config


ALLOWED_ACTIONS = {"read", "write", "delete"}
VALID_SENSITIVITY_LEVELS = {"public", "internal", "restricted"}

DEFAULT_CONFIG_PATH = (
    Path(__file__).resolve().parents[2] / "config" / "policies.json"
)


def get_default_policy_config() -> PolicyConfig:
    """Load the default policy configuration."""
    return load_policy_config(DEFAULT_CONFIG_PATH)


def evaluate_access(
    request: AccessRequest,
    policy_config: PolicyConfig | None = None,
) -> AccessDecision:
    """Evaluate access and record checks up to the first failure."""

    if policy_config is None:
        policy_config = get_default_policy_config()

    checks: list[PolicyCheck] = []

    def record_check(name: str, passed: bool) -> None:
        checks.append(PolicyCheck(check=name, passed=passed))

    def deny(reason: str, policy_id: str) -> AccessDecision:
        return AccessDecision(
            allowed=False,
            reason=reason,
            policy_id=policy_id,
            checks=tuple(checks),
        )

    record_check("authentication", request.identity.authenticated)
    if not request.identity.authenticated:
        return deny("Identity is not authenticated", "ZT-001")

    record_check("device_management", request.device.managed)
    if not request.device.managed:
        return deny("Device is not managed", "ZT-002")

    record_check("device_compliance", request.device.compliant)
    if not request.device.compliant:
        return deny("Device is not compliant", "ZT-003")

    action_valid = request.action in ALLOWED_ACTIONS
    record_check("action_validation", action_valid)
    if not action_valid:
        return deny("Requested action is not recognized", "ZT-004")

    sensitivity_valid = (
        request.resource.sensitivity in VALID_SENSITIVITY_LEVELS
    )
    record_check("sensitivity_validation", sensitivity_valid)
    if not sensitivity_valid:
        return deny("Resource sensitivity is not recognized", "ZT-006")

    role_authorized = (
        request.resource.sensitivity != "restricted"
        or request.identity.role in policy_config.restricted_resource_roles
    )
    record_check("restricted_resource_role", role_authorized)
    if not role_authorized:
        return deny(
            "Restricted resources require an authorized role",
            "ZT-007",
        )

    permission = (
        request.identity.role,
        request.resource.resource_id,
        request.action,
    )
    permission_granted = permission in policy_config.permissions
    record_check("explicit_permission", permission_granted)
    if not permission_granted:
        return deny(
            "No explicit policy permits this request",
            "ZT-005",
        )

    return AccessDecision(
        allowed=True,
        reason="All checks passed and an explicit policy permits this request",
        policy_id="ZT-ALLOW",
        checks=tuple(checks),
    )
