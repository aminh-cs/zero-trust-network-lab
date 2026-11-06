import pytest

from zero_trust_lab.models import (
    AccessRequest,
    Device,
    Identity,
    Resource,
)
from zero_trust_lab.policy import evaluate_access
from zero_trust_lab.policy_config import PolicyConfig


@pytest.fixture
def security_config() -> PolicyConfig:
    return PolicyConfig(
        version=1,
        restricted_resource_roles=frozenset({"admin"}),
        permissions=frozenset(
            {
                ("admin", "sensitive-report", "read"),
                ("analyst", "sensitive-report", "read"),
            }
        ),
    )


def make_request(
    role: str = "analyst",
    action: str = "read",
    sensitivity: str = "internal",
    authenticated: bool = True,
    managed: bool = True,
    compliant: bool = True,
) -> AccessRequest:
    return AccessRequest(
        identity=Identity(
            subject_id="security-test-user",
            role=role,
            authenticated=authenticated,
        ),
        device=Device(
            device_id="security-test-device",
            managed=managed,
            compliant=compliant,
        ),
        resource=Resource(
            resource_id="sensitive-report",
            sensitivity=sensitivity,
        ),
        action=action,
    )


def test_unauthorized_role_is_denied_even_with_permission(
    security_config: PolicyConfig,
) -> None:
    request = make_request(
        role="analyst",
        sensitivity="restricted",
    )

    decision = evaluate_access(request, security_config)

    assert decision.allowed is False
    assert decision.policy_id == "ZT-007"
    assert decision.checks[-1].check == "restricted_resource_role"
    assert decision.checks[-1].passed is False


@pytest.mark.parametrize(
    ("action", "sensitivity", "expected_policy_id"),
    [
        ("execute", "internal", "ZT-004"),
        ("read", "top-secret", "ZT-006"),
    ],
)
def test_invalid_request_values_are_denied(
    security_config: PolicyConfig,
    action: str,
    sensitivity: str,
    expected_policy_id: str,
) -> None:
    request = make_request(
        role="analyst",
        action=action,
        sensitivity=sensitivity,
    )

    decision = evaluate_access(request, security_config)

    assert decision.allowed is False
    assert decision.policy_id == expected_policy_id


def test_authentication_failure_stops_before_permission_check(
    security_config: PolicyConfig,
) -> None:
    request = make_request(authenticated=False)

    decision = evaluate_access(request, security_config)

    assert decision.allowed is False
    assert decision.policy_id == "ZT-001"
    assert decision.checks[-1].check == "authentication"
    assert decision.checks[-1].passed is False


def test_device_failure_stops_before_permission_check(
    security_config: PolicyConfig,
) -> None:
    request = make_request(managed=False)

    decision = evaluate_access(request, security_config)

    assert decision.allowed is False
    assert decision.policy_id == "ZT-002"
    assert decision.checks[-1].check == "device_management"
    assert decision.checks[-1].passed is False
