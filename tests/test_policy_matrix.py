import pytest

from zero_trust_lab.models import (
    AccessRequest,
    Device,
    Identity,
    Resource,
)
from zero_trust_lab.policy import evaluate_access
from zero_trust_lab.policy_config import PolicyConfig


@pytest.mark.parametrize(
    (
        "authenticated",
        "managed",
        "compliant",
        "has_permission",
        "expected_allowed",
        "expected_policy_id",
    ),
    [
        (True, True, True, True, True, "ZT-ALLOW"),
        (False, True, True, True, False, "ZT-001"),
        (True, False, True, True, False, "ZT-002"),
        (True, True, False, True, False, "ZT-003"),
        (True, True, True, False, False, "ZT-005"),
    ],
)
def test_access_decision_matrix(
    authenticated: bool,
    managed: bool,
    compliant: bool,
    has_permission: bool,
    expected_allowed: bool,
    expected_policy_id: str,
) -> None:
    permission = ("analyst", "internal-report", "read")

    config = PolicyConfig(
        version=1,
        restricted_resource_roles=frozenset({"admin"}),
        permissions=(frozenset({permission}) if has_permission else frozenset()),
    )

    request = AccessRequest(
        identity=Identity(
            subject_id="matrix-test-user",
            role="analyst",
            authenticated=authenticated,
        ),
        device=Device(
            device_id="matrix-test-device",
            managed=managed,
            compliant=compliant,
        ),
        resource=Resource(
            resource_id="internal-report",
            sensitivity="internal",
        ),
        action="read",
    )

    decision = evaluate_access(request, config)

    assert decision.allowed is expected_allowed
    assert decision.policy_id == expected_policy_id
