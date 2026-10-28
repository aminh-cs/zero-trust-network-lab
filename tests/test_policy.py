
from zero_trust_lab.models import (
    AccessRequest,
    Device,
    Identity,
    Resource,
)
from zero_trust_lab.policy import evaluate_access


def make_request(
    *,
    role="analyst",
    resource_id="security-dashboard",
    action="read",
    authenticated=True,
    managed=True,
    compliant=True,
):
    return AccessRequest(
        identity=Identity(
            subject_id="user-001",
            role=role,
            authenticated=authenticated,
        ),
        device=Device(
            device_id="device-001",
            managed=managed,
            compliant=compliant,
        ),
        resource=Resource(
            resource_id=resource_id,
            sensitivity="internal",
        ),
        action=action,
    )


def test_explicitly_permitted_request_is_allowed():
    decision = evaluate_access(make_request())

    assert decision.allowed is True
    assert decision.policy_id == "ZT-ALLOW"


def test_unauthenticated_identity_is_denied():
    decision = evaluate_access(make_request(authenticated=False))

    assert decision.allowed is False
    assert decision.policy_id == "ZT-001"


def test_unmanaged_device_is_denied():
    decision = evaluate_access(make_request(managed=False))

    assert decision.allowed is False
    assert decision.policy_id == "ZT-002"


def test_noncompliant_device_is_denied():
    decision = evaluate_access(make_request(compliant=False))

    assert decision.allowed is False
    assert decision.policy_id == "ZT-003"


def test_unlisted_permission_is_denied():
    decision = evaluate_access(
        make_request(role="guest", resource_id="security-dashboard")
    )

    assert decision.allowed is False
    assert decision.policy_id == "ZT-005"


def test_unknown_action_is_denied():
    decision = evaluate_access(make_request(action="execute"))

    assert decision.allowed is False
    assert decision.policy_id == "ZT-004"


def test_analyst_cannot_write_to_security_dashboard():
    decision = evaluate_access(
        make_request(role="analyst", action="write")
    )

    assert decision.allowed is False
    assert decision.policy_id == "ZT-005"


def test_guest_cannot_access_incident_reports():
    decision = evaluate_access(
        make_request(role="guest", resource_id="incident-reports")
    )

    assert decision.allowed is False
    assert decision.policy_id == "ZT-005"


def test_admin_can_write_incident_reports():
    decision = evaluate_access(
        make_request(role="admin", resource_id="incident-reports", action="write")
    )

    assert decision.allowed is True
    assert decision.policy_id == "ZT-ALLOW"
