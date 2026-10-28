
from zero_trust_lab.models import (
    AccessRequest,
    Device,
    Identity,
    Resource,
)
from zero_trust_lab.policy import evaluate_access


from zero_trust_lab.policy_config import PolicyConfig


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


def test_analyst_is_denied_restricted_resource():
    request = make_request(
        role="analyst",
        resource_id="incident-reports",
    )
    request = AccessRequest(
        identity=request.identity,
        device=request.device,
        resource=Resource(
            resource_id="incident-reports",
            sensitivity="restricted",
        ),
        action=request.action,
    )

    decision = evaluate_access(request)

    assert decision.allowed is False
    assert decision.policy_id == "ZT-007"


def test_admin_can_read_restricted_incident_reports():
    request = AccessRequest(
        identity=Identity("admin-001", "admin"),
        device=Device("device-001", managed=True, compliant=True),
        resource=Resource("incident-reports", sensitivity="restricted"),
        action="read",
    )

    decision = evaluate_access(request)

    assert decision.allowed is True
    assert decision.policy_id == "ZT-ALLOW"


def test_unknown_sensitivity_is_denied():
    request = AccessRequest(
        identity=Identity("admin-001", "admin"),
        device=Device("device-001", managed=True, compliant=True),
        resource=Resource("incident-reports", sensitivity="top-secret"),
        action="read",
    )

    decision = evaluate_access(request)

    assert decision.allowed is False
    assert decision.policy_id == "ZT-006"


def test_custom_policy_can_deny_default_permission():
    from zero_trust_lab.models import AccessRequest, Device, Identity, Resource
    from zero_trust_lab.policy import evaluate_access

    request = AccessRequest(
        identity=Identity(
            subject_id="test-user",
            role="analyst",
            authenticated=True,
        ),
        device=Device(
            device_id="test-device",
            managed=True,
            compliant=True,
        ),
        resource=Resource(
            resource_id="security-dashboard",
            sensitivity="internal",
        ),
        action="read",
    )

    restrictive_config = PolicyConfig(
        version=1,
        restricted_resource_roles=frozenset({"admin"}),
        permissions=frozenset(),
    )

    decision = evaluate_access(request, restrictive_config)

    assert decision.allowed is False
    assert decision.policy_id == "ZT-005"


def test_custom_policy_can_allow_additional_permission():
    from zero_trust_lab.models import AccessRequest, Device, Identity, Resource
    from zero_trust_lab.policy import evaluate_access

    request = AccessRequest(
        identity=Identity(
            subject_id="test-user",
            role="analyst",
            authenticated=True,
        ),
        device=Device(
            device_id="test-device",
            managed=True,
            compliant=True,
        ),
        resource=Resource(
            resource_id="incident-reports",
            sensitivity="internal",
        ),
        action="write",
    )

    expanded_config = PolicyConfig(
        version=1,
        restricted_resource_roles=frozenset({"admin"}),
        permissions=frozenset({
            ("analyst", "incident-reports", "write"),
        }),
    )

    decision = evaluate_access(request, expanded_config)

    assert decision.allowed is True
    assert decision.policy_id == "ZT-ALLOW"


def test_allowed_decision_records_all_checks_in_order():
    from zero_trust_lab.models import AccessRequest, Device, Identity, Resource
    from zero_trust_lab.policy import evaluate_access

    request = AccessRequest(
        identity=Identity(
            subject_id="trace-user",
            role="analyst",
            authenticated=True,
        ),
        device=Device(
            device_id="trace-device",
            managed=True,
            compliant=True,
        ),
        resource=Resource(
            resource_id="security-dashboard",
            sensitivity="internal",
        ),
        action="read",
    )

    decision = evaluate_access(request)

    assert decision.allowed is True
    assert [check.check for check in decision.checks] == [
        "authentication",
        "device_management",
        "device_compliance",
        "action_validation",
        "sensitivity_validation",
        "restricted_resource_role",
        "explicit_permission",
    ]
    assert all(check.passed for check in decision.checks)


def test_denied_decision_trace_stops_at_first_failure():
    from zero_trust_lab.models import AccessRequest, Device, Identity, Resource
    from zero_trust_lab.policy import evaluate_access

    request = AccessRequest(
        identity=Identity(
            subject_id="trace-user",
            role="analyst",
            authenticated=True,
        ),
        device=Device(
            device_id="trace-device",
            managed=False,
            compliant=True,
        ),
        resource=Resource(
            resource_id="security-dashboard",
            sensitivity="internal",
        ),
        action="read",
    )

    decision = evaluate_access(request)

    assert decision.allowed is False
    assert decision.policy_id == "ZT-002"
    assert [(check.check, check.passed) for check in decision.checks] == [
        ("authentication", True),
        ("device_management", False),
    ]
