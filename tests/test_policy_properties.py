from hypothesis import given
from hypothesis import strategies as st

from zero_trust_lab.models import (
    AccessRequest,
    Device,
    Identity,
    Resource,
)
from zero_trust_lab.policy import evaluate_access
from zero_trust_lab.policy_config import PolicyConfig

non_empty_text = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
    ),
    min_size=1,
    max_size=20,
)


@given(
    role=non_empty_text,
    resource_id=non_empty_text,
    action=st.sampled_from(["read", "write", "delete"]),
)
def test_request_without_matching_permission_is_denied(
    role: str,
    resource_id: str,
    action: str,
) -> None:
    request = AccessRequest(
        identity=Identity(
            subject_id="property-test-user",
            role=role,
            authenticated=True,
        ),
        device=Device(
            device_id="property-test-device",
            managed=True,
            compliant=True,
        ),
        resource=Resource(
            resource_id=resource_id,
            sensitivity="internal",
        ),
        action=action,
    )

    config = PolicyConfig(
        version=1,
        restricted_resource_roles=frozenset({"admin"}),
        permissions=frozenset(),
    )

    decision = evaluate_access(request, config)

    assert decision.allowed is False
    assert decision.policy_id == "ZT-005"
    assert decision.checks[-1].check == "explicit_permission"
    assert decision.checks[-1].passed is False


@given(
    role=non_empty_text,
    resource_id=non_empty_text,
    action=st.sampled_from(["read", "write", "delete"]),
)
def test_unauthenticated_requests_are_always_denied(
    role: str,
    resource_id: str,
    action: str,
) -> None:
    request = AccessRequest(
        identity=Identity(
            subject_id="property-test-user",
            role=role,
            authenticated=False,
        ),
        device=Device(
            device_id="property-test-device",
            managed=True,
            compliant=True,
        ),
        resource=Resource(
            resource_id=resource_id,
            sensitivity="internal",
        ),
        action=action,
    )

    config = PolicyConfig(
        version=1,
        restricted_resource_roles=frozenset({"admin", role}),
        permissions=frozenset({(role, resource_id, action)}),
    )

    decision = evaluate_access(request, config)

    assert decision.allowed is False
    assert decision.policy_id == "ZT-001"
    assert decision.checks[0].check == "authentication"
    assert decision.checks[0].passed is False


@given(
    role=non_empty_text,
    resource_id=non_empty_text,
    action=st.sampled_from(["read", "write", "delete"]),
)
def test_unmanaged_devices_are_always_denied(
    role: str,
    resource_id: str,
    action: str,
) -> None:
    request = AccessRequest(
        identity=Identity(
            subject_id="property-test-user",
            role=role,
            authenticated=True,
        ),
        device=Device(
            device_id="property-test-device",
            managed=False,
            compliant=True,
        ),
        resource=Resource(
            resource_id=resource_id,
            sensitivity="internal",
        ),
        action=action,
    )

    config = PolicyConfig(
        version=1,
        restricted_resource_roles=frozenset({"admin", role}),
        permissions=frozenset({(role, resource_id, action)}),
    )

    decision = evaluate_access(request, config)

    assert decision.allowed is False
    assert decision.policy_id == "ZT-002"
    assert decision.checks[-1].check == "device_management"
    assert decision.checks[-1].passed is False


@given(
    role=non_empty_text,
    resource_id=non_empty_text,
    action=st.sampled_from(["read", "write", "delete"]),
)
def test_noncompliant_devices_are_always_denied(
    role: str,
    resource_id: str,
    action: str,
) -> None:
    request = AccessRequest(
        identity=Identity(
            subject_id="property-test-user",
            role=role,
            authenticated=True,
        ),
        device=Device(
            device_id="property-test-device",
            managed=True,
            compliant=False,
        ),
        resource=Resource(
            resource_id=resource_id,
            sensitivity="internal",
        ),
        action=action,
    )

    config = PolicyConfig(
        version=1,
        restricted_resource_roles=frozenset({"admin", role}),
        permissions=frozenset({(role, resource_id, action)}),
    )

    decision = evaluate_access(request, config)

    assert decision.allowed is False
    assert decision.policy_id == "ZT-003"
    assert decision.checks[-1].check == "device_compliance"
    assert decision.checks[-1].passed is False
