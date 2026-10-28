
import json
from datetime import datetime

from zero_trust_lab.audit import (
    audit_event_to_json,
    create_audit_event,
)
from zero_trust_lab.models import (
    AccessRequest,
    Device,
    Identity,
    Resource,
)
from zero_trust_lab.policy import evaluate_access


def make_request(*, role="analyst", action="read", managed=True):
    return AccessRequest(
        identity=Identity("user-001", role),
        device=Device("device-001", managed=managed, compliant=True),
        resource=Resource("security-dashboard", "internal"),
        action=action,
    )


def test_audit_event_records_allowed_decision():
    request = make_request()
    decision = evaluate_access(request)

    event = create_audit_event(request, decision)

    assert event.allowed is True
    assert event.subject_id == "user-001"
    assert event.resource_id == "security-dashboard"
    assert event.policy_id == "ZT-ALLOW"


def test_audit_event_records_denied_decision():
    request = make_request(managed=False)
    decision = evaluate_access(request)

    event = create_audit_event(request, decision)

    assert event.allowed is False
    assert event.policy_id == "ZT-002"
    assert event.reason == "Device is not managed"


def test_audit_event_timestamp_is_timezone_aware():
    event = create_audit_event(
        make_request(),
        evaluate_access(make_request()),
    )

    timestamp = datetime.fromisoformat(event.timestamp)

    assert timestamp.tzinfo is not None
    assert timestamp.utcoffset() is not None


def test_audit_event_serializes_to_json():
    request = make_request()
    event = create_audit_event(request, evaluate_access(request))

    data = json.loads(audit_event_to_json(event))

    assert data["subject_id"] == "user-001"
    assert data["allowed"] is True
    assert data["action"] == "read"
