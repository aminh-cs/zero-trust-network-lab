import json

from zero_trust_lab.audit import create_audit_event
from zero_trust_lab.audit_log import append_audit_event
from zero_trust_lab.models import (
    AccessRequest,
    Device,
    Identity,
    Resource,
)
from zero_trust_lab.policy import evaluate_access


def make_event(*, managed=True):
    request = AccessRequest(
        identity=Identity("user-001", "analyst"),
        device=Device("device-001", managed=managed, compliant=True),
        resource=Resource("security-dashboard", "internal"),
        action="read",
    )
    return create_audit_event(request, evaluate_access(request))


def test_appends_audit_event_as_json_line(tmp_path):
    log_path = tmp_path / "audit.jsonl"

    append_audit_event(make_event(), log_path)

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    record = json.loads(lines[0])
    assert record["subject_id"] == "user-001"
    assert record["allowed"] is True


def test_appending_preserves_existing_records(tmp_path):
    log_path = tmp_path / "audit.jsonl"

    append_audit_event(make_event(), log_path)
    append_audit_event(make_event(managed=False), log_path)

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2

    first = json.loads(lines[0])
    second = json.loads(lines[1])

    assert first["allowed"] is True
    assert second["allowed"] is False
    assert second["policy_id"] == "ZT-002"


def test_each_log_line_is_independently_valid_json(tmp_path):
    log_path = tmp_path / "audit.jsonl"

    append_audit_event(make_event(), log_path)
    append_audit_event(make_event(managed=False), log_path)

    for line in log_path.read_text(encoding="utf-8").splitlines():
        assert isinstance(json.loads(line), dict)


def test_creates_missing_parent_directories(tmp_path):
    log_path = tmp_path / "nested" / "logs" / "audit.jsonl"

    append_audit_event(make_event(), log_path)

    assert log_path.exists()
    records = log_path.read_text(encoding="utf-8").splitlines()
    assert len(records) == 1
    assert json.loads(records[0])["allowed"] is True
