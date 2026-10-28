
import json
import subprocess
import sys


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "zero_trust_lab", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_default_request_is_allowed():
    result = run_cli()

    assert result.returncode == 0
    decision = json.loads(result.stdout)
    assert decision["allowed"] is True
    assert decision["policy_id"] == "ZT-ALLOW"


def test_cli_denies_analyst_write_request():
    result = run_cli("--role", "analyst", "--action", "write")

    assert result.returncode == 0
    decision = json.loads(result.stdout)
    assert decision["allowed"] is False
    assert decision["policy_id"] == "ZT-005"


def test_cli_denies_unmanaged_device():
    result = run_cli("--unmanaged-device")

    assert result.returncode == 0
    decision = json.loads(result.stdout)
    assert decision["allowed"] is False
    assert decision["policy_id"] == "ZT-002"


def test_cli_audit_output_contains_timestamp_and_identity():
    result = run_cli("--audit")

    assert result.returncode == 0
    event = json.loads(result.stdout)
    assert "timestamp" in event
    assert event["subject_id"] == "demo-user"
    assert event["allowed"] is True


def test_cli_audit_records_restricted_resource_denial():
    result = run_cli(
        "--resource",
        "incident-reports",
        "--sensitivity",
        "restricted",
        "--audit",
    )

    assert result.returncode == 0
    event = json.loads(result.stdout)
    assert event["allowed"] is False
    assert event["policy_id"] == "ZT-007"


def test_cli_writes_audit_log(tmp_path):
    log_path = tmp_path / "audit.jsonl"

    result = run_cli("--audit-log", str(log_path))

    assert result.returncode == 0
    records = log_path.read_text(encoding="utf-8").splitlines()
    assert len(records) == 1

    event = json.loads(records[0])
    assert event["allowed"] is True
    assert event["subject_id"] == "demo-user"


def test_cli_logs_denied_requests(tmp_path):
    log_path = tmp_path / "audit.jsonl"

    result = run_cli(
        "--role",
        "analyst",
        "--action",
        "write",
        "--audit-log",
        str(log_path),
    )

    assert result.returncode == 0
    event = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    assert event["allowed"] is False
    assert event["policy_id"] == "ZT-005"
