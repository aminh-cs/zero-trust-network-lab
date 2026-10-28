
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
