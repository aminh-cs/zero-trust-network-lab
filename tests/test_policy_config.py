import json

import pytest

from zero_trust_lab.policy_config import (
    PolicyConfigError,
    load_policy_config,
)

VALID_CONFIG = {
    "version": 1,
    "restricted_resource_roles": ["admin"],
    "permissions": [
        {
            "role": "analyst",
            "resource": "security-dashboard",
            "action": "read",
        },
        {
            "role": "admin",
            "resource": "security-dashboard",
            "action": "write",
        },
    ],
}


def write_config(tmp_path, data):
    path = tmp_path / "policies.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_load_valid_config(tmp_path):
    path = write_config(tmp_path, VALID_CONFIG)

    config = load_policy_config(path)

    assert config.version == 1
    assert config.restricted_resource_roles == frozenset({"admin"})
    assert ("analyst", "security-dashboard", "read") in config.permissions
    assert len(config.permissions) == 2


def test_reject_invalid_json(tmp_path):
    path = tmp_path / "policies.json"
    path.write_text("{invalid json", encoding="utf-8")

    with pytest.raises(PolicyConfigError, match="Invalid JSON"):
        load_policy_config(path)


def test_reject_missing_file(tmp_path):
    path = tmp_path / "missing.json"

    with pytest.raises(PolicyConfigError, match="Cannot read policy config"):
        load_policy_config(path)


def test_reject_unsupported_version(tmp_path):
    data = {**VALID_CONFIG, "version": 2}
    path = write_config(tmp_path, data)

    with pytest.raises(PolicyConfigError, match="version"):
        load_policy_config(path)


def test_reject_missing_required_field(tmp_path):
    data = {
        "version": 1,
        "permissions": VALID_CONFIG["permissions"],
    }
    path = write_config(tmp_path, data)

    with pytest.raises(PolicyConfigError, match="missing fields"):
        load_policy_config(path)


def test_reject_unknown_top_level_field(tmp_path):
    data = {**VALID_CONFIG, "unexpected": True}
    path = write_config(tmp_path, data)

    with pytest.raises(PolicyConfigError, match="unknown fields"):
        load_policy_config(path)


def test_reject_invalid_action(tmp_path):
    data = {
        **VALID_CONFIG,
        "permissions": [
            {
                "role": "analyst",
                "resource": "security-dashboard",
                "action": "execute",
            }
        ],
    }
    path = write_config(tmp_path, data)

    with pytest.raises(PolicyConfigError, match="unsupported action"):
        load_policy_config(path)


def test_reject_duplicate_permissions(tmp_path):
    permission = VALID_CONFIG["permissions"][0]
    data = {**VALID_CONFIG, "permissions": [permission, permission]}
    path = write_config(tmp_path, data)

    with pytest.raises(PolicyConfigError, match="duplicates"):
        load_policy_config(path)


def test_reject_empty_restricted_roles(tmp_path):
    data = {**VALID_CONFIG, "restricted_resource_roles": []}
    path = write_config(tmp_path, data)

    with pytest.raises(PolicyConfigError, match="restricted_resource_roles"):
        load_policy_config(path)


def test_reject_empty_permission_values(tmp_path):
    data = {
        **VALID_CONFIG,
        "permissions": [
            {
                "role": "",
                "resource": "security-dashboard",
                "action": "read",
            }
        ],
    }
    path = write_config(tmp_path, data)

    with pytest.raises(PolicyConfigError, match="empty or invalid"):
        load_policy_config(path)
