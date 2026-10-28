
import json
from dataclasses import dataclass
from pathlib import Path


ALLOWED_ACTIONS = {"read", "write", "delete"}


class PolicyConfigError(ValueError):
    """Raised when a policy configuration is invalid."""


@dataclass(frozen=True)
class PolicyConfig:
    version: int
    restricted_resource_roles: frozenset[str]
    permissions: frozenset[tuple[str, str, str]]


def load_policy_config(path: str | Path) -> PolicyConfig:
    """Load and validate a JSON policy configuration."""
    config_path = Path(path)

    try:
        with config_path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except OSError as exc:
        raise PolicyConfigError(
            f"Cannot read policy config '{config_path}': {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise PolicyConfigError(
            f"Invalid JSON in '{config_path}': {exc.msg}"
        ) from exc

    if not isinstance(data, dict):
        raise PolicyConfigError("Config must be a JSON object.")

    required_fields = {
        "version",
        "restricted_resource_roles",
        "permissions",
    }
    if set(data) != required_fields:
        missing = required_fields - set(data)
        extra = set(data) - required_fields
        details = []
        if missing:
            details.append(f"missing fields: {sorted(missing)}")
        if extra:
            details.append(f"unknown fields: {sorted(extra)}")
        raise PolicyConfigError("Invalid config fields; " + "; ".join(details))

    version = data["version"]
    if type(version) is not int or version != 1:
        raise PolicyConfigError("Config version must be the integer 1.")

    roles = data["restricted_resource_roles"]
    if (
        not isinstance(roles, list)
        or not roles
        or any(not isinstance(role, str) or not role.strip() for role in roles)
    ):
        raise PolicyConfigError(
            "'restricted_resource_roles' must be a non-empty list "
            "of non-empty strings."
        )

    if len(roles) != len(set(roles)):
        raise PolicyConfigError(
            "'restricted_resource_roles' must not contain duplicates."
        )

    raw_permissions = data["permissions"]
    if not isinstance(raw_permissions, list) or not raw_permissions:
        raise PolicyConfigError("'permissions' must be a non-empty list.")

    permissions = []
    expected_permission_fields = {"role", "resource", "action"}

    for index, permission in enumerate(raw_permissions):
        if not isinstance(permission, dict) or set(permission) != expected_permission_fields:
            raise PolicyConfigError(
                f"Permission at index {index} must contain exactly "
                "'role', 'resource', and 'action'."
            )

        role = permission["role"]
        resource = permission["resource"]
        action = permission["action"]

        if any(
            not isinstance(value, str) or not value.strip()
            for value in (role, resource, action)
        ):
            raise PolicyConfigError(
                f"Permission at index {index} has an empty or invalid value."
            )

        if action not in ALLOWED_ACTIONS:
            raise PolicyConfigError(
                f"Permission at index {index} uses unsupported action '{action}'."
            )

        permissions.append((role, resource, action))

    if len(permissions) != len(set(permissions)):
        raise PolicyConfigError("Permissions must not contain duplicates.")

    return PolicyConfig(
        version=version,
        restricted_resource_roles=frozenset(roles),
        permissions=frozenset(permissions),
    )
