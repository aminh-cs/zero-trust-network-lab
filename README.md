# Zero Trust Network Lab

A Python-based simulation of a Zero Trust access-control policy engine. This project demonstrates explicit authorization, least privilege, device posture verification, default-deny behavior, configurable policies, structured audit events, policy decision tracing, and explainable access decisions.

> **Project status:** Educational security lab. This is a policy simulation, not a production identity or network enforcement system.

## Features

- **Authentication checks:** Deny requests from unauthenticated identities.
- **Device posture checks:** Require managed and compliant devices.
- **Explicit authorization:** Grant access only when a matching role, resource, and action permission exists.
- **Default-deny behavior:** Reject unknown actions and requests without explicit permission.
- **Restricted-resource authorization:** Require an authorized role for restricted resources.
- **Configurable policies:** Load permissions from JSON configuration files.
- **Policy validation:** Reject malformed JSON, unsupported versions, missing or unknown fields, invalid actions, empty values, and duplicate entries.
- **Policy decision tracing:** Record individual security checks and stop at the first failure.
- **Explainable decisions:** Generate human-readable explanations for allowed and denied requests.
- **Structured audit events:** Record timestamps, identity, device, resource, action, decision, reason, and policy ID.
- **Persistent audit logging:** Append audit events to JSON Lines (`.jsonl`) files.
- **Command-line interface:** Simulate access requests, load custom policies, inspect decision traces, and generate reports.
- **Automated testing:** Use pytest and Hypothesis for unit, security, decision-matrix, and property-based tests.
- **Continuous integration:** Automatically run formatting, linting, static type checking, and tests through GitHub Actions.

## Architecture

The project separates request models, policy configuration, policy evaluation, reporting, audit handling, and command-line interaction.

```text
CLI arguments
     |
     v
AccessRequest
  | Identity
  | Device
  | Resource
  | Action
     |
     v
Policy configuration
  | Load JSON configuration
  | Validate schema and permissions
     |
     v
Policy evaluation
  | Authentication
  | Device management
  | Device compliance
  | Action validation
  | Sensitivity validation
  | Restricted-resource role check
  | Explicit permission lookup
     |
     v
AccessDecision
  | Allowed / Denied
  | Reason
  | Policy ID
  | Policy checks
     |
     +----------------------+
     |                      |
     v                      v
Decision reporting     Audit event
  | Explanation          | Timestamp
  | Failed check         | Request context
  | Human-readable       | Decision details
     |                      |
     +----------+-----------+
                |
                v
       CLI output / JSON
       / JSON Lines audit log
```

### Main components

| Component | Responsibility |
|---|---|
| `models.py` | Defines identities, devices, resources, access requests, decisions, and report models. |
| `policy.py` | Evaluates access requests using ordered security checks and configured policies. |
| `policy_config.py` | Loads and validates JSON policy configuration. |
| `reporting.py` | Generates structured, human-readable explanations for access decisions. |
| `cli.py` | Parses command-line arguments and runs the simulation. |
| `audit.py` | Creates structured audit events and serializes them to JSON. |
| `audit_log.py` | Appends audit events to persistent JSON Lines logs. |
| `config/policies.json` | Stores the default access policy configuration. |
| `tests/` | Contains unit, property-based, decision-matrix, security, reporting, and CLI tests. |

## Requirements

- Python 3.11 or later
- pip

## Setup

The following commands are for Windows PowerShell. Run them from the project root.

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the project and development dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pip install ruff mypy
```

## Run the Demo

### Default request

The default analyst request to read the security dashboard should be allowed:

```powershell
python -m zero_trust_lab
```

### Denied write request

An analyst attempting to write to the security dashboard should be denied:

```powershell
python -m zero_trust_lab --role analyst --action write
```

### Device posture and identity checks

Simulate an unmanaged device:

```powershell
python -m zero_trust_lab --unmanaged-device
```

Simulate an unauthenticated identity:

```powershell
python -m zero_trust_lab --unauthenticated
```

Simulate a noncompliant device:

```powershell
python -m zero_trust_lab --noncompliant-device
```

Each standard invocation prints a JSON decision containing `allowed`, `reason`, and `policy_id`.

## Configurable Access Policies

Access permissions are stored in `config/policies.json`. This separates policy data from the Python logic that evaluates requests.

The configuration contains three required fields:

- `version`: The policy configuration schema version. The current supported version is `1`.
- `restricted_resource_roles`: The roles authorized to pass the restricted-resource role check.
- `permissions`: Explicit combinations of roles, resources, and actions.

### Example configuration

```json
{
  "version": 1,
  "restricted_resource_roles": [
    "admin"
  ],
  "permissions": [
    {
      "role": "analyst",
      "resource": "security-dashboard",
      "action": "read"
    },
    {
      "role": "admin",
      "resource": "security-dashboard",
      "action": "write"
    }
  ]
}
```

This is an illustrative example of the configuration format. The repository's `config/policies.json` contains the complete default permission set.

### Use a custom policy file

Supply `--policy-config` to evaluate requests against a different valid JSON configuration:

```powershell
python -m zero_trust_lab --role analyst --resource security-dashboard --action read --policy-config config/policies.json
```

If `--policy-config` is omitted, the application loads the default configuration from the project's `config` directory.

A custom configuration can change which role/resource/action combinations are permitted without requiring changes to the policy evaluation code.

### Policy configuration validation

Before evaluating an access request, the application validates the policy configuration. It rejects:

- Invalid JSON syntax or unreadable configuration files.
- Unsupported configuration versions.
- Missing required fields or unexpected top-level fields.
- Empty or invalid role, resource, or action values.
- Unsupported actions.
- Duplicate roles or permissions.

Invalid configuration produces a readable CLI error instead of silently falling back to a different policy.

## Access Decision Process

The policy engine evaluates requests in the following order:

1. **Authentication:** Reject unauthenticated identities.
2. **Device management:** Reject unmanaged devices.
3. **Device compliance:** Reject noncompliant devices.
4. **Action validation:** Accept only `read`, `write`, and `delete`.
5. **Sensitivity validation:** Accept only `public`, `internal`, and `restricted`.
6. **Restricted-resource role check:** Require a role listed in `restricted_resource_roles` for restricted resources.
7. **Explicit permission lookup:** Require an exact role, resource, and action match in the configured permissions.

A request is allowed only if it passes every check and has an explicit matching permission. Otherwise, access is denied.

The resource sensitivity field affects authorization: `restricted` resources require an authorized role. The `public` and `internal` sensitivity levels do not bypass the other access-control checks.

### Policy Decision Tracing

Use the `--trace` CLI option to inspect individual checks performed during an access-control decision.

For an allowed request:

```powershell
python -m zero_trust_lab --trace
```

For a request denied because the device is unmanaged:

```powershell
python -m zero_trust_lab --unmanaged-device --trace
```

The output includes a `checks` array. Each entry contains the check name and a Boolean `passed` result.

Checks are recorded in evaluation order, and evaluation stops at the first failed check. This provides an explainable record of why access was granted or denied.

Tracing is optional. Without `--trace`, the standard CLI output omits the `checks` array.

### Human-readable Decision Reports

Use `--report` to generate a human-readable explanation of an access decision.

Example: an analyst attempting to access a restricted resource:

```powershell
python -m zero_trust_lab --role analyst --resource incident-reports --sensitivity restricted --action read --report
```

Illustrative output:

```text
ACCESS DECISION REPORT
========================================

Decision: DENIED
Policy ID: ZT-007

Explanation:
The identity's role is not authorized to access this resource.

Failed security check:
restricted_resource_role

Reason:
The identity's role is not authorized to access this resource.
```

An authorized administrator can access the same resource if the configured policy explicitly grants permission:

```powershell
python -m zero_trust_lab --role admin --resource incident-reports --sensitivity restricted --action read --report
```

The report distinguishes between successful and failed decisions and identifies the policy responsible for a denial.

## Access Policy Examples

The default policy set includes permissions such as:

| Role | Resource | Action | Expected result |
|---|---|---|---|
| `analyst` | `security-dashboard` | `read` | Allow |
| `analyst` | `security-dashboard` | `write` | Deny |
| `analyst` | `incident-reports` | `read` | Allow |
| `admin` | `security-dashboard` | `write` | Allow |
| `admin` | `incident-reports` | `write` | Allow |
| `guest` | `incident-reports` | `read` | Deny |

These are demonstration policies, not recommendations for a real organization's access configuration.

## Audit Events and Logging

The lab generates structured audit events for access decisions. An event includes the timestamp, identity, device, resource, requested action, decision, reason, and policy ID.

### Print an audit event

Print the complete timestamped audit event:

```powershell
python -m zero_trust_lab --audit
```

Print an audit event for a denied request:

```powershell
python -m zero_trust_lab --role analyst --action write --audit
```

### Persist audit events

Use `--audit-log` to append audit events to a JSON Lines file. Each event is stored as a separate JSON object on its own line.

Record a default request:

```powershell
python -m zero_trust_lab --audit-log logs\audit.jsonl
```

Record a denied request:

```powershell
python -m zero_trust_lab --role analyst --action write --audit-log logs\audit.jsonl
```

Inspect the log:

```powershell
Get-Content logs\audit.jsonl
```

The application creates the parent directory when necessary. Audit logs are useful for inspecting simulated decisions, but the implementation does not provide tamper-resistant storage, cryptographic integrity protection, or centralized log management.

## Testing

Run the full test suite:

```powershell
python -m pytest -v
```

The test suite covers:

- Allowed and denied access requests.
- Authentication and device posture checks.
- Invalid actions and resource sensitivity values.
- Explicit permission enforcement and default-deny behavior.
- Custom policy configurations and configuration validation.
- Security boundary and policy decision-matrix scenarios.
- Property-based tests using Hypothesis.
- Decision traces and first-failure behavior.
- Human-readable reporting.
- CLI execution and audit output.
- Audit event creation and persistent JSON Lines logging.

The latest verified local test run contains **63 passing tests**.

### Code quality checks

The project also uses Ruff for formatting and linting, and mypy for static type checking.

Run the checks locally:

```powershell
python -m ruff format --check .
python -m ruff check .
python -m mypy src/zero_trust_lab
python -m pytest -q
```

### Continuous Integration

GitHub Actions automatically runs the project's quality checks when changes are pushed to the repository.

The workflow verifies:

- Ruff formatting.
- Ruff linting.
- mypy static type checking.
- pytest test execution.

This helps ensure that changes are checked consistently before they are considered complete.

## Threat Model and Limitations

This lab focuses on authorization decision logic. It assumes that identity and device attributes are supplied to the engine; it does not independently verify them.

The current implementation does not provide:

- Real identity-provider integration or credential validation.
- Actual network traffic filtering or resource enforcement.
- Cryptographic device attestation.
- Tamper-resistant audit storage or centralized security monitoring.
- Policy administration, revocation workflows, or distributed policy synchronization.
- Production-grade deployment controls or independent security assurance.

The lab demonstrates selected Zero Trust concepts; it is not a complete Zero Trust architecture or a production security control.

## Future Improvements

Potential extensions include:

- Add richer policy conditions, such as time, network context, and device risk.
- Add policy versioning and explicit policy change history.
- Add tamper-evident audit records and log integrity verification.
- Add integration with an identity provider.
- Add more advanced security scenarios and threat-model documentation.
- Add centralized monitoring and visualization of audit events.

## Disclaimer

Built for educational purposes to explore Zero Trust principles, policy design, configurable authorization, audit logging, explainable decisions, and automated security testing.

Do not use it as a production security control without substantial additional engineering, threat modeling, and independent security review.