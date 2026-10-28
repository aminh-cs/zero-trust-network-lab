# Zero Trust Network Lab

A Python-based simulation of a Zero Trust access-control policy engine. The project demonstrates explicit authorization, least privilege, device posture checks, default-deny behavior, and explainable access decisions.

> **Status:** Educational security lab. This is a policy simulation, not a production identity or network enforcement system.

## Features

- **Authentication checks:** deny requests from unauthenticated identities.
- **Device posture checks:** require managed and compliant devices.
- **Explicit authorization:** grant access only when a matching role, resource, and action policy exists.
- **Default deny:** unknown actions and unlisted permissions are rejected.
- **Explainable decisions:** return an allow/deny result, a reason, and a policy identifier.
- **Command-line interface:** run sample requests and receive JSON output.
- **Automated tests:** verify policy behavior and CLI scenarios.
- **Continuous integration:** run tests through GitHub Actions.

## Architecture

The project separates request data, policy evaluation, and command-line interaction.

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
Policy evaluation
  | Authentication
  | Device management
  | Device compliance
  | Action validation
  | Explicit permission lookup
     |
     v
AccessDecision
  | allowed
  | reason
  | policy_id
     |
     v
JSON output
```

## Access policy examples

The initial policy set includes these permissions:

| Role | Resource | Action | Result |
|---|---|---|---|
| analyst | security-dashboard | read | Allow |
| analyst | security-dashboard | write | Deny |
| analyst | incident-reports | read | Allow |
| admin | security-dashboard | write | Allow |
| admin | incident-reports | write | Allow |
| guest | incident-reports | read | Deny |

These are demonstration policies, not recommendations for a real organization's access configuration.

## Requirements

- Python 3.11 or later
- `pip`
- `pytest` for tests

## Setup

Create and activate a virtual environment.

**Windows PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install wheel
python -m pip install -e . --no-build-isolation
python -m pip install pytest
```

## Run the demo

Default request — expected to be allowed:

```powershell
python -m zero_trust_lab
```

Analyst requesting write access — expected to be denied:

```powershell
python -m zero_trust_lab --role analyst --action write
```

Unmanaged device — expected to be denied:

```powershell
python -m zero_trust_lab --unmanaged-device
```

Unauthenticated identity — expected to be denied:

```powershell
python -m zero_trust_lab --unauthenticated
```

Noncompliant device — expected to be denied:

```powershell
python -m zero_trust_lab --noncompliant-device
```

Each invocation prints a JSON decision with `allowed`, `reason`, and `policy_id` fields.

## Run tests

```powershell
python -m pytest -v
```

The test suite covers permitted access, authentication failures, device posture, unlisted permissions, invalid actions, and CLI execution.

## Threat model and limitations

This lab focuses on **authorization decision logic**. It assumes identity and device attributes are supplied to the engine; it does not independently verify them.

The current implementation does not provide:

- Real identity-provider integration or credential validation
- Actual network traffic filtering or resource enforcement
- Cryptographic device attestation
- Persistent audit logging or tamper-resistant records
- Policy administration, revocation, or distributed policy synchronization
- Production-grade input validation, monitoring, or deployment controls

The `sensitivity` field on a resource is currently descriptive and does not affect authorization decisions.

## Future improvements

- Add sensitivity-aware access policies.
- Add structured audit events and decision timestamps.
- Load policies from a validated configuration file.
- Add policy tests for malformed or incomplete requests.
- Document security assumptions and example threat scenarios.

## Disclaimer

Built for educational purposes to explore Zero Trust principles, policy design, and automated security testing. Do not use it as a production security control without substantial additional engineering and independent security review.