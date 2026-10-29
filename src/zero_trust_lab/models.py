from dataclasses import dataclass


@dataclass(frozen=True)
class Identity:
    subject_id: str
    role: str
    authenticated: bool = True


@dataclass(frozen=True)
class Device:
    device_id: str
    managed: bool
    compliant: bool


@dataclass(frozen=True)
class Resource:
    resource_id: str
    sensitivity: str


@dataclass(frozen=True)
class AccessRequest:
    identity: Identity
    device: Device
    resource: Resource
    action: str


@dataclass(frozen=True)
class PolicyCheck:
    check: str
    passed: bool


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    reason: str
    policy_id: str
    checks: tuple[PolicyCheck, ...] = ()
