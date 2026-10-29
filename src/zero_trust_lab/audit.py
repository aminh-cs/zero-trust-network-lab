import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from .models import AccessDecision, AccessRequest


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    subject_id: str
    device_id: str
    resource_id: str
    sensitivity: str
    action: str
    role: str
    allowed: bool
    reason: str
    policy_id: str


def create_audit_event(
    request: AccessRequest,
    decision: AccessDecision,
) -> AuditEvent:
    """Create a timestamped audit event for an access decision."""
    return AuditEvent(
        timestamp=datetime.now(UTC).isoformat(),
        subject_id=request.identity.subject_id,
        device_id=request.device.device_id,
        resource_id=request.resource.resource_id,
        sensitivity=request.resource.sensitivity,
        action=request.action,
        role=request.identity.role,
        allowed=decision.allowed,
        reason=decision.reason,
        policy_id=decision.policy_id,
    )


def audit_event_to_json(event: AuditEvent) -> str:
    """Serialize an audit event to readable JSON."""
    return json.dumps(asdict(event), indent=2)
