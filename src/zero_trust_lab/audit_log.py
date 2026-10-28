
import json
from pathlib import Path

from .audit import AuditEvent


def append_audit_event(event: AuditEvent, log_path: str | Path) -> None:
    """Append one audit event as a JSON object on a single line."""
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(event.__dict__) + "\n")
