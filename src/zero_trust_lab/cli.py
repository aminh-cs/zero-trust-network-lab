
import argparse
import json
from dataclasses import asdict

from .audit import audit_event_to_json, create_audit_event
from .models import AccessRequest, Device, Identity, Resource
from .policy import evaluate_access


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulate a Zero Trust access-control decision."
    )
    parser.add_argument("--role", default="analyst")
    parser.add_argument("--resource", default="security-dashboard")
    parser.add_argument("--action", default="read")
    parser.add_argument(
        "--unauthenticated",
        action="store_true",
        help="Simulate an unauthenticated identity.",
    )
    parser.add_argument(
        "--unmanaged-device",
        action="store_true",
        help="Simulate an unmanaged device.",
    )
    parser.add_argument(
        "--noncompliant-device",
        action="store_true",
        help="Simulate a noncompliant device.",
    )
    parser.add_argument(
        "--sensitivity",
        choices=["public", "internal", "restricted", "top-secret"],
        default="internal",
        help="Resource sensitivity level.",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Print the complete timestamped audit event.",
    )
    args = parser.parse_args()

    request = AccessRequest(
        identity=Identity(
            subject_id="demo-user",
            role=args.role,
            authenticated=not args.unauthenticated,
        ),
        device=Device(
            device_id="demo-device",
            managed=not args.unmanaged_device,
            compliant=not args.noncompliant_device,
        ),
        resource=Resource(
            resource_id=args.resource,
            sensitivity=args.sensitivity,
        ),
        action=args.action,
    )

    decision = evaluate_access(request)

    if args.audit:
        event = create_audit_event(request, decision)
        print(audit_event_to_json(event))
    else:
        print(json.dumps(asdict(decision), indent=2))


if __name__ == "__main__":
    main()
