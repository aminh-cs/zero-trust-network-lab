
import argparse
import json
from dataclasses import asdict

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
            sensitivity="internal",
        ),
        action=args.action,
    )

    decision = evaluate_access(request)
    print(json.dumps(asdict(decision), indent=2))


if __name__ == "__main__":
    main()
