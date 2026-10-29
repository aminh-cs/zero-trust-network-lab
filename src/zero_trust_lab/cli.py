import argparse
import json
from dataclasses import asdict

from .audit import audit_event_to_json, create_audit_event
from .audit_log import append_audit_event
from .models import AccessRequest, Device, Identity, Resource
from .policy import evaluate_access, get_default_policy_config
from .policy_config import PolicyConfigError, load_policy_config


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
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Include policy check results in the output.",
    )
    parser.add_argument(
        "--audit-log",
        metavar="PATH",
        help="Append the access decision to a JSON Lines audit log.",
    )
    parser.add_argument(
        "--policy-config",
        metavar="PATH",
        help="Path to a custom JSON policy configuration file.",
    )

    args = parser.parse_args()

    try:
        policy_config = (
            load_policy_config(args.policy_config)
            if args.policy_config
            else get_default_policy_config()
        )
    except PolicyConfigError as exc:
        parser.error(str(exc))

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

    decision = evaluate_access(request, policy_config)
    event = create_audit_event(request, decision)

    if args.audit_log:
        append_audit_event(event, args.audit_log)

    if args.audit:
        print(audit_event_to_json(event))
    else:
        output = asdict(decision)
        if not args.trace:
            output.pop("checks", None)
        print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
