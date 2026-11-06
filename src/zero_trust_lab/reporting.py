from .models import (
    AccessDecision,
    AccessReport,
    DecisionExplanation,
)

CHECK_REASONS = {
    "authentication": "The identity is not authenticated.",
    "device_management": "The device is not managed.",
    "device_compliance": "The device does not meet compliance requirements.",
    "action_validation": "The requested action is not supported.",
    "sensitivity_validation": "The resource sensitivity level is invalid.",
    "restricted_resource_role": (
        "The identity's role is not authorized to access this resource."
    ),
    "explicit_permission": (
        "No explicit policy grants this identity permission to perform "
        "the requested action."
    ),
}


def explain_decision(decision: AccessDecision) -> AccessReport:
    """Generate a structured explanation for an access decision."""

    failed_check = next(
        (check for check in decision.checks if not check.passed),
        None,
    )

    if decision.allowed:
        summary = (
            "Access was allowed because all security checks passed "
            "and an explicit permission was found."
        )
        failed_check_name = None
        failed_check_reason = None

    elif failed_check is not None:
        failed_check_name = failed_check.check
        failed_check_reason = CHECK_REASONS.get(
            failed_check.check,
            decision.reason,
        )
        summary = failed_check_reason

    else:
        failed_check_name = None
        failed_check_reason = decision.reason
        summary = decision.reason

    return AccessReport(
        decision=decision,
        explanation=DecisionExplanation(
            policy_id=decision.policy_id,
            summary=summary,
            failed_check=failed_check_name,
            failed_check_reason=failed_check_reason,
        ),
    )
