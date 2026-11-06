from zero_trust_lab.models import (
    AccessDecision,
    PolicyCheck,
)
from zero_trust_lab.reporting import explain_decision


def test_allowed_decision_has_successful_explanation() -> None:
    decision = AccessDecision(
        allowed=True,
        reason="All checks passed",
        policy_id="ZT-ALLOW",
        checks=(
            PolicyCheck("authentication", True),
            PolicyCheck("device_management", True),
            PolicyCheck("explicit_permission", True),
        ),
    )

    report = explain_decision(decision)

    assert report.decision.allowed is True
    assert report.explanation.policy_id == "ZT-ALLOW"
    assert report.explanation.failed_check is None
    assert report.explanation.failed_check_reason is None


def test_denied_decision_identifies_failed_check() -> None:
    decision = AccessDecision(
        allowed=False,
        reason="Identity is not authenticated",
        policy_id="ZT-001",
        checks=(PolicyCheck("authentication", False),),
    )

    report = explain_decision(decision)

    assert report.decision.allowed is False
    assert report.explanation.policy_id == "ZT-001"
    assert report.explanation.failed_check == "authentication"
    assert report.explanation.failed_check_reason == (
        "The identity is not authenticated."
    )


def test_denied_decision_without_trace_uses_original_reason() -> None:
    decision = AccessDecision(
        allowed=False,
        reason="Access denied",
        policy_id="ZT-005",
    )

    report = explain_decision(decision)

    assert report.explanation.failed_check is None
    assert report.explanation.failed_check_reason == "Access denied"
    assert report.explanation.summary == "Access denied"
