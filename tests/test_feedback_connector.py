from datetime import datetime

from src.enforcement.guardrails import AdaptiveGuardrailsEngine
from src.feedback.connector import FeedbackConnector, FeedbackObservation
from src.models.policy_schema import ConditionOperator, LogicalCondition, PolicyDomain, PolicyScope, StructuredPolicy


def _policy(policy_id: str) -> StructuredPolicy:
    return StructuredPolicy(
        policy_id=policy_id,
        title=policy_id,
        domain=PolicyDomain.GOVERNANCE,
        scope=PolicyScope.GLOBAL,
        effective_date=datetime.utcnow(),
        raw_source=f"source-{policy_id}",
        rationale=f"rationale-{policy_id}",
        instructions=["Follow governance workflow"],
        conditions=[
            LogicalCondition(parameter="amount", operator=ConditionOperator.GT, value=100),
        ],
    )


def test_feedback_connector_tracks_policy_adherence_and_suggests_policy_updates():
    connector = FeedbackConnector(adherence_target=0.8)
    connector.apply_policy_update(_policy("POL-1"))

    connector.record_observation(
        FeedbackObservation(
            agent_id="agent-a",
            workflow_id="wf-a",
            action={"amount": 120},
            outcome={"policy_breach": True, "impact_score": 0.2, "actual_success": 0, "predicted_success": 0.8},
        )
    )
    connector.record_observation(
        FeedbackObservation(
            agent_id="agent-a",
            workflow_id="wf-a",
            action={"amount": 50},
            outcome={"policy_breach": False, "impact_score": 0.4, "actual_success": 1, "predicted_success": 0.7},
        )
    )

    summary = connector.summarize()

    assert summary.total_observations == 2
    assert summary.policy_adherence == 0.5
    assert len(summary.policy_suggestions) == 1
    assert summary.policy_suggestions[0].policy_id == "POL-1"


def test_feedback_connector_recommends_guardrail_and_template_changes_from_low_quality_signals():
    connector = FeedbackConnector(adherence_target=0.5, impact_target=0.5)
    connector.record_observation(
        FeedbackObservation(
            agent_id="agent-x",
            workflow_id="wf-x",
            action={"task": "handoff"},
            outcome={
                "policy_breach": False,
                "impact_score": 0.1,
                "predicted_success": 0.95,
                "actual_success": 0,
                "cooperation_score": 0.4,
            },
        )
    )

    summary = connector.summarize()

    assert summary.predictive_synergy < 0.7
    assert summary.cooperative_intelligence < 0.65
    assert len(summary.guardrail_suggestions) >= 1
    assert len(summary.template_suggestions) >= 1


def test_feedback_connector_can_apply_guardrail_tuning():
    connector = FeedbackConnector()
    guardrails = AdaptiveGuardrailsEngine()

    connector.record_observation(
        FeedbackObservation(
            agent_id="agent-z",
            workflow_id="wf-z",
            action={"task": "estimate"},
            outcome={
                "policy_breach": False,
                "impact_score": 0.3,
                "predicted_success": 1.0,
                "actual_success": 0.0,
                "cooperation_score": 0.5,
            },
        )
    )
    summary = connector.summarize()
    connector.apply_guardrail_suggestions(guardrails, list(summary.guardrail_suggestions))

    assert "feedback_tuning" in guardrails._context


def test_feedback_connector_can_apply_template_refinements():
    connector = FeedbackConnector(impact_target=0.6)
    connector.record_observation(
        FeedbackObservation(
            agent_id="agent-y",
            workflow_id="wf-y",
            action={"task": "delivery"},
            outcome={"policy_breach": False, "impact_score": 0.1, "cooperation_score": 0.8},
        )
    )

    summary = connector.summarize()
    registry = {"default-operational-template": {"existing": True}}
    updated = connector.apply_template_suggestions(registry, list(summary.template_suggestions))

    assert updated["default-operational-template"]["existing"] is True
    assert updated["default-operational-template"]["add_outcome_metric_step"] is True
