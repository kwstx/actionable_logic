from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from statistics import mean
from threading import RLock
from typing import Any

from src.enforcement.engine import PolicyEnforcer
from src.models.policy_schema import StructuredPolicy


@dataclass(frozen=True)
class FeedbackObservation:
    agent_id: str
    workflow_id: str
    action: dict[str, Any]
    outcome: dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass(frozen=True)
class PolicyUpdateSuggestion:
    policy_id: str
    reason: str
    proposed_changes: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0


@dataclass(frozen=True)
class GuardrailAdjustmentSuggestion:
    parameter: str
    value: float
    reason: str
    confidence: float = 0.0


@dataclass(frozen=True)
class TemplateRefinementSuggestion:
    template_id: str
    reason: str
    recommended_updates: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0


@dataclass(frozen=True)
class FeedbackSummary:
    policy_adherence: float
    real_world_impact: float
    predictive_synergy: float
    cooperative_intelligence: float
    total_observations: int
    policy_suggestions: tuple[PolicyUpdateSuggestion, ...]
    guardrail_suggestions: tuple[GuardrailAdjustmentSuggestion, ...]
    template_suggestions: tuple[TemplateRefinementSuggestion, ...]


@dataclass
class _AssessedObservation:
    observation: FeedbackObservation
    compliant: bool
    active_policy_ids: tuple[str, ...]


class FeedbackConnector:
    """
    Monitors operational outcomes against codified policies and produces
    adaptive recommendations for policy updates, guardrail tuning, and
    template refinement.
    """

    def __init__(self, adherence_target: float = 0.9, impact_target: float = 0.55) -> None:
        self._enforcer = PolicyEnforcer()
        self._observations: list[_AssessedObservation] = []
        self._lock = RLock()
        self._adherence_target = max(0.0, min(1.0, adherence_target))
        self._impact_target = max(-1.0, min(1.0, impact_target))

    def apply_policy_update(self, policy: StructuredPolicy) -> None:
        """LiveUpdateEngine-compatible policy update hook."""
        with self._lock:
            for i, existing in enumerate(self._enforcer.policies):
                if existing.policy_id == policy.policy_id:
                    self._enforcer.policies[i] = policy
                    break
            else:
                self._enforcer.add_policy(policy)

    def record_observation(self, observation: FeedbackObservation) -> None:
        with self._lock:
            results = self._enforcer.evaluate(observation.action, context={"agent_id": observation.agent_id})
            active_ids = tuple(
                sorted(
                    result.policy_id
                    for result in results
                    if result.metadata.get("status") == "active"
                )
            )
            reported_violation = bool(observation.outcome.get("policy_breach") or observation.outcome.get("ignored_instructions"))
            hard_violation = any(not r.is_allowed for r in results)
            compliant = not reported_violation and not hard_violation
            self._observations.append(
                _AssessedObservation(observation=observation, compliant=compliant, active_policy_ids=active_ids)
            )

    def summarize(self, lookback: int | None = None) -> FeedbackSummary:
        with self._lock:
            assessed = self._observations[-lookback:] if lookback else list(self._observations)

        if not assessed:
            return FeedbackSummary(
                policy_adherence=1.0,
                real_world_impact=0.0,
                predictive_synergy=1.0,
                cooperative_intelligence=1.0,
                total_observations=0,
                policy_suggestions=(),
                guardrail_suggestions=(),
                template_suggestions=(),
            )

        policy_adherence = sum(1.0 for entry in assessed if entry.compliant) / len(assessed)
        real_world_impact = mean(self._impact_score(entry.observation.outcome) for entry in assessed)
        predictive_synergy = self._predictive_synergy(assessed)
        cooperative_intelligence = mean(self._cooperation_score(entry.observation.outcome) for entry in assessed)

        policy_suggestions = self._policy_suggestions(assessed, policy_adherence)
        guardrail_suggestions = self._guardrail_suggestions(predictive_synergy, cooperative_intelligence)
        template_suggestions = self._template_suggestions(real_world_impact, cooperative_intelligence)

        return FeedbackSummary(
            policy_adherence=round(policy_adherence, 4),
            real_world_impact=round(real_world_impact, 4),
            predictive_synergy=round(predictive_synergy, 4),
            cooperative_intelligence=round(cooperative_intelligence, 4),
            total_observations=len(assessed),
            policy_suggestions=tuple(policy_suggestions),
            guardrail_suggestions=tuple(guardrail_suggestions),
            template_suggestions=tuple(template_suggestions),
        )

    def apply_guardrail_suggestions(self, guardrails: Any, suggestions: list[GuardrailAdjustmentSuggestion]) -> None:
        """
        Applies suggested guardrail tuning values to a shared context bag.
        This remains non-breaking for existing guardrail implementations.
        """
        context = getattr(guardrails, "_context", None)
        if not isinstance(context, dict):
            return
        tuning = context.setdefault("feedback_tuning", {})
        for suggestion in suggestions:
            tuning[suggestion.parameter] = suggestion.value

    def apply_template_suggestions(
        self,
        template_registry: dict[str, dict[str, Any]],
        suggestions: list[TemplateRefinementSuggestion],
    ) -> dict[str, dict[str, Any]]:
        """
        Applies refinement payloads to an in-memory template registry.
        """
        for suggestion in suggestions:
            template = template_registry.setdefault(suggestion.template_id, {})
            template.update(suggestion.recommended_updates)
        return template_registry

    @staticmethod
    def _impact_score(outcome: dict[str, Any]) -> float:
        raw = outcome.get("impact_score", 0.0)
        try:
            value = float(raw)
        except (TypeError, ValueError):
            value = 0.0
        return max(-1.0, min(1.0, value))

    @staticmethod
    def _cooperation_score(outcome: dict[str, Any]) -> float:
        raw = outcome.get("cooperation_score")
        if raw is None:
            raw = outcome.get("handoff_quality", 1.0)
        try:
            value = float(raw)
        except (TypeError, ValueError):
            value = 1.0
        return max(0.0, min(1.0, value))

    @staticmethod
    def _predictive_synergy(assessed: list[_AssessedObservation]) -> float:
        deltas: list[float] = []
        for entry in assessed:
            predicted = entry.observation.outcome.get("predicted_success")
            actual = entry.observation.outcome.get("actual_success")
            if predicted is None or actual is None:
                continue
            try:
                pred = max(0.0, min(1.0, float(predicted)))
                observed = float(actual)
                observed = 1.0 if observed >= 1.0 else 0.0 if observed <= 0.0 else observed
            except (TypeError, ValueError):
                continue
            deltas.append(abs(pred - observed))
        if not deltas:
            return 1.0
        return max(0.0, min(1.0, 1.0 - mean(deltas)))

    def _policy_suggestions(
        self, assessed: list[_AssessedObservation], policy_adherence: float
    ) -> list[PolicyUpdateSuggestion]:
        if policy_adherence >= self._adherence_target:
            return []

        violations_by_policy: dict[str, int] = {}
        for entry in assessed:
            if entry.compliant:
                continue
            target_ids = entry.active_policy_ids or ("global-policy-set",)
            for policy_id in target_ids:
                violations_by_policy[policy_id] = violations_by_policy.get(policy_id, 0) + 1

        ordered = sorted(violations_by_policy.items(), key=lambda item: item[1], reverse=True)[:3]
        suggestions: list[PolicyUpdateSuggestion] = []
        for policy_id, failures in ordered:
            confidence = min(1.0, failures / len(assessed) + 0.2)
            suggestions.append(
                PolicyUpdateSuggestion(
                    policy_id=policy_id,
                    reason="Observed recurring policy misalignment in live execution.",
                    proposed_changes={
                        "clarify_instructions": True,
                        "add_trigger": "on_violation_escalation",
                        "failure_count": failures,
                    },
                    confidence=round(confidence, 3),
                )
            )
        return suggestions

    @staticmethod
    def _guardrail_suggestions(
        predictive_synergy: float, cooperative_intelligence: float
    ) -> list[GuardrailAdjustmentSuggestion]:
        suggestions: list[GuardrailAdjustmentSuggestion] = []
        if predictive_synergy < 0.7:
            suggestions.append(
                GuardrailAdjustmentSuggestion(
                    parameter="escalation_sensitivity",
                    value=0.85,
                    reason="Prediction drift detected; increase early escalation frequency.",
                    confidence=round(1.0 - predictive_synergy, 3),
                )
            )
        if cooperative_intelligence < 0.65:
            suggestions.append(
                GuardrailAdjustmentSuggestion(
                    parameter="cross_agent_review_threshold",
                    value=0.75,
                    reason="Low cooperative intelligence requires tighter multi-agent review.",
                    confidence=round(0.8 - cooperative_intelligence, 3),
                )
            )
        return suggestions

    def _template_suggestions(
        self, real_world_impact: float, cooperative_intelligence: float
    ) -> list[TemplateRefinementSuggestion]:
        suggestions: list[TemplateRefinementSuggestion] = []
        if real_world_impact < self._impact_target:
            suggestions.append(
                TemplateRefinementSuggestion(
                    template_id="default-operational-template",
                    reason="Impact score is below target under current policy-template mix.",
                    recommended_updates={
                        "add_outcome_metric_step": True,
                        "increase_validation_depth": "medium",
                    },
                    confidence=round((self._impact_target - real_world_impact) + 0.2, 3),
                )
            )
        if cooperative_intelligence < 0.7:
            suggestions.append(
                TemplateRefinementSuggestion(
                    template_id="default-cooperation-template",
                    reason="Cross-agent handoff quality is trending below target.",
                    recommended_updates={
                        "require_handoff_contract": True,
                        "add_peer_acknowledgement": True,
                    },
                    confidence=round(0.9 - cooperative_intelligence, 3),
                )
            )
        return suggestions
