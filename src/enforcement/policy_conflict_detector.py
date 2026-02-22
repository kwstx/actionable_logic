from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from itertools import combinations
from pathlib import Path
from typing import Iterable

from src.models.policy_schema import ConditionOperator, LogicalCondition, PolicyDomain, StructuredPolicy
from src.repository.policy_repository import PolicyRepository

logger = logging.getLogger(__name__)


class ConflictType(str, Enum):
    CONTRADICTORY_RULE = "contradictory_rule"
    OVERLAPPING_ENFORCEMENT = "overlapping_enforcement"


class ConflictSeverity(str, Enum):
    SAFETY_CRITICAL = "safety_critical"
    LEGAL_COMPLIANCE = "legal_compliance"
    HIGH = "high"
    MEDIUM = "medium"


@dataclass(frozen=True)
class PolicyConflict:
    conflict_id: str
    detected_at: datetime
    severity: ConflictSeverity
    conflict_type: ConflictType
    policy_ids: tuple[str, str]
    description: str
    workflow_id: str | None
    resolution_suggestions: tuple[str, ...]
    evidence: dict[str, str]


class PolicyConflictDetector:
    """
    Continuously scans policy sources for contradictory and overlapping rules.
    Produces prioritized conflict objects and keeps an audit log of all detections.
    """

    _SEVERITY_PRIORITY = {
        ConflictSeverity.SAFETY_CRITICAL: 0,
        ConflictSeverity.LEGAL_COMPLIANCE: 1,
        ConflictSeverity.HIGH: 2,
        ConflictSeverity.MEDIUM: 3,
    }

    def __init__(
        self,
        repository: PolicyRepository,
        workflow_provider: object | None = None,
        scan_interval_seconds: float = 10.0,
        audit_log_path: str | None = None,
    ) -> None:
        self._repository = repository
        self._workflow_provider = workflow_provider
        self._scan_interval_seconds = max(0.25, scan_interval_seconds)
        self._audit_log_path = Path(audit_log_path) if audit_log_path else None

        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._audit_log: list[PolicyConflict] = []

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, name="policy-conflict-detector", daemon=True)
        self._thread.start()

    def stop(self, timeout_seconds: float = 3.0) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout_seconds)
        self._thread = None

    def scan_once(self) -> list[PolicyConflict]:
        conflicts: list[PolicyConflict] = []
        latest_repo = self._latest_by_policy_id(self._repository.list_policies())
        conflicts.extend(self._scan_policy_collection(latest_repo, workflow_id=None))

        for workflow_id, policies in self._load_workflow_policies().items():
            latest_workflow = self._latest_by_policy_id(policies)
            conflicts.extend(self._scan_policy_collection(latest_workflow, workflow_id=workflow_id))

        conflicts.sort(key=lambda c: (self._SEVERITY_PRIORITY[c.severity], c.detected_at), reverse=False)
        self._append_audit_entries(conflicts)
        return conflicts

    def get_audit_log(self, limit: int | None = None) -> list[PolicyConflict]:
        with self._lock:
            if limit is None or limit >= len(self._audit_log):
                return list(self._audit_log)
            return self._audit_log[-limit:]

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.scan_once()
            finally:
                self._stop_event.wait(self._scan_interval_seconds)

    def _scan_policy_collection(self, policies: list[StructuredPolicy], workflow_id: str | None) -> list[PolicyConflict]:
        conflicts: list[PolicyConflict] = []
        for left, right in combinations(policies, 2):
            contradictory, contradiction_evidence = self._policies_contradict(left, right)
            if contradictory:
                conflicts.append(
                    self._build_conflict(
                        left,
                        right,
                        ConflictType.CONTRADICTORY_RULE,
                        workflow_id=workflow_id,
                        details=contradiction_evidence,
                    )
                )
                continue

            overlap, overlap_evidence = self._policies_overlap(left, right)
            if overlap:
                conflicts.append(
                    self._build_conflict(
                        left,
                        right,
                        ConflictType.OVERLAPPING_ENFORCEMENT,
                        workflow_id=workflow_id,
                        details=overlap_evidence,
                    )
                )
        return conflicts

    @staticmethod
    def _latest_by_policy_id(policies: Iterable[StructuredPolicy]) -> list[StructuredPolicy]:
        latest: dict[str, StructuredPolicy] = {}
        for policy in policies:
            current = latest.get(policy.policy_id)
            if not current:
                latest[policy.policy_id] = policy
                continue
            if policy.effective_date >= current.effective_date:
                latest[policy.policy_id] = policy
        return list(latest.values())

    def _load_workflow_policies(self) -> dict[str, list[StructuredPolicy]]:
        provider = self._workflow_provider
        if not provider:
            return {}

        if hasattr(provider, "snapshot_workflow_policies"):
            snapshot = provider.snapshot_workflow_policies()
            return {k: list(v) for k, v in snapshot.items()}

        return {}

    def _build_conflict(
        self,
        left: StructuredPolicy,
        right: StructuredPolicy,
        conflict_type: ConflictType,
        workflow_id: str | None,
        details: dict[str, str],
    ) -> PolicyConflict:
        severity = self._classify_severity(left, right)
        suggestions = self._build_suggestions(left, right, conflict_type, severity, workflow_id)
        description = (
            f"{left.policy_id} and {right.policy_id} have {conflict_type.value.replace('_', ' ')} "
            f"on enforcement conditions."
        )
        timestamp = datetime.utcnow()
        scope = workflow_id or "repository"
        conflict_id = f"{scope}:{left.policy_id}:{right.policy_id}:{conflict_type.value}"
        return PolicyConflict(
            conflict_id=conflict_id,
            detected_at=timestamp,
            severity=severity,
            conflict_type=conflict_type,
            policy_ids=(left.policy_id, right.policy_id),
            description=description,
            workflow_id=workflow_id,
            resolution_suggestions=tuple(suggestions),
            evidence=details,
        )

    @staticmethod
    def _classify_severity(left: StructuredPolicy, right: StructuredPolicy) -> ConflictSeverity:
        domains = {left.domain, right.domain}
        if PolicyDomain.SECURITY in domains:
            return ConflictSeverity.SAFETY_CRITICAL
        if PolicyDomain.LEGAL in domains or left.compliance_type or right.compliance_type:
            return ConflictSeverity.LEGAL_COMPLIANCE
        if PolicyDomain.FINANCE in domains:
            return ConflictSeverity.HIGH
        return ConflictSeverity.MEDIUM

    @staticmethod
    def _build_suggestions(
        left: StructuredPolicy,
        right: StructuredPolicy,
        conflict_type: ConflictType,
        severity: ConflictSeverity,
        workflow_id: str | None,
    ) -> list[str]:
        suggestions: list[str] = []
        if severity in {ConflictSeverity.SAFETY_CRITICAL, ConflictSeverity.LEGAL_COMPLIANCE}:
            suggestions.append(
                f"Temporarily prioritize {left.policy_id if left.domain in (PolicyDomain.SECURITY, PolicyDomain.LEGAL) else right.policy_id} and require manual compliance review."
            )
        if conflict_type is ConflictType.CONTRADICTORY_RULE:
            suggestions.append("Define explicit precedence and add scoped exceptions to remove impossible condition intersections.")
            suggestions.append("Split rule applicability by workflow, team, or domain to avoid concurrent activation.")
        else:
            suggestions.append("Refine one rule with narrower thresholds so both policies do not trigger on the same action.")
            suggestions.append("Consolidate shared controls into a single policy and keep one source of truth for enforcement.")
        if workflow_id:
            suggestions.append(f"Pin policy subscriptions for workflow '{workflow_id}' to only the intended policy subset.")
        return suggestions

    @staticmethod
    def _policies_contradict(left: StructuredPolicy, right: StructuredPolicy) -> tuple[bool, dict[str, str]]:
        for left_cond in left.conditions:
            for right_cond in right.conditions:
                if left_cond.parameter != right_cond.parameter:
                    continue
                contradiction, reason = PolicyConflictDetector._conditions_contradict(left_cond, right_cond)
                if contradiction:
                    return True, {
                        "parameter": left_cond.parameter,
                        "left_operator": left_cond.operator.value,
                        "left_value": str(left_cond.value),
                        "right_operator": right_cond.operator.value,
                        "right_value": str(right_cond.value),
                        "reason": reason,
                    }
        return False, {}

    @staticmethod
    def _policies_overlap(left: StructuredPolicy, right: StructuredPolicy) -> tuple[bool, dict[str, str]]:
        if not left.conditions or not right.conditions:
            return False, {}

        for left_cond in left.conditions:
            for right_cond in right.conditions:
                if left_cond.parameter != right_cond.parameter:
                    continue
                if PolicyConflictDetector._conditions_overlap(left_cond, right_cond):
                    if left.instructions != right.instructions or left.triggers != right.triggers:
                        return True, {
                            "parameter": left_cond.parameter,
                            "left_operator": left_cond.operator.value,
                            "left_value": str(left_cond.value),
                            "right_operator": right_cond.operator.value,
                            "right_value": str(right_cond.value),
                        }
        return False, {}

    @staticmethod
    def _conditions_overlap(left: LogicalCondition, right: LogicalCondition) -> bool:
        if left.operator == ConditionOperator.EQ and right.operator == ConditionOperator.EQ:
            return left.value == right.value
        if left.operator == ConditionOperator.NE and right.operator == ConditionOperator.NE:
            return True
        if left.operator == ConditionOperator.CONTAINS and right.operator == ConditionOperator.CONTAINS:
            return str(left.value) == str(right.value)
        if left.operator == ConditionOperator.MATCHES and right.operator == ConditionOperator.MATCHES:
            return str(left.value) == str(right.value)

        if PolicyConflictDetector._is_numeric(left.value) and PolicyConflictDetector._is_numeric(right.value):
            return PolicyConflictDetector._numeric_intersection_exists(left, right)
        return str(left.value) == str(right.value)

    @staticmethod
    def _conditions_contradict(left: LogicalCondition, right: LogicalCondition) -> tuple[bool, str]:
        if left.operator == ConditionOperator.EQ and right.operator == ConditionOperator.EQ and left.value != right.value:
            return True, "same parameter requires two different exact values"

        if left.operator == ConditionOperator.EQ and right.operator == ConditionOperator.NE and left.value == right.value:
            return True, "exact match conflicts with explicit inequality"
        if right.operator == ConditionOperator.EQ and left.operator == ConditionOperator.NE and left.value == right.value:
            return True, "exact match conflicts with explicit inequality"

        if PolicyConflictDetector._is_numeric(left.value) and PolicyConflictDetector._is_numeric(right.value):
            if not PolicyConflictDetector._numeric_intersection_exists(left, right):
                return True, "numeric ranges do not intersect"
        return False, ""

    @staticmethod
    def _numeric_intersection_exists(left: LogicalCondition, right: LogicalCondition) -> bool:
        left_low, left_low_inclusive, left_high, left_high_inclusive = PolicyConflictDetector._numeric_bounds(left)
        right_low, right_low_inclusive, right_high, right_high_inclusive = PolicyConflictDetector._numeric_bounds(right)

        low = max(left_low, right_low)
        high = min(left_high, right_high)
        if low < high:
            return True
        if low > high:
            return False

        left_inclusive = left_low_inclusive if low == left_low else left_high_inclusive
        right_inclusive = right_low_inclusive if low == right_low else right_high_inclusive
        return left_inclusive and right_inclusive

    @staticmethod
    def _numeric_bounds(condition: LogicalCondition) -> tuple[float, bool, float, bool]:
        value = float(condition.value)
        if condition.operator == ConditionOperator.GT:
            return value, False, float("inf"), True
        if condition.operator == ConditionOperator.GE:
            return value, True, float("inf"), True
        if condition.operator == ConditionOperator.LT:
            return float("-inf"), True, value, False
        if condition.operator == ConditionOperator.LE:
            return float("-inf"), True, value, True
        if condition.operator == ConditionOperator.EQ:
            return value, True, value, True
        if condition.operator == ConditionOperator.NE:
            return float("-inf"), True, float("inf"), True
        return float("-inf"), True, float("inf"), True

    @staticmethod
    def _is_numeric(value: object) -> bool:
        try:
            float(value)
            return True
        except (TypeError, ValueError):
            return False

    def _append_audit_entries(self, conflicts: list[PolicyConflict]) -> None:
        if not conflicts:
            return
        with self._lock:
            self._audit_log.extend(conflicts)

        for conflict in conflicts:
            logger.warning(
                "policy_conflict_detected id=%s severity=%s type=%s workflow=%s policies=%s",
                conflict.conflict_id,
                conflict.severity.value,
                conflict.conflict_type.value,
                conflict.workflow_id,
                ",".join(conflict.policy_ids),
            )
            if self._audit_log_path:
                self._append_audit_file(conflict)

    def _append_audit_file(self, conflict: PolicyConflict) -> None:
        if not self._audit_log_path:
            return
        payload = asdict(conflict)
        payload["detected_at"] = conflict.detected_at.isoformat()
        payload["severity"] = conflict.severity.value
        payload["conflict_type"] = conflict.conflict_type.value
        self._audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        with self._audit_log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True))
            handle.write("\n")
