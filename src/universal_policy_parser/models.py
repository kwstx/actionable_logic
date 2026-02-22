from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class BooleanExpression:
    operator: str
    operands: list[str] = field(default_factory=list)


@dataclass
class ThresholdConstraint:
    metric: str
    comparator: str
    value: float
    unit: str | None = None


@dataclass
class TemporalConstraint:
    relation: str
    value: int | str
    unit: str | None = None


@dataclass
class Dependency:
    dependency_type: str
    target: str


@dataclass
class NormalizedRule:
    rule_id: str
    source_domain: str
    original_text: str
    boolean_logic: list[BooleanExpression] = field(default_factory=list)
    thresholds: list[ThresholdConstraint] = field(default_factory=list)
    temporal_constraints: list[TemporalConstraint] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class UnifiedPolicy:
    policy_id: str
    source: str
    rules: list[NormalizedRule] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "source": self.source,
            "rules": [rule.to_dict() for rule in self.rules],
        }
