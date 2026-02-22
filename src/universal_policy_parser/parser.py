from __future__ import annotations

import re
from typing import Any

from .models import (
    BooleanExpression,
    Dependency,
    NormalizedRule,
    TemporalConstraint,
    ThresholdConstraint,
    UnifiedPolicy,
)


class UniversalPolicyParser:
    """
    Parses heterogeneous policy formats into a unified logical model.

    Supports:
    - free-form policy text
    - list[str] of policy statements
    - dict/list structures with common keys like rule/text/statement/conditions
    """

    _THRESHOLD_PATTERN = re.compile(
        r"(?P<metric>[A-Za-z][\w\s/-]{1,40}?)\s*"
        r"(?P<comparator>>=|<=|>|<|==|=)\s*"
        r"(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>[A-Za-z%]+)?\b",
        flags=re.IGNORECASE,
    )
    _AT_LEAST_PATTERN = re.compile(
        r"\bat\s+least\s+(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>[A-Za-z%]+)?\b",
        flags=re.IGNORECASE,
    )
    _NO_MORE_THAN_PATTERN = re.compile(
        r"\b(no\s+more\s+than|at\s+most)\s+(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>[A-Za-z%]+)?\b",
        flags=re.IGNORECASE,
    )
    _WITHIN_PATTERN = re.compile(
        r"\bwithin\s+(?P<value>\d+)\s*(?P<unit>minute|minutes|hour|hours|day|days|week|weeks|month|months)\b",
        flags=re.IGNORECASE,
    )
    _BEFORE_AFTER_PATTERN = re.compile(
        r"\b(?P<relation>before|after)\s+(?P<target>[\w\s-]{2,60})",
        flags=re.IGNORECASE,
    )
    _EVERY_PATTERN = re.compile(
        r"\bevery\s+(?P<value>\d+)\s*(?P<unit>minute|minutes|hour|hours|day|days|week|weeks|month|months)\b",
        flags=re.IGNORECASE,
    )
    _DEPENDENCY_PATTERN = re.compile(
        r"\b(requires?|dependent\s+on|subject\s+to|after)\s+(?P<target>[A-Za-z0-9\s/_-]{2,80})",
        flags=re.IGNORECASE,
    )

    _DOMAIN_KEYWORDS: dict[str, tuple[str, ...]] = {
        "gdpr": ("gdpr", "data subject", "personal data", "dpo", "controller", "processor"),
        "hipaa": ("hipaa", "phi", "protected health information", "covered entity"),
        "financial_compliance": ("sec", "finra", "sox", "aml", "kyc", "transaction", "audit"),
        "safety_protocol": ("safety", "incident", "hazard", "ppe", "osha"),
        "hr_policy": ("employee", "manager", "leave", "harassment", "disciplinary"),
        "internal_approval": ("approval", "sign-off", "escalation", "workflow", "owner"),
    }

    def parse(self, data: str | list[Any] | dict[str, Any], policy_id: str = "policy", source: str = "unknown") -> UnifiedPolicy:
        statements = self._extract_statements(data)
        rules = []
        for idx, statement in enumerate(statements, start=1):
            domain = self._infer_domain(statement)
            rules.append(self._normalize_statement(statement, domain, idx))
        return UnifiedPolicy(policy_id=policy_id, source=source, rules=rules)

    def _extract_statements(self, data: str | list[Any] | dict[str, Any]) -> list[str]:
        if isinstance(data, str):
            return self._split_text_into_statements(data)

        if isinstance(data, list):
            statements: list[str] = []
            for item in data:
                if isinstance(item, str):
                    statements.extend(self._split_text_into_statements(item))
                elif isinstance(item, dict):
                    statements.extend(self._extract_from_rule_object(item))
                else:
                    statements.append(str(item))
            return [s.strip() for s in statements if s.strip()]

        if isinstance(data, dict):
            if "rules" in data and isinstance(data["rules"], list):
                statements: list[str] = []
                for rule in data["rules"]:
                    if isinstance(rule, dict):
                        statements.extend(self._extract_from_rule_object(rule))
                    else:
                        statements.append(str(rule))
                return [s.strip() for s in statements if s.strip()]
            return self._extract_from_rule_object(data)

        return [str(data)]

    def _extract_from_rule_object(self, obj: dict[str, Any]) -> list[str]:
        text_keys = ("rule", "statement", "text", "description", "policy")
        conditions = obj.get("conditions")
        if conditions and isinstance(conditions, list):
            return [str(c) for c in conditions]
        for key in text_keys:
            if key in obj and obj[key]:
                return self._split_text_into_statements(str(obj[key]))
        return [str(obj)]

    def _split_text_into_statements(self, text: str) -> list[str]:
        pieces = re.split(r"(?:\n+|;\s+|\.\s+|^\s*[-*]\s+)", text, flags=re.MULTILINE)
        return [p.strip(" .\n\t") for p in pieces if p and p.strip(" .\n\t")]

    def _infer_domain(self, statement: str) -> str:
        lowered = statement.lower()
        for domain, keywords in self._DOMAIN_KEYWORDS.items():
            if any(self._contains_keyword(lowered, k) for k in keywords):
                return domain
        return "general_policy"

    def _contains_keyword(self, text: str, keyword: str) -> bool:
        pattern = rf"\b{re.escape(keyword.lower())}\b"
        return re.search(pattern, text) is not None

    def _normalize_statement(self, statement: str, domain: str, idx: int) -> NormalizedRule:
        boolean_logic = self._extract_boolean(statement)
        thresholds = self._extract_thresholds(statement)
        temporal = self._extract_temporal(statement)
        dependencies = self._extract_dependencies(statement)
        return NormalizedRule(
            rule_id=f"rule-{idx}",
            source_domain=domain,
            original_text=statement,
            boolean_logic=boolean_logic,
            thresholds=thresholds,
            temporal_constraints=temporal,
            dependencies=dependencies,
            metadata={"has_explicit_if": "if" in statement.lower()},
        )

    def _extract_boolean(self, text: str) -> list[BooleanExpression]:
        lowered = text.lower()
        expressions: list[BooleanExpression] = []
        if " if " in f" {lowered} ":
            condition = lowered.split(" if ", 1)[1]
            expressions.append(BooleanExpression(operator="if", operands=[condition.strip()]))
        if " unless " in f" {lowered} ":
            condition = lowered.split(" unless ", 1)[1]
            expressions.append(BooleanExpression(operator="unless", operands=[condition.strip()]))
        connectors = [token for token in ("and", "or", "not") if re.search(rf"\b{token}\b", lowered)]
        if connectors:
            expressions.append(BooleanExpression(operator="connectors", operands=connectors))
        return expressions

    def _extract_thresholds(self, text: str) -> list[ThresholdConstraint]:
        results: list[ThresholdConstraint] = []
        for match in self._THRESHOLD_PATTERN.finditer(text):
            metric = match.group("metric").strip()
            value = float(match.group("value"))
            comparator = match.group("comparator")
            unit = match.group("unit")
            results.append(
                ThresholdConstraint(
                    metric=metric,
                    comparator=comparator,
                    value=value,
                    unit=unit,
                )
            )

        at_least = self._AT_LEAST_PATTERN.search(text)
        if at_least:
            results.append(
                ThresholdConstraint(
                    metric="implicit_metric",
                    comparator=">=",
                    value=float(at_least.group("value")),
                    unit=at_least.group("unit"),
                )
            )

        no_more_than = self._NO_MORE_THAN_PATTERN.search(text)
        if no_more_than:
            results.append(
                ThresholdConstraint(
                    metric="implicit_metric",
                    comparator="<=",
                    value=float(no_more_than.group("value")),
                    unit=no_more_than.group("unit"),
                )
            )
        return results

    def _extract_temporal(self, text: str) -> list[TemporalConstraint]:
        constraints: list[TemporalConstraint] = []
        for match in self._WITHIN_PATTERN.finditer(text):
            constraints.append(
                TemporalConstraint(
                    relation="within",
                    value=int(match.group("value")),
                    unit=match.group("unit"),
                )
            )
        for match in self._EVERY_PATTERN.finditer(text):
            constraints.append(
                TemporalConstraint(
                    relation="every",
                    value=int(match.group("value")),
                    unit=match.group("unit"),
                )
            )
        for match in self._BEFORE_AFTER_PATTERN.finditer(text):
            constraints.append(
                TemporalConstraint(
                    relation=match.group("relation").lower(),
                    value=match.group("target").strip(),
                )
            )
        return constraints

    def _extract_dependencies(self, text: str) -> list[Dependency]:
        dependencies: list[Dependency] = []
        for match in self._DEPENDENCY_PATTERN.finditer(text):
            relation = match.group(1).lower()
            target = match.group("target").strip(" .")
            dep_type = "requires" if "require" in relation else relation.replace(" ", "_")
            dependencies.append(Dependency(dependency_type=dep_type, target=target))
        return dependencies
