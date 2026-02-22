from universal_policy_parser import UniversalPolicyParser


def _contains_relation(rule, relation):
    return any(t.relation == relation for t in rule.temporal_constraints)


def _has_dependency(rule):
    return len(rule.dependencies) > 0


def test_parses_diverse_policy_inputs_into_unified_representation():
    parser = UniversalPolicyParser()
    policy_input = [
        "GDPR: If personal data breach occurs, notify DPA within 72 hours and after incident triage approval.",
        "HIPAA: Covered entity must encrypt PHI at rest if risk score >= 8.",
        "FINRA/AML: Flag transaction_amount > 10000 USD unless executive_override exists.",
        "Safety: Workers must wear PPE every 1 day and report incidents within 2 hours.",
        "HR: Employee is eligible for remote work if tenure >= 12 months and performance_score > 4.",
        "Internal approval: Deployment requires security sign-off after QA approval.",
    ]

    unified = parser.parse(policy_input, policy_id="cross-domain", source="unit-test")
    rules = unified.rules

    assert len(rules) == 6
    assert any(r.source_domain == "gdpr" for r in rules)
    assert any(r.source_domain == "hipaa" for r in rules)
    assert any(r.source_domain == "financial_compliance" for r in rules)
    assert any(r.source_domain == "safety_protocol" for r in rules)
    assert any(r.source_domain == "hr_policy" for r in rules)
    assert any(r.source_domain == "internal_approval" for r in rules)

    assert any(_contains_relation(r, "within") for r in rules)
    assert any(_contains_relation(r, "every") for r in rules)
    assert any(_has_dependency(r) for r in rules)
    assert any(len(r.thresholds) > 0 for r in rules)
    assert any(len(r.boolean_logic) > 0 for r in rules)


def test_parses_structured_rule_objects():
    parser = UniversalPolicyParser()
    policy_input = {
        "rules": [
            {"statement": "Approve expense if amount <= 5000 USD and manager_approval exists."},
            {"text": "Run safety audit every 4 weeks before launch."},
        ]
    }

    unified = parser.parse(policy_input, policy_id="structured", source="unit-test")
    assert len(unified.rules) == 2
    assert unified.rules[0].thresholds[0].comparator == "<="
    assert any(t.relation == "every" for t in unified.rules[1].temporal_constraints)
