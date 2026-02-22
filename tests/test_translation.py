import json
from src.translator.core import PolicySchemaTranslator
from src.models.policy_schema import PolicyDomain, PolicyScope

def test_manual_translation_flow():
    """
    Simulates the flow of translating a complex policy into a structured object.
    Since we don't have a live LLM, we'll demonstrate the structure creation.
    """
    translator = PolicySchemaTranslator()
    
    nl_policy = (
        "All agents must maintain a trust score above 0.7 for financial transactions. "
        "If an agent's trust score drops below 0.7, their transacting privilege is revoked immediately, "
        "unless they are in 'emergency_repair' mode where they can still transact up to 100 credits."
    )
    
    # In a real scenario, this would be the output of translator.translate() calling an LLM.
    # Here we show what the resulting object looks like.
    
    print(f"Translating Policy: {nl_policy}\n")
    
    # Manually creating the object that an LLM would produce
    from src.models.policy_schema import StructuredPolicy, LogicalCondition, ConditionOperator, ActionTrigger, ExceptionHandler
    from datetime import datetime
    
    structured_policy = StructuredPolicy(
        policy_id="pol-trust-fin-001",
        title="Financial Trust Enforcement",
        domain=PolicyDomain.FINANCE,
        scope=PolicyScope.GLOBAL,
        effective_date=datetime.utcnow(),
        raw_source=nl_policy,
        rationale="Enforces high trust for financial stability with specific repair exceptions.",
        conditions=[
            LogicalCondition(
                parameter="trust_score",
                operator=ConditionOperator.GT,
                value=0.7,
                description="Minimum trust score required for transactions."
            )
        ],
        triggers=[
            ActionTrigger(
                trigger_type="on_violation",
                action_name="revoke_privilege",
                parameters={"privilege": "transaction", "effect": "immediate"}
            )
        ],
        exceptions=[
            ExceptionHandler(
                condition="agent_state == 'emergency_repair'",
                override_action="allow_limited_transaction",
                priority=10
            )
        ],
        instructions=[
            "Monitor agent.trust_score in real-time.",
            "If transaction requested and trust_score <= 0.7, check agent_state.",
            "If agent_state is 'emergency_repair', limit transaction to 100 credits.",
            "Otherwise, block transaction and emit 'privilege_revoked' event."
        ]
    )
    
    json_output = translator.export_as_json(structured_policy)
    print("Structured Machine-Readable Output:")
    print(json_output)
    
    # Verify parsing back
    parsed_policy = PolicySchemaTranslator.from_json(json_output)
    assert parsed_policy.policy_id == "pol-trust-fin-001"
    assert parsed_policy.domain == PolicyDomain.FINANCE
    print("\nVerification Successful: Policy parsed and validated.")

if __name__ == "__main__":
    test_manual_translation_flow()
