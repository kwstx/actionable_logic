from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field
from datetime import datetime
import threading
import logging

from src.models.policy_schema import StructuredPolicy, LogicalCondition, ConditionOperator, PolicyDomain
from src.enforcement.engine import PolicyEnforcer, EnforcementResult

logger = logging.getLogger(__name__)

class GuardrailAction(str, Enum):
    ALLOW = "allow"
    CORRECT = "correct"
    REROUTE = "reroute"
    ESCALATE = "escalate"
    BLOCK = "block"

class GuardrailResponse(BaseModel):
    """Adaptive response from the guardrails engine."""
    action: GuardrailAction
    reason: str
    suggested_correction: Optional[Dict[str, Any]] = None
    target_route: Optional[str] = None
    applied_policies: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class AdaptiveGuardrailsEngine:
    """
    Monitors agent actions relative to active policies.
    Detected violations or potential conflicts trigger automatic corrective actions,
    task routing adjustments, or escalation.
    """

    def __init__(self, context: Optional[Dict[str, Any]] = None):
        self._enforcer = PolicyEnforcer()
        self._context = context or {}
        self._lock = threading.RLock()
        self._routing_table: Dict[str, str] = {} # action -> target_workflow
        self._policy_metadata: Dict[str, Dict[str, Any]] = {}

    def apply_policy_update(self, policy: StructuredPolicy) -> None:
        """
        Subscribed to LiveUpdateEngine. 
        Updates guardrails in real-time as policies propagate.
        """
        with self._lock:
            # Update or add policy
            existing_idx = None
            for i, p in enumerate(self._enforcer.policies):
                if p.policy_id == policy.policy_id:
                    existing_idx = i
                    break
            
            if existing_idx is not None:
                self._enforcer.policies[existing_idx] = policy
            else:
                self._enforcer.add_policy(policy)
            
            # Analyze policy for routing hints or priority
            self._analyze_policy_dynamics(policy)
            self._check_static_conflicts(policy)
            logger.info(f"Guardrails updated with policy: {policy.policy_id} (v{policy.version})")

    def _check_static_conflicts(self, new_policy: StructuredPolicy):
        """Detects if a new policy overlaps with existing ones in a potentially conflicting way."""
        for existing in self._enforcer.policies:
            if existing.policy_id == new_policy.policy_id:
                continue
            
            # Simple check: identical conditions but different instructions/triggers
            if existing.conditions == new_policy.conditions and existing.conditions:
                logger.warning(
                    f"Static Conflict Detected: Policy '{new_policy.policy_id}' has same conditions as "
                    f"'{existing.policy_id}' but may have different effects."
                )

    def _analyze_policy_dynamics(self, policy: StructuredPolicy):
        """Extract metadata for routing and conflict detection."""
        # For example, look for 'reroute' instructions or specific triggers
        for trigger in policy.triggers:
            if trigger.trigger_type == "on_violation":
                if "reroute" in trigger.action_name.lower():
                    target = trigger.parameters.get("target_workflow")
                    if target:
                        # Simple mapping for demo
                        self._routing_table[policy.policy_id] = target

    def monitor_action(self, agent_id: str, action: Dict[str, Any]) -> GuardrailResponse:
        """
        Evaluates a proposed agent action against all active policies.
        Returns a structured response with suggested corrections or routing changes.
        """
        with self._lock:
            # 1. Evaluate against current policies
            eval_context = {**self._context, "agent_id": agent_id}
            results = self._enforcer.evaluate(action, eval_context)

            # 2. Proactive Monitoring: Detect 'near-misses' (potential conflicts)
            # Find policies where most but not all conditions are met
            potential_conflicts = self._detect_potential_conflicts(action, eval_context)
            
            # 3. Check for active violations
            active_violations = [r for r in results if r.metadata.get("status") == "active" or not r.is_allowed]
            
            if not active_violations:
                if potential_conflicts:
                    return GuardrailResponse(
                        action=GuardrailAction.CORRECT,
                        reason=f"Potential policy conflicts detected: {', '.join(potential_conflicts)}",
                        suggested_correction={"warning": "Action is close to policy limits."},
                        applied_policies=potential_conflicts
                    )
                return GuardrailResponse(
                    action=GuardrailAction.ALLOW,
                    reason="No policy violations detected."
                )

            # 4. Resolve actual conflicts (multiple restrictive policies active)
            restrictive_policies = [r for r in active_violations if r.instructions or not r.is_allowed]
            if len(restrictive_policies) > 1:
                return self._resolve_active_conflicts(restrictive_policies, action)

            # 5. Process single violation/active policy
            primary_result = active_violations[0]
            return self._determine_adaptive_response(primary_result, action)

    def _detect_potential_conflicts(self, action: Dict[str, Any], context: Dict[str, Any]) -> List[str]:
        """Detects policies that are partially matched (e.g., 1 condition away)."""
        near_misses = []
        for policy in self._enforcer.policies:
            if not policy.conditions:
                continue
                
            matched_count = 0
            for cond in policy.conditions:
                if self._enforcer._evaluate_condition(cond, action):
                    matched_count += 1
            
            # If > 75% of conditions are met, it's a 'potential conflict'
            if 0 < matched_count < len(policy.conditions) and (matched_count / len(policy.conditions)) >= 0.75:
                near_misses.append(policy.policy_id)
        return near_misses

    def _resolve_active_conflicts(self, results: List[EnforcementResult], action: Dict[str, Any]) -> GuardrailResponse:
        """
        Heuristic-based conflict resolution.
        Favors security > legal > finance > governance.
        """
        policies = []
        for r in results:
            p = next((p for p in self._enforcer.policies if p.policy_id == r.policy_id), None)
            if p:
                policies.append(p)

        # Sort by domain priority
        domain_priority = {
            PolicyDomain.SECURITY: 0,
            PolicyDomain.LEGAL: 1,
            PolicyDomain.FINANCE: 2,
            PolicyDomain.GOVERNANCE: 3,
            PolicyDomain.COOPERATION: 4
        }
        
        sorted_policies = sorted(policies, key=lambda p: domain_priority.get(p.domain, 10))
        
        # If the highest priority policy allows it but a lower one blocks it, we might still block or escalate
        highest_priority = sorted_policies[0]
        
        return GuardrailResponse(
            action=GuardrailAction.ESCALATE,
            reason=f"Active conflict between {len(policies)} policies. Priority given to {highest_priority.domain.value} ({highest_priority.title}).",
            applied_policies=[p.policy_id for p in sorted_policies]
        )
    def _determine_adaptive_response(self, result: EnforcementResult, action: Dict[str, Any]) -> GuardrailResponse:
        """Determines the best adaptive response for a detected violation."""
        policy = next((p for p in self._enforcer.policies if p.policy_id == result.policy_id), None)
        
        # Priority 1: Escalation if the policy is critical (e.g., SECURITY, LEGAL)
        if policy and policy.domain in ["security", "legal"]:
            return GuardrailResponse(
                action=GuardrailAction.ESCALATE,
                reason=f"Critical policy violation in domain {policy.domain}: {policy.title}",
                applied_policies=[policy.policy_id]
            )

        # Priority 2: Reroute if a routing target is defined for this policy
        if policy and policy.policy_id in self._routing_table:
            return GuardrailResponse(
                action=GuardrailAction.REROUTE,
                reason=f"Policy {policy.policy_id} suggests specialized handling.",
                target_route=self._routing_table[policy.policy_id],
                applied_policies=[policy.policy_id]
            )

        # Priority 3: Automatic Correction suggestion
        for trigger in (policy.triggers if policy else []):
            if trigger.action_name == "suggest_correction":
                return GuardrailResponse(
                    action=GuardrailAction.CORRECT,
                    reason=f"Action violates {policy.title}. Suggesting correction.",
                    suggested_correction=trigger.parameters.get("correction"),
                    applied_policies=[policy.policy_id]
                )

        # Default: Block if not allowed, otherwise Warn/Correct
        if not result.is_allowed:
            return GuardrailResponse(
                action=GuardrailAction.BLOCK,
                reason=f"Action blocked by policy: {result.policy_id}",
                applied_policies=[result.policy_id]
            )
        
        return GuardrailResponse(
            action=GuardrailAction.CORRECT,
            reason=f"Compliance check required for {result.policy_id}",
            applied_policies=[result.policy_id],
            suggested_correction={"review_required": True}
        )
