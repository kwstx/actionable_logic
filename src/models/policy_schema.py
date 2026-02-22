from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field

class PolicyDomain(str, Enum):
    GOVERNANCE = "governance"
    FINANCE = "finance"
    OPERATIONS = "operations"
    ETHICS = "ethics"
    SECURITY = "security"
    LEGAL = "legal"
    COOPERATION = "cooperation"

class PolicyScope(str, Enum):
    GLOBAL = "global"
    DOMAIN_SPECIFIC = "domain_specific"
    TEAM = "team"
    AGENT_SPECIFIC = "agent_specific"

class ConditionOperator(str, Enum):
    GT = ">"
    LT = "<"
    GE = ">="
    LE = "<="
    EQ = "=="
    NE = "!="
    CONTAINS = "contains"
    MATCHES = "matches"

class LogicalCondition(BaseModel):
    """Structured logical condition for policy evaluation."""
    parameter: str = Field(..., description="The system or agent parameter to evaluate.")
    operator: ConditionOperator
    value: Any = Field(..., description="The value to compare against.")
    description: Optional[str] = Field(None, description="Natural language description of the condition.")

class ActionTrigger(BaseModel):
    """Defines an action to be taken when conditions are met."""
    trigger_type: str = Field(..., description="Event type: 'on_violation', 'on_activation', 'on_scheduled'.")
    action_name: str = Field(..., description="The name of the action to execute.")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Parameters for the action.")

class ExceptionHandler(BaseModel):
    """Defines circumstances where the policy is bypassed or modified."""
    condition: str = Field(..., description="DSL or NL description of the exception case.")
    override_action: str = Field(..., description="Action to take: 'ignore', 'log_only', 'escalate'.")
    priority: int = Field(1, description="Priority of the exception handler.")

class StructuredPolicy(BaseModel):
    """
    Machine-readable policy object translated from natural language.
    Includes metadata, logical conditions, triggers, and exception handling.
    """
    # Metadata
    policy_id: str = Field(..., description="Unique identifier.")
    title: str = Field(..., description="Human-readable title.")
    version: str = Field("1.0.0")
    domain: PolicyDomain
    scope: PolicyScope
    effective_date: datetime = Field(default_factory=datetime.utcnow)
    
    # Core Logic
    conditions: List[LogicalCondition] = Field(default_factory=list)
    triggers: List[ActionTrigger] = Field(default_factory=list)
    exceptions: List[ExceptionHandler] = Field(default_factory=list)
    
    # Traceability
    raw_source: str = Field(..., description="The original natural language text.")
    rationale: str = Field(..., description="Reasoning for the policy translation.")
    
    # Actionable instructions for agents
    instructions: List[str] = Field(..., description="Step-by-step instructions for agent execution.")

