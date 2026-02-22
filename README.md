# PolicySchemaTranslator

A module for converting natural language policies into structured, machine-readable objects for multi-agent governance systems.

## Overview

The `PolicySchemaTranslator` bridge the gap between human-written regulations and executable agent instructions. It ensures that every policy includes:
- **Metadata**: Scope, Domain, and Effective Date.
- **Logical Conditions**: Parameter-based evaluations (e.g., `trust_score > 0.7`).
- **Action Triggers**: Immediate actions for agents on activation or violation.
- **Exception Handling**: Defined scenarios where policies are bypassed or modified.
- **Actionable Instructions**: Step-by-step guidance for autonomous agents.

## Project Structure

- `src/models/policy_schema.py`: Pydantic models for the structured policy.
- `src/translator/core.py`: Main translator class and serialization logic.
- `src/translator/prompt_templates.py`: Instructions for LLMs to perform the translation.
- `tests/test_translation.py`: Example usage and verification flow.

## Usage

```python
from src.translator import PolicySchemaTranslator
from src.models import PolicyDomain, PolicyScope

translator = PolicySchemaTranslator()

# 1. Translate NL to Structured Object (LLM Required for NL processing)
# structured_policy = translator.translate("Your natural language policy here")

# 2. Export to JSON for Agent consumption
# json_payload = translator.export_as_json(structured_policy)

# 3. Agents load the policy
# policy = PolicySchemaTranslator.from_json(json_payload)
```

## Requirements

- Python 3.10+
- `pydantic>=2.0.0`
