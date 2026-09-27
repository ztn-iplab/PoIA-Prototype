"""Render signed scope and context without resolving mutable database values."""

import json
from typing import Any, Dict, List, Tuple

Field = Tuple[str, str]


def _value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    if value is None or value == "":
        return "Not specified"
    return str(value)


def render_intent_fields(action: str, scope: Dict[str, Any], context: Dict[str, Any]) -> List[Field]:
    fields = [("Action", action.replace("_", " ").capitalize())]
    fields.extend((key.replace("_", " ").capitalize(), _value(value)) for key, value in scope.items())
    # Execution-time commitment metadata is omitted from the compact display.
    fields.extend((key.replace("_", " ").capitalize(), _value(value))
                  for key, value in context.items() if key != "referent_commitments")
    return fields


def render_intent_summary_text(action: str, scope: Dict[str, Any], context: Dict[str, Any]) -> str:
    return "\n".join(f"{label}: {value}" for label, value in render_intent_fields(action, scope, context))


def resolve_scope_display_overrides(scope: Dict[str, Any]) -> Dict[str, str]:
    # Legacy callers must not substitute current database values for signed IDs.
    return {}
