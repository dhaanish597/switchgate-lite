"""Read-only investigation and proposal-staging @tool functions for TriageAgent."""
from typing import Any, Callable, Dict, List
import uuid

from src.models import RollbackProposal, compute_proposal_sha256
from src.sandbox_db import SandboxDatabase

TOOL_SCHEMAS: List[Dict[str, Any]] = []


def tool(name: str, description: str, parameters: Dict[str, Any]) -> Callable[..., Any]:
    """Decorator registering a function with a formal JSON Schema for LLM tool-calling."""
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        func._tool_name = name  # type: ignore[attr-defined]
        TOOL_SCHEMAS.append(
            {
                "name": name,
                "description": description,
                "parameters": parameters,
            }
        )
        return func
    return decorator


class TriageToolBox:
    """Provides read-only inspection and proposal-staging tools (zero write access to flags)."""

    def __init__(self, db: SandboxDatabase) -> None:
        self.db = db

    @tool(
        name="get_service_error_metrics",
        description="Fetches HTTP 500 error rate, latency, and recent flag changes for a service.",
        parameters={
            "type": "object",
            "properties": {"service_name": {"type": "string"}},
            "required": ["service_name"],
        },
    )
    def get_service_error_metrics(self, service_name: str) -> Dict[str, Any]:
        """Returns current telemetry metrics for the specified service."""
        return self.db.get_service_metrics(service_name)

    @tool(
        name="get_feature_flag_state",
        description="Reads the current state of a feature flag from the SQLite sandbox.",
        parameters={
            "type": "object",
            "properties": {"flag_key": {"type": "string"}},
            "required": ["flag_key"],
        },
    )
    def get_feature_flag_state(self, flag_key: str) -> Dict[str, Any]:
        """Reads feature flag state without mutation permissions."""
        flag = self.db.get_flag(flag_key)
        if not flag:
            return {"error": f"Flag '{flag_key}' not found", "available": [f["flag_key"] for f in self.db.list_flags()]}
        return flag

    @tool(
        name="stage_flag_rollback_proposal",
        description="Stages an unapproved feature-flag rollback proposal with a SHA-256 digest.",
        parameters={
            "type": "object",
            "properties": {
                "incident_id": {"type": "string"},
                "flag_key": {"type": "string"},
                "to_enabled": {"type": "integer", "enum": [0, 1]},
                "reason": {"type": "string"},
            },
            "required": ["incident_id", "flag_key", "to_enabled", "reason"],
        },
    )
    def stage_flag_rollback_proposal(
        self,
        incident_id: str,
        flag_key: str,
        to_enabled: int,
        reason: str,
        proposal_id: str = "",
    ) -> Dict[str, Any]:
        """Creates a PROPOSED RollbackProposal and computes its canonical SHA-256 digest."""
        flag = self.db.get_flag(flag_key)
        if not flag:
            raise ValueError(f"Unknown feature flag: {flag_key}")
        prop_id = proposal_id or f"prop_{uuid.uuid4().hex[:8]}"
        from_enabled = int(flag["enabled"])
        env = str(flag["environment"])
        digest = compute_proposal_sha256(
            proposal_id=prop_id,
            incident_id=incident_id,
            flag_key=flag_key,
            from_enabled=from_enabled,
            to_enabled=int(to_enabled),
            environment=env,
            reason=reason,
        )
        proposal = RollbackProposal(
            proposal_id=prop_id,
            incident_id=incident_id,
            proposer_agent="@triage-agent",
            flag_key=flag_key,
            from_enabled=from_enabled,
            to_enabled=int(to_enabled),
            environment=env,
            reason=reason.strip(),
            sha256_digest=digest,
            status="PROPOSED",
        )
        self.db.save_proposal(proposal)
        return proposal.to_dict()

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches a tool call by name."""
        dispatch = {
            "get_service_error_metrics": self.get_service_error_metrics,
            "get_feature_flag_state": self.get_feature_flag_state,
            "stage_flag_rollback_proposal": self.stage_flag_rollback_proposal,
        }
        if tool_name not in dispatch:
            return {"error": f"Unsupported tool: {tool_name}"}
        return dispatch[tool_name](**arguments)
