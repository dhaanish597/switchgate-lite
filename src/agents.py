"""TriageAgent (bounded tool loop) and PolicyAuditorAgent for SwitchGate Lite."""
import json
import pathlib
from typing import Any, Dict, List, Optional, Tuple

from src.llm_client import LiveLLMClient
from src.models import IncidentReport, PolicyVerdict, RollbackProposal
from src.prompts import POLICY_AUDITOR_SYSTEM_PROMPT, TRIAGE_AGENT_SYSTEM_PROMPT
from src.sandbox_db import SandboxDatabase
from src.tools import TOOL_SCHEMAS, TriageToolBox


class TriageAgent:
    """LLM-powered Incident Triage Agent executing a bounded tool-calling loop."""

    def __init__(
        self,
        db: SandboxDatabase,
        llm_client: LiveLLMClient,
        max_turns: int = 4,
    ) -> None:
        self.db = db
        self.llm = llm_client
        self.toolbox = TriageToolBox(db)
        self.max_turns = max_turns

    def _build_turn_prompt(
        self, incident: IncidentReport, turn: int, scratchpad: List[Dict[str, Any]]
    ) -> str:
        payload = {
            "incident": {
                "incident_id": incident.incident_id,
                "service_name": incident.service_name,
                "description": incident.description,
            },
            "available_tools": TOOL_SCHEMAS,
            "turn": turn,
            "max_turns": self.max_turns,
            "tool_history": scratchpad,
        }
        return json.dumps(payload, indent=2)

    def investigate_and_propose(self, incident: IncidentReport) -> RollbackProposal:
        """Runs a bounded `while turn < max_turns` loop to investigate and propose a rollback."""
        scratchpad: List[Dict[str, Any]] = []
        staged_id: Optional[str] = None
        turn = 0
        while turn < self.max_turns:
            turn += 1
            prompt = self._build_turn_prompt(incident, turn, scratchpad)
            decision = self.llm.generate_json("@triage-agent", TRIAGE_AGENT_SYSTEM_PROMPT, prompt)
            if decision.get("action") == "call_tool":
                t_name = str(decision.get("tool_name", ""))
                t_args = decision.get("arguments") or {}
                out = self.toolbox.execute_tool(t_name, t_args)
                scratchpad.append({"turn": turn, "tool": t_name, "args": t_args, "output": out})
                if t_name == "stage_flag_rollback_proposal" and "proposal_id" in out:
                    staged_id = str(out["proposal_id"])
            elif decision.get("action") == "final_proposal":
                prop = self.db.get_proposal(str(decision.get("proposal_id") or staged_id or ""))
                if prop:
                    return prop
        if staged_id and self.db.get_proposal(staged_id):
            return self.db.get_proposal(staged_id)  # type: ignore[return-value]
        raise RuntimeError(f"@triage-agent exhausted max_turns={self.max_turns} without proposal.")


class PolicyAuditorAgent:
    """Second agent that audits a RollbackProposal against deterministic policy + LLM review."""

    def __init__(
        self,
        db: SandboxDatabase,
        policy_path: str = "./config/policy.json",
        llm_client: Optional[LiveLLMClient] = None,
    ) -> None:
        self.db = db
        self.policy_path = pathlib.Path(policy_path)
        self.policy = self._load_policy()
        self.llm = llm_client

    def _load_policy(self) -> Dict[str, Any]:
        if self.policy_path.exists():
            return json.loads(self.policy_path.read_text(encoding="utf-8"))
        return {
            "policy_id": "POL-FF-2026-01",
            "allowed_environments": ["production", "staging"],
            "protected_flags": ["root_db_migration_lock", "pci_audit_logging_enabled"],
            "allowed_flags": ["checkout_v2_new_payment_flow", "realtime_webhook_fanout"],
            "authorized_human_approvers": ["priya", "sam", "dhaanish", "oncall-lead"],
        }

    def _evaluate_static_rules(self, proposal: RollbackProposal) -> Tuple[List[str], List[str]]:
        checked = ["sha256_integrity", "protected_flags", "allowed_flags_env", "justification_len"]
        violations: List[str] = []
        if proposal.current_parameter_hash() != proposal.sha256_digest:
            violations.append("SHA-256 digest mismatch on proposal parameters.")
        if proposal.flag_key in set(self.policy.get("protected_flags", [])):
            violations.append(f"Flag '{proposal.flag_key}' is protected and cannot be modified.")
        allowed_flags = set(self.policy.get("allowed_flags", []))
        if allowed_flags and proposal.flag_key not in allowed_flags:
            violations.append(f"Flag '{proposal.flag_key}' is not in allowed_flags.")
        if proposal.environment not in set(self.policy.get("allowed_environments", ["production"])):
            violations.append(f"Environment '{proposal.environment}' is not permitted.")
        if len(proposal.reason.strip()) < 8:
            violations.append("Rollback reason is too short or missing evidence.")
        return checked, violations

    def audit_proposal(self, proposal: RollbackProposal) -> PolicyVerdict:
        """Audits a proposal against policy rules and updates its status in SQLite."""
        checked, violations = self._evaluate_static_rules(proposal)
        passed = len(violations) == 0
        notes = "Policy audit PASSED: eligible for human approval." if passed else "; ".join(violations)
        if passed and self.llm and self.llm.is_configured():
            review = self.llm.generate_json(
                "@policy-auditor",
                POLICY_AUDITOR_SYSTEM_PROMPT,
                json.dumps({"proposal": proposal.to_dict(), "policy": self.policy}),
            )
            if not review.get("passed", True):
                passed = False
                notes = f"LLM Policy Auditor rejected: {review.get('notes', 'Violation')}"
            elif review.get("notes"):
                notes = str(review["notes"])
        proposal.audit_verdict = "PASSED" if passed else "REJECTED"
        proposal.status = "AUDITED_AWAITING_HUMAN" if passed else "AUDIT_REJECTED"
        proposal.audit_notes = notes
        self.db.save_proposal(proposal)
        return PolicyVerdict(
            proposal_id=proposal.proposal_id,
            passed=passed,
            policy_id=str(self.policy.get("policy_id", "POL-FF-2026-01")),
            checked_rules=checked,
            notes=notes,
            audited_sha256=proposal.sha256_digest,
        )
