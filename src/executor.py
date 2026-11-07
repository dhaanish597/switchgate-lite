"""Deterministic executor validating human approval, SHA-256 binding, execution, and rollback."""
import json
import pathlib
from typing import Set
import uuid

from src.models import ExecutionReceipt, RollbackProposal
from src.sandbox_db import SandboxDatabase


class GovernancePermissionError(PermissionError):
    """Raised when an unapproved, unauthorized, or tampered proposal attempts execution."""


class ActionExecutor:
    """Deterministic executor that gates SQLite feature-flag mutations behind human approval."""

    def __init__(
        self,
        db: SandboxDatabase,
        policy_path: str = "./config/policy.json",
    ) -> None:
        self.db = db
        self.authorized_humans: Set[str] = self._load_authorized_humans(policy_path)

    @staticmethod
    def _load_authorized_humans(policy_path: str) -> Set[str]:
        path = pathlib.Path(policy_path)
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            return {str(u).lower() for u in data.get("authorized_human_approvers", [])}
        return {"priya", "sam", "dhaanish", "oncall-lead"}

    def _validate_human_actor(self, actor_id: str, actor_type: str) -> None:
        if actor_type.lower() != "human":
            raise GovernancePermissionError("Only a human participant can approve or rollback.")
        if actor_id.lower() not in self.authorized_humans:
            raise GovernancePermissionError(f"Human '{actor_id}' is not in authorized_human_approvers.")

    def record_human_decision(
        self,
        proposal_id: str,
        actor_id: str,
        actor_type: str,
        decision: str,
        sha256_prefix: str = "",
        reason: str = "",
    ) -> RollbackProposal:
        """Records an explicit human approval or rejection bound to the proposal's SHA-256 digest."""
        self._validate_human_actor(actor_id, actor_type)
        proposal = self.db.get_proposal(proposal_id)
        if not proposal:
            raise ValueError(f"Proposal '{proposal_id}' does not exist.")
        if proposal.audit_verdict != "PASSED":
            raise GovernancePermissionError(f"Proposal '{proposal_id}' failed policy audit.")
        current_hash = proposal.current_parameter_hash()
        if current_hash != proposal.sha256_digest:
            raise GovernancePermissionError("Proposal parameters were modified after creation.")
        if decision.lower() == "reject":
            proposal.status = "REJECTED_BY_HUMAN"
            proposal.audit_notes = reason or f"Rejected by {actor_id}"
            self.db.save_proposal(proposal)
            return proposal
        if decision.lower() != "approve":
            raise ValueError(f"Invalid decision '{decision}'.")
        if sha256_prefix and not proposal.sha256_digest.startswith(sha256_prefix.lower().strip()):
            raise GovernancePermissionError("Provided SHA-256 prefix does not match proposal digest.")
        proposal.status = "APPROVED"
        proposal.approved_by = actor_id
        proposal.approved_sha256 = current_hash
        self.db.save_proposal(proposal)
        return proposal

    def execute_approved_proposal(self, proposal_id: str) -> ExecutionReceipt:
        """Validates approval and parameter hash binding, then updates the SQLite feature flag."""
        proposal = self.db.get_proposal(proposal_id)
        if not proposal:
            raise ValueError(f"Proposal '{proposal_id}' does not exist.")
        if proposal.status != "APPROVED" or not proposal.approved_by or not proposal.approved_sha256:
            raise GovernancePermissionError(f"Unapproved proposal '{proposal_id}' cannot execute.")
        live_hash = proposal.current_parameter_hash()
        if live_hash != proposal.sha256_digest or live_hash != proposal.approved_sha256:
            raise GovernancePermissionError("TOCTOU hash mismatch detected; execution aborted.")
        flag = self.db.get_flag(proposal.flag_key)
        if not flag:
            raise ValueError(f"Flag '{proposal.flag_key}' not found.")
        pre_digest = self.db.compute_flags_state_digest()
        self.db.set_flag_enabled(proposal.flag_key, proposal.to_enabled)
        post_digest = self.db.compute_flags_state_digest()
        proposal.status = "EXECUTED"
        self.db.save_proposal(proposal)
        receipt = ExecutionReceipt(
            receipt_id=f"rcpt_{uuid.uuid4().hex[:8]}",
            proposal_id=proposal.proposal_id,
            action_type="FEATURE_FLAG_ROLLBACK",
            flag_key=proposal.flag_key,
            previous_enabled=int(flag["enabled"]),
            new_enabled=int(proposal.to_enabled),
            proposal_sha256=live_hash,
            approved_by=proposal.approved_by,
            pre_state_digest=pre_digest,
            post_state_digest=post_digest,
        )
        self.db.save_receipt(receipt)
        return receipt

    def rollback_receipt(self, receipt_id: str, actor_id: str, actor_type: str = "human") -> ExecutionReceipt:
        """Restores the original feature flag state recorded in an ExecutionReceipt."""
        self._validate_human_actor(actor_id, actor_type)
        orig = self.db.get_receipt(receipt_id)
        if not orig:
            raise ValueError(f"Receipt '{receipt_id}' not found.")
        pre_digest = self.db.compute_flags_state_digest()
        current_flag = self.db.get_flag(orig.flag_key)
        current_enabled = int(current_flag["enabled"]) if current_flag else orig.new_enabled
        self.db.set_flag_enabled(orig.flag_key, orig.previous_enabled)
        post_digest = self.db.compute_flags_state_digest()
        proposal = self.db.get_proposal(orig.proposal_id)
        if proposal:
            proposal.status = "ROLLED_BACK"
            self.db.save_proposal(proposal)
        revert_receipt = ExecutionReceipt(
            receipt_id=f"rcpt_rev_{uuid.uuid4().hex[:6]}",
            proposal_id=orig.proposal_id,
            action_type="COMPENSATING_RESTORE",
            flag_key=orig.flag_key,
            previous_enabled=current_enabled,
            new_enabled=orig.previous_enabled,
            proposal_sha256=orig.proposal_sha256,
            approved_by=actor_id,
            pre_state_digest=pre_digest,
            post_state_digest=post_digest,
        )
        self.db.save_receipt(revert_receipt)
        return revert_receipt
