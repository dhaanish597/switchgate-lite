"""Core data models and RFC 8785 canonical SHA-256 digest functions for SwitchGate Lite."""
from dataclasses import asdict, dataclass, field
import datetime
import hashlib
import json
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    """Returns current UTC timestamp in ISO-8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    """Serializes dictionary to deterministic RFC 8785-style canonical JSON bytes."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def compute_proposal_sha256(
    proposal_id: str,
    incident_id: str,
    flag_key: str,
    from_enabled: int,
    to_enabled: int,
    environment: str,
    reason: str,
) -> str:
    """Computes deterministic SHA-256 digest binding exact proposal parameters."""
    canonical_payload = {
        "environment": str(environment),
        "flag_key": str(flag_key),
        "from_enabled": int(from_enabled),
        "incident_id": str(incident_id),
        "proposal_id": str(proposal_id),
        "reason": str(reason).strip(),
        "to_enabled": int(to_enabled),
    }
    return hashlib.sha256(canonical_json_bytes(canonical_payload)).hexdigest()


@dataclass
class IncidentReport:
    """Represents a human-reported production incident in a Switch Room."""
    incident_id: str
    reporter_id: str
    room_id: str
    service_name: str
    description: str
    created_at: str = field(default_factory=utc_now_iso)


@dataclass
class RollbackProposal:
    """Represents a staged feature-flag rollback proposal bound by SHA-256."""
    proposal_id: str
    incident_id: str
    proposer_agent: str
    flag_key: str
    from_enabled: int
    to_enabled: int
    environment: str
    reason: str
    sha256_digest: str
    status: str = "PROPOSED"
    audit_verdict: str = "PENDING"
    audit_notes: str = ""
    approved_by: Optional[str] = None
    approved_sha256: Optional[str] = None
    created_at: str = field(default_factory=utc_now_iso)

    def current_parameter_hash(self) -> str:
        """Recomputes SHA-256 from current fields to detect parameter tampering."""
        return compute_proposal_sha256(
            proposal_id=self.proposal_id,
            incident_id=self.incident_id,
            flag_key=self.flag_key,
            from_enabled=self.from_enabled,
            to_enabled=self.to_enabled,
            environment=self.environment,
            reason=self.reason,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Converts proposal to dictionary."""
        return asdict(self)


@dataclass
class PolicyVerdict:
    """Represents the output of the Policy Auditor Agent."""
    proposal_id: str
    passed: bool
    policy_id: str
    checked_rules: List[str]
    notes: str
    audited_sha256: str
    audited_at: str = field(default_factory=utc_now_iso)


@dataclass
class ExecutionReceipt:
    """Auditable receipt emitted after deterministic sandbox execution or rollback."""
    receipt_id: str
    proposal_id: str
    action_type: str
    flag_key: str
    previous_enabled: int
    new_enabled: int
    proposal_sha256: str
    approved_by: str
    pre_state_digest: str
    post_state_digest: str
    executed_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        """Converts receipt to dictionary."""
        return asdict(self)
