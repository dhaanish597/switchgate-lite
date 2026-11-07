"""Switch Room protocol bridge and workflow coordinator for SwitchGate Lite."""
import json
import os
from typing import Any, Callable, Dict, List, Optional, Tuple
import urllib.error
import urllib.request
import uuid

from src.agents import PolicyAuditorAgent, TriageAgent
from src.env_loader import load_local_env
from src.executor import ActionExecutor
from src.models import ExecutionReceipt, IncidentReport, PolicyVerdict, RollbackProposal, utc_now_iso

load_local_env()


class SwitchRoomBridge:
    """Connects to a Switch server over HTTP REST (with two-room or one-room routing)."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        triage_room_id: Optional[str] = None,
        approval_room_id: Optional[str] = None,
        single_room_mode: bool = False,
        custom_handler: Optional[Callable[[str, str, Optional[Dict[str, Any]]], Dict[str, Any]]] = None,
    ) -> None:
        load_local_env()
        default_host = os.environ.get("SWITCH_BIND_ADDR", "127.0.0.1")
        default_port = os.environ.get("API_HOST_PORT", "8000")
        fallback_url = f"http://{default_host}:{default_port}"
        self.base_url = (base_url or os.environ.get("SWITCH_SERVER_URL", fallback_url)).rstrip("/")
        self.triage_room_id = triage_room_id or os.environ.get("SWITCH_TRIAGE_ROOM_ID", "incident-triage")
        self.single_room_mode = single_room_mode or (
            os.environ.get("SWITCH_SINGLE_ROOM_MODE", "false").lower() == "true"
        )
        raw_approval = approval_room_id or os.environ.get("SWITCH_APPROVAL_ROOM_ID", "approval-vault")
        self.approval_room_id = self.triage_room_id if self.single_room_mode else raw_approval
        self.custom_handler = custom_handler
        self._cached_agent: Optional[Tuple[str, str]] = None
        self._rooms_cache: Dict[str, str] = {}

    def check_health(self) -> Dict[str, Any]:
        """Checks connectivity against the configured Switch server."""
        if self.custom_handler is not None:
            return self.custom_handler("GET", "/health", None)
        url = f"{self.base_url}/health"
        req = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _ensure_live_agent(self) -> Tuple[str, str]:
        if self._cached_agent is not None:
            return self._cached_agent
        token = os.environ.get("SWITCH_AGENT_TOKEN") or os.environ.get("AGENT_REGISTRATION_TOKEN") or ""
        payload = {
            "name": "triage-agent", "display_name": "Triage Agent",
            "description": "SwitchGate Lite Triage Agent", "connector_type": "custom",
            "overwrite": True,
            "integration_profile": {
                "connection_model": "always_on", "message_exchange": True,
                "pre_invocation_mediation": [], "post_invocation_mediation": [], "event_reporting": [],
            },
        }
        req = urllib.request.Request(
            f"{self.base_url}/agents", data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        self._cached_agent = (data["id"], data["api_key"])
        return self._cached_agent

    def _resolve_live_room(self, room_id: str) -> str:
        if room_id in self._rooms_cache:
            return self._rooms_cache[room_id]
        agent_id, api_key = self._ensure_live_agent()
        req = urllib.request.Request(
            f"{self.base_url}/agents/{agent_id}/ops/list_rooms", data=b"{}",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            for r in json.loads(resp.read().decode("utf-8")).get("result", []):
                self._rooms_cache[r["name"]] = r["room_id"]
                self._rooms_cache[r["room_id"]] = r["room_id"]
        if room_id in self._rooms_cache:
            return self._rooms_cache[room_id]
        cr_payload = {"name": room_id, "description": f"SwitchGate {room_id}", "agent_names": ["triage-agent"], "internal_only": True}
        cr_req = urllib.request.Request(
            f"{self.base_url}/agents/{agent_id}/ops/create_room", data=json.dumps(cr_payload).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
            method="POST",
        )
        with urllib.request.urlopen(cr_req, timeout=10) as resp:
            created = json.loads(resp.read().decode("utf-8")).get("result", {})
            self._rooms_cache[room_id] = created.get("id") or room_id
        return self._rooms_cache[room_id]

    def post_room_message(
        self, room_id: str, sender_handle: str, actor_type: str, content: str, metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Posts a message to a Switch Room."""
        payload = {
            "message_id": f"msg_{uuid.uuid4().hex[:10]}", "room_id": room_id,
            "sender": sender_handle, "actor_type": actor_type,
            "content": content, "metadata": metadata or {}, "timestamp": utc_now_iso(),
        }
        if self.custom_handler is not None:
            return self.custom_handler("POST", f"/api/v1/rooms/{room_id}/messages", payload)
        agent_id, api_key = self._ensure_live_agent()
        live_uuid = self._resolve_live_room(room_id)
        msg_payload = {"room_id": live_uuid, "content": f"[{sender_handle}] {content}"}
        req = urllib.request.Request(
            f"{self.base_url}/agents/{agent_id}/message", data=json.dumps(msg_payload).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            res = json.loads(resp.read().decode("utf-8"))
        return {"status": "posted", "result": res, "message": payload}

    def get_room_messages(self, room_id: str) -> List[Dict[str, Any]]:
        """Fetches the message log for a Switch Room."""
        if self.custom_handler is not None:
            data = self.custom_handler("GET", f"/api/v1/rooms/{room_id}/messages", None)
            return list(data.get("messages", []))
        agent_id, api_key = self._ensure_live_agent()
        live_uuid = self._resolve_live_room(room_id)
        req = urllib.request.Request(
            f"{self.base_url}/agents/{agent_id}/ops/read_context", data=json.dumps({"room_id": live_uuid}).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            threads = json.loads(resp.read().decode("utf-8")).get("result", {}).get("threads", [])
        return [t["root"] for t in threads if "root" in t]


class SwitchGateWorkflow:
    """Coordinates the 8-step SwitchGate Lite incident-to-rollback workflow across Switch Rooms."""

    def __init__(
        self, bridge: SwitchRoomBridge, triage_agent: TriageAgent,
        auditor_agent: PolicyAuditorAgent, executor: ActionExecutor
    ) -> None:
        self.bridge = bridge
        self.triage_agent = triage_agent
        self.auditor_agent = auditor_agent
        self.executor = executor

    @staticmethod
    def _format_approval_card(inc_id: str, prop: RollbackProposal, verdict: PolicyVerdict) -> str:
        status_label = "PASSED" if verdict.passed else "REJECTED"
        return (
            f"### SwitchGate Approval Request `{prop.proposal_id}`\n"
            f"- **Incident**: `{inc_id}` | **Flag**: `{prop.flag_key}` (`{prop.from_enabled}` -> `{prop.to_enabled}`)\n"
            f"- **Environment**: `{prop.environment}` | **Policy Audit**: `{status_label}`\n"
            f"- **Reason**: {prop.reason}\n"
            f"- **Canonical SHA-256 Digest**: `{prop.sha256_digest}`\n"
            f"- **Human Command**: Reply `/approve {prop.proposal_id} {prop.sha256_digest[:8]}` or `/reject {prop.proposal_id}`"
        )

    def handle_human_incident(
        self, reporter_id: str, service_name: str, description: str, incident_id: str = ""
    ) -> Tuple[RollbackProposal, PolicyVerdict]:
        """Steps 1–4: Human posts incident -> TriageAgent proposes -> PolicyAuditor audits -> Posted to Switch."""
        inc_id = incident_id or f"inc_{uuid.uuid4().hex[:6]}"
        report = IncidentReport(inc_id, reporter_id, self.bridge.triage_room_id, service_name, description)
        self.bridge.post_room_message(
            self.bridge.triage_room_id, reporter_id, "human",
            f"[INCIDENT {inc_id}] Service `{service_name}`: {description}",
            {"incident_id": inc_id, "service_name": service_name},
        )
        proposal = self.triage_agent.investigate_and_propose(report)
        self.bridge.post_room_message(
            self.bridge.triage_room_id, "@triage-agent", "agent",
            f"@policy-auditor Proposing rollback of `{proposal.flag_key}` ({proposal.from_enabled}->{proposal.to_enabled}). "
            f"Proposal `{proposal.proposal_id}` | SHA-256: `{proposal.sha256_digest}`",
            {"proposal": proposal.to_dict()},
        )
        verdict = self.auditor_agent.audit_proposal(proposal)
        updated = self.executor.db.get_proposal(proposal.proposal_id) or proposal
        self.bridge.post_room_message(
            self.bridge.approval_room_id, "@policy-auditor", "agent",
            self._format_approval_card(inc_id, updated, verdict),
            {"proposal": updated.to_dict(), "verdict": verdict.__dict__},
        )
        return updated, verdict

    def handle_human_approval(
        self, approver_id: str, proposal_id: str, sha256_prefix: str
    ) -> ExecutionReceipt:
        """Steps 5–7: Human approves in Switch -> Executor validates & mutates SQLite -> Posts receipt."""
        self.bridge.post_room_message(
            self.bridge.approval_room_id, approver_id, "human",
            f"/approve {proposal_id} {sha256_prefix}",
            {"command": "approve", "proposal_id": proposal_id, "sha256_prefix": sha256_prefix},
        )
        self.executor.record_human_decision(proposal_id, approver_id, "human", "approve", sha256_prefix)
        receipt = self.executor.execute_approved_proposal(proposal_id)
        receipt_msg = (
            f"### Execution Receipt `{receipt.receipt_id}`\n"
            f"- **Proposal**: `{receipt.proposal_id}` | **Approved By**: `{receipt.approved_by}`\n"
            f"- **Mutation**: Flag `{receipt.flag_key}` changed `{receipt.previous_enabled}` -> `{receipt.new_enabled}`\n"
            f"- **Bound Proposal SHA-256**: `{receipt.proposal_sha256}`\n"
            f"- **Rollback Command**: `/rollback {receipt.receipt_id}`"
        )
        self.bridge.post_room_message(
            self.bridge.approval_room_id, "@action-steward", "agent",
            receipt_msg, {"receipt": receipt.to_dict()},
        )
        return receipt

    def handle_human_rollback(self, operator_id: str, receipt_id: str) -> ExecutionReceipt:
        """Step 8: Human triggers rollback in Switch -> Original SQLite state restored -> Receipt posted."""
        self.bridge.post_room_message(
            self.bridge.approval_room_id, operator_id, "human",
            f"/rollback {receipt_id}", {"command": "rollback", "receipt_id": receipt_id},
        )
        revert_receipt = self.executor.rollback_receipt(receipt_id, operator_id, "human")
        msg = (
            f"### Rollback Receipt `{revert_receipt.receipt_id}`\n"
            f"- **Restored Flag**: `{revert_receipt.flag_key}` (`{revert_receipt.previous_enabled}` -> `{revert_receipt.new_enabled}`)\n"
            f"- **Restored State Digest**: `{revert_receipt.post_state_digest}`"
        )
        self.bridge.post_room_message(
            self.bridge.approval_room_id, "@action-steward", "agent",
            msg, {"receipt": revert_receipt.to_dict()},
        )
        return revert_receipt
