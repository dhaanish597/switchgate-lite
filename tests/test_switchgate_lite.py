"""Automated tests for SwitchGate Lite covering all 5 required working scenarios + NVIDIA config."""
import json
import os
import tempfile
from typing import Any, Dict, List, Optional
import unittest

from src.agents import PolicyAuditorAgent, TriageAgent
from src.executor import ActionExecutor, GovernancePermissionError
from src.llm_client import DEFAULT_NVIDIA_BASE_URL, DEFAULT_NVIDIA_MODEL, LiveLLMClient, TelemetryLogger
from src.sandbox_db import SandboxDatabase
from src.switch_bridge import SwitchGateWorkflow, SwitchRoomBridge


class InMemorySwitchRoomTransport:
    """Records Switch room messages for deterministic verification of room collaboration."""

    def __init__(self) -> None:
        self.rooms: Dict[str, List[Dict[str, Any]]] = {}

    def handle(
        self, method: str, path: str, payload: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        if path == "/health":
            return {"status": "ok"}
        parts = [p for p in path.split("/") if p]
        room_id = parts[3] if len(parts) >= 4 else "default"
        self.rooms.setdefault(room_id, [])
        if method == "POST" and payload is not None:
            self.rooms[room_id].append(payload)
            return {"status": "posted", "message": payload}
        if method == "GET":
            return {"room_id": room_id, "messages": list(self.rooms[room_id])}
        return {}


def structured_test_llm_transport(
    system_prompt: str, user_prompt: str, meta: Dict[str, Any]
) -> Dict[str, Any]:
    """Drives the 3-turn TriageAgent tool loop and PolicyAuditorAgent review."""
    if "@policy-auditor" in system_prompt:
        return {"passed": True, "notes": "Policy audit PASSED: rollback of checkout_v2_new_payment_flow is safe."}

    state = json.loads(user_prompt)
    history = state.get("tool_history", [])
    inc = state.get("incident", {})
    if len(history) == 0:
        return {
            "action": "call_tool",
            "tool_name": "get_service_error_metrics",
            "arguments": {"service_name": inc.get("service_name", "payment-checkout")},
            "thought": "Check service error metrics first.",
        }
    if len(history) == 1:
        return {
            "action": "call_tool",
            "tool_name": "get_feature_flag_state",
            "arguments": {"flag_key": "checkout_v2_new_payment_flow"},
            "thought": "Inspect current state of checkout_v2_new_payment_flow.",
        }
    if len(history) == 2:
        return {
            "action": "call_tool",
            "tool_name": "stage_flag_rollback_proposal",
            "arguments": {
                "incident_id": inc.get("incident_id", "inc_01"),
                "flag_key": "checkout_v2_new_payment_flow",
                "to_enabled": 0,
                "reason": "HTTP 500 error rate spiked to 18.4% after enabling checkout_v2_new_payment_flow",
            },
            "thought": "Stage rollback proposal to disable checkout_v2_new_payment_flow.",
        }
    last_out = history[-1].get("output", {})
    return {
        "action": "final_proposal",
        "proposal_id": last_out.get("proposal_id", ""),
        "sha256_digest": last_out.get("sha256_digest", ""),
        "summary": "Proposed disabling checkout_v2_new_payment_flow due to 18.4% HTTP 500 spike.",
    }


class SwitchGateLiteTestSuite(unittest.TestCase):
    """Verifies the 5 required working tests and NVIDIA Build provider wiring."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = f"{self.tmp_dir.name}/test_sandbox.db"
        self.log_dir = f"{self.tmp_dir.name}/logs"
        self.db = SandboxDatabase(self.db_path)
        self.room_transport = InMemorySwitchRoomTransport()
        self.bridge = SwitchRoomBridge(
            triage_room_id="incident-triage",
            approval_room_id="approval-vault",
            custom_handler=self.room_transport.handle,
        )
        self.telemetry = TelemetryLogger(self.log_dir)
        self.llm = LiveLLMClient(
            provider="nvidia",
            model=DEFAULT_NVIDIA_MODEL,
            base_url=DEFAULT_NVIDIA_BASE_URL,
            telemetry=self.telemetry,
            transport_fn=structured_test_llm_transport,
        )
        self.triage = TriageAgent(self.db, self.llm, max_turns=4)
        self.auditor = PolicyAuditorAgent(self.db, llm_client=self.llm)
        self.executor = ActionExecutor(self.db)
        self.workflow = SwitchGateWorkflow(self.bridge, self.triage, self.auditor, self.executor)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_01_legitimate_proposal_approved_and_executed(self) -> None:
        """Test 1: A legitimate proposal can be approved and executed."""
        flag_before = self.db.get_flag("checkout_v2_new_payment_flow")
        self.assertIsNotNone(flag_before)
        self.assertEqual(flag_before["enabled"], 1)

        proposal, verdict = self.workflow.handle_human_incident(
            reporter_id="sam",
            service_name="payment-checkout",
            description="Checkout 500s at 18.4% since 09:40Z",
        )
        self.assertTrue(verdict.passed)
        self.assertEqual(proposal.status, "AUDITED_AWAITING_HUMAN")

        receipt = self.workflow.handle_human_approval(
            approver_id="priya",
            proposal_id=proposal.proposal_id,
            sha256_prefix=proposal.sha256_digest[:8],
        )
        flag_after = self.db.get_flag("checkout_v2_new_payment_flow")
        self.assertEqual(flag_after["enabled"], 0)
        self.assertEqual(receipt.new_enabled, 0)
        self.assertEqual(receipt.proposal_sha256, proposal.sha256_digest)

    def test_02_unapproved_proposal_cannot_execute(self) -> None:
        """Test 2: An unapproved proposal cannot execute."""
        proposal, _ = self.workflow.handle_human_incident(
            reporter_id="sam",
            service_name="payment-checkout",
            description="Checkout 500 spike",
        )
        with self.assertRaises(GovernancePermissionError):
            self.executor.execute_approved_proposal(proposal.proposal_id)

        flag_now = self.db.get_flag("checkout_v2_new_payment_flow")
        self.assertEqual(flag_now["enabled"], 1)

    def test_03_changed_proposal_cannot_execute_using_original_approval(self) -> None:
        """Test 3: A changed proposal cannot execute using approval of the original."""
        proposal, _ = self.workflow.handle_human_incident(
            reporter_id="sam",
            service_name="payment-checkout",
            description="Checkout 500 spike",
        )
        self.executor.record_human_decision(
            proposal_id=proposal.proposal_id,
            actor_id="priya",
            actor_type="human",
            decision="approve",
            sha256_prefix=proposal.sha256_digest[:8],
        )
        approved_prop = self.db.get_proposal(proposal.proposal_id)
        self.assertIsNotNone(approved_prop)
        approved_prop.flag_key = "realtime_webhook_fanout"
        self.db.save_proposal(approved_prop)

        with self.assertRaises(GovernancePermissionError):
            self.executor.execute_approved_proposal(proposal.proposal_id)

        self.assertEqual(self.db.get_flag("checkout_v2_new_payment_flow")["enabled"], 1)
        self.assertEqual(self.db.get_flag("realtime_webhook_fanout")["enabled"], 1)

    def test_04_rollback_restores_original_sandbox_state(self) -> None:
        """Test 4: Rollback restores the original sandbox state."""
        initial_digest = self.db.compute_flags_state_digest()
        proposal, _ = self.workflow.handle_human_incident(
            reporter_id="sam",
            service_name="payment-checkout",
            description="Checkout 500 spike",
        )
        receipt = self.workflow.handle_human_approval(
            approver_id="priya",
            proposal_id=proposal.proposal_id,
            sha256_prefix=proposal.sha256_digest[:8],
        )
        self.assertNotEqual(self.db.compute_flags_state_digest(), initial_digest)

        revert_receipt = self.workflow.handle_human_rollback(
            operator_id="priya", receipt_id=receipt.receipt_id
        )
        restored_digest = self.db.compute_flags_state_digest()
        self.assertEqual(restored_digest, initial_digest)
        self.assertEqual(revert_receipt.post_state_digest, initial_digest)
        self.assertEqual(self.db.get_flag("checkout_v2_new_payment_flow")["enabled"], 1)

    def test_05_switch_messages_and_ai_responses_visible(self) -> None:
        """Test 5: Switch room messages and AI responses are recorded and visible."""
        proposal, _ = self.workflow.handle_human_incident(
            reporter_id="sam",
            service_name="payment-checkout",
            description="Checkout 500 spike",
        )
        self.workflow.handle_human_approval(
            approver_id="priya",
            proposal_id=proposal.proposal_id,
            sha256_prefix=proposal.sha256_digest[:8],
        )
        triage_msgs = self.bridge.get_room_messages("incident-triage")
        approval_msgs = self.bridge.get_room_messages("approval-vault")
        self.assertEqual(len(triage_msgs), 2)
        self.assertEqual(triage_msgs[0]["sender"], "sam")
        self.assertEqual(triage_msgs[1]["sender"], "@triage-agent")
        self.assertIn(proposal.sha256_digest, triage_msgs[1]["content"])
        self.assertEqual(len(approval_msgs), 3)
        self.assertEqual(approval_msgs[0]["sender"], "@policy-auditor")
        self.assertEqual(approval_msgs[1]["sender"], "priya")
        self.assertEqual(approval_msgs[2]["sender"], "@action-steward")

    def test_06_nvidia_build_defaults_and_json_extraction(self) -> None:
        """Verifies NVIDIA Build env defaults and structured JSON extraction."""
        old_key = os.environ.pop("NVIDIA_API_KEY", None)
        try:
            unconfigured = LiveLLMClient(provider="nvidia", telemetry=self.telemetry)
            self.assertEqual(unconfigured.base_url, "https://integrate.api.nvidia.com/v1")
            self.assertEqual(unconfigured.model, "meta/llama-3.3-70b-instruct")
            self.assertFalse(unconfigured.is_configured())
            parsed = LiveLLMClient._extract_json_dict(
                "<think>reasoning</think>\n```json\n{\"action\": \"final_proposal\", \"proposal_id\": \"p1\"}\n```"
            )
            self.assertEqual(parsed["action"], "final_proposal")
        finally:
            if old_key is not None:
                os.environ["NVIDIA_API_KEY"] = old_key


if __name__ == "__main__":
    unittest.main()
