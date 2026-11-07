"""Live integration test against the real local Switch Core server and real LLM API."""
import unittest

from src.env_loader import load_local_env
from src.llm_client import LiveLLMClient
from src.switch_bridge import SwitchRoomBridge

load_local_env()


class LiveSwitchAndLLMIntegrationTest(unittest.TestCase):
    """Verifies live communication with the running Switch Core and live LLM API."""

    def test_live_switch_connectivity_and_messaging(self) -> None:
        bridge = SwitchRoomBridge()
        health = bridge.check_health()
        self.assertEqual(health.get("status"), "ok")

        test_content = "Smoke verification message from live test suite"
        post_res = bridge.post_room_message("incident-triage", "@smoke-test", "agent", test_content)
        self.assertEqual(post_res.get("status"), "posted")

        messages = bridge.get_room_messages("incident-triage")
        self.assertTrue(len(messages) > 0)
        bodies = [m.get("body", "") for m in messages]
        self.assertTrue(any(test_content in b for b in bodies))

    def test_live_llm_generation(self) -> None:
        llm = LiveLLMClient()
        self.assertTrue(llm.is_configured())
        resp = llm.generate_json(
            agent_id="@live-test",
            system_prompt="Return ONLY valid JSON: {\"tested\": true, \"value\": 42}",
            user_prompt="Run smoke test",
        )
        self.assertIsInstance(resp, dict)
        self.assertTrue(resp.get("tested") is True or resp.get("value") == 42 or "status" in resp)


if __name__ == "__main__":
    unittest.main()
