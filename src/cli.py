"""CLI runner and connection checker for SwitchGate Lite (NVIDIA Build + Switch AI)."""
import argparse
import json
import os
import sys

from src.agents import PolicyAuditorAgent, TriageAgent
from src.env_loader import load_local_env
from src.executor import ActionExecutor
from src.llm_client import DEFAULT_NVIDIA_BASE_URL, DEFAULT_NVIDIA_MODEL, LiveLLMClient
from src.sandbox_db import SandboxDatabase
from src.switch_bridge import SwitchGateWorkflow, SwitchRoomBridge

load_local_env()


def cmd_check_switch(bridge: SwitchRoomBridge) -> int:
    """Checks whether the configured Switch server is reachable."""
    try:
        health = bridge.check_health()
        print(f"SWITCH CONNECTION OK ({bridge.base_url}): {json.dumps(health)}")
        return 0
    except Exception as exc:
        print(
            f"SWITCH CONNECTION BLOCKED ({bridge.base_url}): {exc}\n"
            "Ensure Switch Console / switch-core is running on SWITCH_SERVER_URL."
        )
        return 1


def cmd_check_llm(llm: LiveLLMClient) -> int:
    """Checks whether NVIDIA Build (or fallback LLM) credentials are configured and live."""
    nv_key_present = bool(os.environ.get("NVIDIA_API_KEY", "").strip())
    if not llm.is_configured():
        print(
            f"LLM NOT CONFIGURED: provider='{llm.provider}', model='{llm.model}', "
            f"base_url='{llm.base_url}', NVIDIA_API_KEY_SET={nv_key_present}.\n"
            "Export NVIDIA_API_KEY, NVIDIA_MODEL, and NVIDIA_BASE_URL."
        )
        return 1
    try:
        resp = llm.generate_json(
            agent_id="@cli-check",
            system_prompt="You are a JSON responder. Return ONLY valid JSON: {\"status\": \"ok\", \"provider\": \"nvidia\"}",
            user_prompt="Verify NVIDIA Build inference connection and return JSON.",
        )
        print(
            f"LLM CONNECTION OK (provider={llm.provider}, model={llm.model}, "
            f"base_url={llm.base_url}): {json.dumps(resp)}"
        )
        return 0
    except Exception as exc:
        print(f"LLM CALL FAILED (provider={llm.provider}, model={llm.model}): {exc}")
        return 1


def _build_workflow(args: argparse.Namespace, db: SandboxDatabase) -> SwitchGateWorkflow:
    bridge = SwitchRoomBridge(base_url=args.switch_url, single_room_mode=args.single_room)
    llm = LiveLLMClient(
        provider=args.llm_provider, model=args.llm_model, base_url=args.nvidia_base_url
    )
    triage = TriageAgent(db=db, llm_client=llm)
    auditor = PolicyAuditorAgent(db=db, policy_path=args.policy_path, llm_client=llm)
    executor = ActionExecutor(db=db, policy_path=args.policy_path)
    return SwitchGateWorkflow(bridge, triage, auditor, executor)


def cmd_run_demo(args: argparse.Namespace) -> int:
    """Runs the complete 8-step SwitchGate Lite flow against Switch and live LLM."""
    db = SandboxDatabase(args.db_path)
    if args.reset_db:
        db.reset_sandbox()
    workflow = _build_workflow(args, db)
    initial_digest = db.compute_flags_state_digest()
    print(f"[1/4] Initial SQLite feature_flags digest: {initial_digest}")
    prop, verdict = workflow.handle_human_incident(args.reporter, args.service, args.description)
    print(f"[2/4] Staged & audited: id={prop.proposal_id} sha256={prop.sha256_digest} audit={verdict.passed}")
    if getattr(args, "interactive_approval", False):
        print(f"\n=== HUMAN APPROVAL REQUIRED ===")
        print(f"Proposal: {prop.proposal_id} | Flag: {prop.flag_key} (1 -> 0)")
        print(f"Canonical SHA-256 Digest: {prop.sha256_digest}")
        print(f"Expected: /approve {prop.proposal_id} {prop.sha256_digest[:8]}")
        cmd = input(f"Enter approval command (Enter to approve as {args.approver}): ").strip()
        sha_pfx = cmd.split()[2] if cmd.startswith("/approve") and len(cmd.split()) >= 3 else prop.sha256_digest[:8]
        receipt = workflow.handle_human_approval(args.approver, prop.proposal_id, sha_pfx)
    else:
        receipt = workflow.handle_human_approval(args.approver, prop.proposal_id, prop.sha256_digest[:8])
    flag_now = db.get_flag(prop.flag_key)
    print(f"[3/4] Executed: receipt={receipt.receipt_id} enabled={flag_now['enabled'] if flag_now else 'N/A'}")
    if args.with_rollback:
        rev = workflow.handle_human_rollback(args.approver, receipt.receipt_id)
        restored = db.compute_flags_state_digest()
        print(f"[4/4] Rolled back: receipt={rev.receipt_id} matches_initial={restored == initial_digest}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SwitchGate Lite CLI (NVIDIA Build + Switch AI)")
    parser.add_argument("--switch-url", default=None, help="Switch server URL")
    parser.add_argument("--single-room", action="store_true", help="Use single room mode")
    parser.add_argument("--llm-provider", default="nvidia", help="nvidia (default) | openai | anthropic")
    parser.add_argument(
        "--llm-model",
        default=os.environ.get("NVIDIA_MODEL", DEFAULT_NVIDIA_MODEL),
        help="NVIDIA Build model ID",
    )
    parser.add_argument(
        "--nvidia-base-url",
        default=os.environ.get("NVIDIA_BASE_URL", DEFAULT_NVIDIA_BASE_URL),
        help="NVIDIA Build base URL",
    )
    parser.add_argument("--db-path", default="./data/sandbox.db", help="SQLite DB path")
    parser.add_argument("--policy-path", default="./config/policy.json", help="Policy JSON path")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check-switch", help="Verify Switch server connection")
    sub.add_parser("check-llm", help="Verify live NVIDIA Build LLM API connection")
    run_p = sub.add_parser("run-flow", help="Execute end-to-end incident -> approval -> rollback flow")
    run_p.add_argument("--reporter", default="sam")
    run_p.add_argument("--approver", default="priya")
    run_p.add_argument("--service", default="payment-checkout")
    run_p.add_argument(
        "--description",
        default="HTTP 500 error rate spiked to 18.4% after checkout_v2_new_payment_flow was enabled.",
    )
    run_p.add_argument("--reset-db", action="store_true")
    run_p.add_argument("--with-rollback", action="store_true")
    run_p.add_argument("--interactive-approval", action="store_true", help="Prompt human operator for explicit approval")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    bridge = SwitchRoomBridge(base_url=args.switch_url, single_room_mode=args.single_room)
    llm = LiveLLMClient(
        provider=args.llm_provider, model=args.llm_model, base_url=args.nvidia_base_url
    )
    if args.command == "check-switch":
        return cmd_check_switch(bridge)
    if args.command == "check-llm":
        return cmd_check_llm(llm)
    if args.command == "run-flow":
        return cmd_run_demo(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
