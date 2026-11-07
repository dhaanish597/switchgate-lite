# SwitchGate Lite — 2-Minute Demo Script & Submission Checklist (`DEMO_AND_SUBMISSION.md`)

## 1. Timed 2-Minute Demo Script

- **0:00 – 0:20 (Problem & Switch Centrality)**:
  - Show [`config/switchgate-lite.template.yaml`](config/switchgate-lite.template.yaml) with two rooms: `#incident-triage` and `#approval-vault`.
  - Explain: *"Switch connects AI agents to team chat, but per Switch's Shared Responsibility Model, Switch doesn't inspect tool calls or turn a chat reply into a parameter-bound approval. SwitchGate Lite adds a SHA-256 human approval airlock and deterministic SQLite rollback."*
- **0:20 – 0:55 (Incident Report -> AI Triage -> Policy Audit)**:
  - In `#incident-triage`, human operator `sam` posts: `"HTTP 500 error rate spiked to 18.4% after checkout_v2_new_payment_flow was enabled."`
  - `@triage-agent` runs its bounded `while turn < max_turns` tool loop (`get_service_error_metrics`, `get_feature_flag_state`, `stage_flag_rollback_proposal`) using a read-only SQLite connection (`PRAGMA query_only = ON`) and proposes disabling `checkout_v2_new_payment_flow` (`1 -> 0`).
  - `@policy-auditor` checks `config/policy.json`, verifies the flag is not in `protected_flags`, and posts the approval card with the exact parameters and **Canonical SHA-256 Digest** to `#approval-vault`.
- **0:55 – 1:30 (Human Approval -> SQLite Execution -> Auditable Receipt -> Rollback)**:
  - In `#approval-vault`, human approver `priya` replies `/approve <proposal_id> <sha256_prefix>`.
  - `@action-steward` (`ActionExecutor`) verifies `priya` is in `authorized_human_approvers`, recomputes the SHA-256 digest to block TOCTOU parameter tampering, flips `checkout_v2_new_payment_flow` from `1` to `0` in `data/sandbox.db`, and posts the `ExecutionReceipt`.
  - `priya` sends `/rollback <receipt_id>` and `@action-steward` restores the original SQLite state digest byte-for-byte.
- **1:30 – 2:00 (Automated Security & Guardrail Tests)**:
  - Run `python3 -m unittest discover -s tests -v` and `python3 scripts/verify_guardrails.py` in the terminal showing all 8 tests passing.

## 2. Final Pre-Submission Checklist (Before 23:59 IST)

- [x] `python3 scripts/verify_guardrails.py` passes (all `.py` files `<= 250` lines, all functions `<= 40` lines, `while turn < max_turns` present, `3` `@tool` schemas present).
- [x] `python3 -m unittest discover -s tests -v` passes all 8 tests (6 unit tests + 2 live integration tests).
- [x] Local `switch-core` and PostgreSQL running in Docker Compose (`http://127.0.0.1:8000`).
- [x] Live LLM inference verified (`sarvam-105b-conversations` / `meta/llama-3.3-70b-instruct`).
- [x] `python3 -m src.cli check-switch` passes against live Switch Core.
- [x] `python3 -m src.cli check-llm` passes with live model response and telemetry logging.
- [x] `python3 -m src.cli run-flow --reset-db --with-rollback` completes all 4 stages and delivers real Switch messages.
- [x] Security review: `.env` and SQLite database files ignored in `.gitignore`, no credentials tracked in Git.
