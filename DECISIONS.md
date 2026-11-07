# SwitchGate Lite — Architectural Decisions & Tradeoffs (`DECISIONS.md`)

## 1. Why Switch Rooms Are Central to SwitchGate Lite
Switch Rooms connect humans and AI agents in shared channels, but per the [Switch Shared Responsibility Model](https://docs.switchagents.ai/switch-rooms/resources/shared-responsibility), Switch does not inspect what a tool call will do or turn a chat message into a reviewed action. SwitchGate Lite uses two Switch Rooms (`#incident-triage` and `#approval-vault`, with a single-room fallback toggle `SWITCH_SINGLE_ROOM_MODE=true`) as an operational approval airlock.

## 2. Why Two Agents + Deterministic Executor (The Sandwich Pattern)
- **`@triage-agent` (LLM Tool-Calling Agent)**: Runs a bounded `while turn < max_turns:` loop (`src/agents.py`) using read-only `@tool` functions (`get_service_error_metrics`, `get_feature_flag_state`, `stage_flag_rollback_proposal` in `src/tools.py`). It holds **zero** write permissions (`PRAGMA query_only = ON`).
- **`@policy-auditor` (Policy Audit Agent)**: Audits the proposed feature-flag rollback against `config/policy.json` (blocking protected flags like `root_db_migration_lock` and verifying SHA-256 integrity) before posting the approval card to `#approval-vault`.
- **`@action-steward` (`ActionExecutor` in `src/executor.py`)**: A 100% deterministic Python executor that only mutates the SQLite `feature_flags` table after verifying an explicit human approval (`/approve <proposal_id> <sha256_prefix>`) and recomputing the RFC 8785 canonical JSON SHA-256 digest to prevent Time-of-Check to Time-of-Use (TOCTOU) parameter tampering.

## 3. Why Zero Third-Party Pip Dependencies for the Core Engine
To guarantee instant clone-and-run reproducibility on any macOS/Linux machine (including bare system Python 3.9+ without virtualenv compilation delays), the entire SwitchGate Lite runtime uses Python's standard library (`sqlite3`, `hashlib`, `http.client`, `json`, `unittest`, `ast`).

## 4. Key Scope Tradeoffs Made for the 120-Minute Deadline
- **Cut**: Separate React/HTMX web dashboard, Ed25519 asymmetric keypair ceremonies, Kubernetes/cloud APIs, and FinOps billing tables.
- **Kept**: Real Switch HTTP/SSE room protocol integration (`src/switch_bridge.py`), real live LLM HTTP API support (`src/llm_client.py`), canonical SHA-256 parameter binding (`src/models.py`), deterministic SQLite feature-flag execution + 1-command `/rollback` (`src/executor.py`), and 8 automated tests covering unit and live integration scenarios (`tests/test_switchgate_lite.py` and `tests/test_live_integration.py`).
