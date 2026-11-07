"""Local SQLite sandbox database for feature flags, proposals, and receipts."""
import hashlib
import json
import pathlib
import sqlite3
from typing import Any, Dict, List, Optional

from src.models import ExecutionReceipt, RollbackProposal, utc_now_iso

DEFAULT_FLAGS = [
    ("checkout_v2_new_payment_flow", "payment-checkout", 1, "production", "2026-11-07T09:40:00Z"),
    ("realtime_webhook_fanout", "webhook-dispatcher", 1, "production", "2026-11-05T14:20:00Z"),
    ("root_db_migration_lock", "core-postgres", 1, "production", "2026-10-01T00:00:00Z"),
]

DEFAULT_METRICS = {
    "payment-checkout": {
        "service": "payment-checkout",
        "http_500_rate_pct": 18.4,
        "p99_latency_ms": 1420,
        "recent_flag_change": "checkout_v2_new_payment_flow enabled at 09:40Z",
        "suspect_flag_key": "checkout_v2_new_payment_flow",
    },
    "webhook-dispatcher": {
        "service": "webhook-dispatcher",
        "http_500_rate_pct": 0.2,
        "p99_latency_ms": 85,
        "recent_flag_change": "none",
        "suspect_flag_key": "realtime_webhook_fanout",
    },
}

SCHEMA_STATEMENTS = [
    (
        "CREATE TABLE IF NOT EXISTS feature_flags ("
        "flag_key TEXT PRIMARY KEY, service_name TEXT NOT NULL, "
        "enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)), "
        "environment TEXT NOT NULL, updated_at TEXT NOT NULL)"
    ),
    (
        "CREATE TABLE IF NOT EXISTS proposals ("
        "proposal_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, "
        "proposer_agent TEXT NOT NULL, flag_key TEXT NOT NULL, "
        "from_enabled INTEGER NOT NULL, to_enabled INTEGER NOT NULL, "
        "environment TEXT NOT NULL, reason TEXT NOT NULL, "
        "sha256_digest TEXT NOT NULL, status TEXT NOT NULL, "
        "audit_verdict TEXT NOT NULL, audit_notes TEXT NOT NULL, "
        "approved_by TEXT, approved_sha256 TEXT, created_at TEXT NOT NULL)"
    ),
    (
        "CREATE TABLE IF NOT EXISTS receipts ("
        "receipt_id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL, "
        "action_type TEXT NOT NULL, flag_key TEXT NOT NULL, "
        "previous_enabled INTEGER NOT NULL, new_enabled INTEGER NOT NULL, "
        "proposal_sha256 TEXT NOT NULL, approved_by TEXT NOT NULL, "
        "pre_state_digest TEXT NOT NULL, post_state_digest TEXT NOT NULL, "
        "executed_at TEXT NOT NULL)"
    ),
]


class SandboxDatabase:
    """Manages SQLite state for feature flags, proposals, and execution receipts."""

    def __init__(self, db_path: str = "./data/sandbox.db") -> None:
        self.db_path = pathlib.Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
        self._seed_defaults()

    def _connect(self, readonly: bool = False) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        if readonly:
            conn.execute("PRAGMA query_only = ON;")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            for stmt in SCHEMA_STATEMENTS:
                conn.execute(stmt)

    def _seed_defaults(self) -> None:
        with self._connect() as conn:
            count = conn.execute("SELECT COUNT(*) FROM feature_flags").fetchone()[0]
            if count == 0:
                conn.executemany(
                    "INSERT INTO feature_flags VALUES (?, ?, ?, ?, ?)",
                    DEFAULT_FLAGS,
                )

    def reset_sandbox(self) -> None:
        """Resets sandbox tables to initial seeded state for deterministic tests."""
        with self._connect() as conn:
            conn.execute("DELETE FROM feature_flags")
            conn.execute("DELETE FROM proposals")
            conn.execute("DELETE FROM receipts")
        self._seed_defaults()

    def get_flag(self, flag_key: str) -> Optional[Dict[str, Any]]:
        """Reads a feature flag using a read-only connection."""
        with self._connect(readonly=True) as conn:
            row = conn.execute(
                "SELECT * FROM feature_flags WHERE flag_key = ?", (flag_key,)
            ).fetchone()
            return dict(row) if row else None

    def list_flags(self) -> List[Dict[str, Any]]:
        """Returns all feature flags ordered by key."""
        with self._connect(readonly=True) as conn:
            rows = conn.execute(
                "SELECT * FROM feature_flags ORDER BY flag_key ASC"
            ).fetchall()
            return [dict(r) for r in rows]

    def compute_flags_state_digest(self) -> str:
        """Computes SHA-256 digest of the entire feature_flags table state."""
        flags = self.list_flags()
        stable = [
            {
                "enabled": int(f["enabled"]),
                "environment": f["environment"],
                "flag_key": f["flag_key"],
                "service_name": f["service_name"],
            }
            for f in flags
        ]
        raw = json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def get_service_metrics(self, service_name: str) -> Dict[str, Any]:
        """Returns diagnostic error rate and latency metrics for a service."""
        return DEFAULT_METRICS.get(
            service_name,
            {
                "service": service_name,
                "http_500_rate_pct": 15.0,
                "p99_latency_ms": 1100,
                "recent_flag_change": "checkout_v2_new_payment_flow enabled",
                "suspect_flag_key": "checkout_v2_new_payment_flow",
            },
        )

    def save_proposal(self, prop: RollbackProposal) -> None:
        """Inserts or updates a RollbackProposal in SQLite."""
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO proposals VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    prop.proposal_id, prop.incident_id, prop.proposer_agent,
                    prop.flag_key, prop.from_enabled, prop.to_enabled,
                    prop.environment, prop.reason, prop.sha256_digest,
                    prop.status, prop.audit_verdict, prop.audit_notes,
                    prop.approved_by, prop.approved_sha256, prop.created_at,
                ),
            )

    def get_proposal(self, proposal_id: str) -> Optional[RollbackProposal]:
        """Retrieves a RollbackProposal by ID."""
        with self._connect(readonly=True) as conn:
            row = conn.execute(
                "SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,)
            ).fetchone()
            return RollbackProposal(**dict(row)) if row else None

    def set_flag_enabled(self, flag_key: str, new_enabled: int) -> None:
        """Updates a feature flag's enabled state (called only by ActionExecutor)."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE feature_flags SET enabled = ?, updated_at = ? WHERE flag_key = ?",
                (int(new_enabled), utc_now_iso(), flag_key),
            )

    def save_receipt(self, receipt: ExecutionReceipt) -> None:
        """Persists an ExecutionReceipt."""
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO receipts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    receipt.receipt_id, receipt.proposal_id, receipt.action_type,
                    receipt.flag_key, receipt.previous_enabled, receipt.new_enabled,
                    receipt.proposal_sha256, receipt.approved_by,
                    receipt.pre_state_digest, receipt.post_state_digest,
                    receipt.executed_at,
                ),
            )

    def get_receipt(self, receipt_id: str) -> Optional[ExecutionReceipt]:
        """Retrieves an ExecutionReceipt by ID."""
        with self._connect(readonly=True) as conn:
            row = conn.execute(
                "SELECT * FROM receipts WHERE receipt_id = ?", (receipt_id,)
            ).fetchone()
            return ExecutionReceipt(**dict(row)) if row else None
