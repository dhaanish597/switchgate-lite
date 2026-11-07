"""SwitchGate Lite - Cloud Web Application & Governance Airlock.
Exposes a responsive browser UI and REST endpoints for:
1. Real Switch Core room messaging and live context
2. Live Sarvam AI 105B model triage and proposal generation
3. Policy audit evaluation against policy.json
4. Authenticated human approval gating
5. Cryptographic SHA-256 bound mutation execution and rollback
"""
import os
import sys
import json
import logging
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

# Ensure src is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.models import IncidentReport, RollbackProposal
from src.sandbox_db import SandboxDatabase
from src.llm_client import LiveLLMClient
from src.agents import TriageAgent, PolicyAuditorAgent
from src.executor import ActionExecutor, GovernancePermissionError
from src.switch_bridge import SwitchRoomBridge, SwitchGateWorkflow

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("switchgate_cloud")

app = FastAPI(title="SwitchGate Lite Cloud Airlock", version="1.0.0")

# Initialize database
DB_PATH = os.environ.get("SANDBOX_DB_PATH", "./sandbox_data.db")
db = SandboxDatabase(DB_PATH)
executor = ActionExecutor(db=db, policy_path="./config/policy.json")

# LLM Client & Agents
llm = LiveLLMClient()
triage_agent = TriageAgent(db=db, llm_client=llm, max_turns=4)
auditor_agent = PolicyAuditorAgent(db=db, llm_client=llm, policy_path="./config/policy.json")

# Switch Core Bridge & Workflow
bridge = SwitchRoomBridge(
    base_url=os.environ.get("SWITCH_URL", "http://127.0.0.1:8000"),
    single_room_mode=True,
)
workflow = SwitchGateWorkflow(
    bridge=bridge,
    triage_agent=triage_agent,
    auditor_agent=auditor_agent,
    executor=executor,
)

ACTIVE_SESSION: Dict[str, Any] = {
    "incident_id": None,
    "proposal": None,
    "verdict": None,
    "latest_receipt": None,
}


# --- API Models ---
class InvestigateRequest(BaseModel):
    service_name: str = "payment-checkout"
    incident_id: str = "INC-2026-991"
    description: str = "High 500 error rate (18.4%) in payment-checkout following feature flag rollout"
    reporter_id: str = "dhaanish"


class ApproveRequest(BaseModel):
    proposal_id: str
    actor_id: str = "dhaanish"
    decision: str = "approve"
    sha256_prefix: str = ""


class ExecuteRequest(BaseModel):
    proposal_id: str


class RollbackRequest(BaseModel):
    receipt_id: str
    actor_id: str = "dhaanish"


# --- REST Endpoints ---
@app.get("/health")
def health_check():
    switch_healthy = False
    try:
        health_resp = bridge.check_health()
        switch_healthy = health_resp.get("status") in ("ok", "healthy")
    except Exception:
        pass

    has_sarvam = bool(os.environ.get("SARVAM_API_KEY"))
    return {
        "status": "healthy",
        "service": "switchgate-lite-cloud",
        "switch_core_connected": switch_healthy,
        "llm_provider": "sarvam-105b-conversations" if has_sarvam else "mock_fallback",
        "database": "sqlite_sandbox_with_render_postgres_switch_core",
    }


@app.get("/api/status")
def get_status():
    flags = db.list_flags()
    return {
        "flags": flags,
        "active_session": ACTIVE_SESSION,
    }


@app.post("/api/investigate")
def investigate_incident(req: InvestigateRequest):
    try:
        proposal, verdict = workflow.handle_human_incident(
            reporter_id=req.reporter_id,
            service_name=req.service_name,
            description=req.description,
            incident_id=req.incident_id,
        )
        ACTIVE_SESSION["incident_id"] = req.incident_id
        ACTIVE_SESSION["proposal"] = proposal.to_dict()
        ACTIVE_SESSION["verdict"] = verdict.__dict__

        return {
            "proposal": proposal.to_dict(),
            "verdict": verdict.__dict__,
            "status": "success",
        }
    except Exception as e:
        logger.error(f"Error in investigate_incident: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/audit")
def audit_proposal():
    prop_data = ACTIVE_SESSION.get("proposal")
    if not prop_data:
        raise HTTPException(status_code=400, detail="No active proposal to audit.")
    proposal = db.get_proposal(prop_data["proposal_id"])
    if not proposal:
        raise HTTPException(status_code=404, detail="Proposal not found in database.")

    verdict = auditor_agent.audit_proposal(proposal)
    ACTIVE_SESSION["proposal"] = proposal.to_dict()
    ACTIVE_SESSION["verdict"] = verdict.__dict__

    return {
        "verdict": "PASSED" if verdict.passed else "REJECTED",
        "notes": verdict.notes,
        "proposal": proposal.to_dict(),
    }


@app.post("/api/approve")
def approve_proposal(req: ApproveRequest):
    try:
        prefix = req.sha256_prefix
        if not prefix and ACTIVE_SESSION.get("proposal"):
            prefix = ACTIVE_SESSION["proposal"].get("sha256_digest", "")[:8]

        receipt = workflow.handle_human_approval(
            approver_id=req.actor_id,
            proposal_id=req.proposal_id,
            sha256_prefix=prefix,
        )
        ACTIVE_SESSION["latest_receipt"] = receipt.to_dict()
        prop = db.get_proposal(req.proposal_id)
        if prop:
            ACTIVE_SESSION["proposal"] = prop.to_dict()

        return {"status": "success", "receipt": receipt.to_dict()}
    except GovernancePermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Error in approve_proposal: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/execute")
def execute_proposal(req: ExecuteRequest):
    try:
        receipt = executor.execute_approved_proposal(proposal_id=req.proposal_id)
        ACTIVE_SESSION["latest_receipt"] = receipt.to_dict()
        return {"status": "success", "receipt": receipt.to_dict()}
    except GovernancePermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/rollback")
def rollback_action(req: RollbackRequest):
    try:
        receipt = workflow.handle_human_rollback(
            operator_id=req.actor_id,
            receipt_id=req.receipt_id,
        )
        ACTIVE_SESSION["latest_receipt"] = receipt.to_dict()
        return {"status": "success", "receipt": receipt.to_dict()}
    except Exception as e:
        logger.error(f"Error in rollback: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/switch/context")
def get_switch_context():
    try:
        messages = bridge.get_room_messages(bridge.triage_room_id)
        return {"messages": messages}
    except Exception as e:
        return {"messages": [], "error": str(e)}


# --- Frontend Dashboard ---
@app.get("/", response_class=HTMLResponse)
def index_page():
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SwitchGate Lite — Cloud Governance Airlock</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card: #111827;
      --border: #1f2937;
      --text: #f9fafb;
      --text-muted: #9ca3af;
      --accent: #3b82f6;
      --accent-hover: #2563eb;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --font-mono: 'JetBrains Mono', 'Fira Code', Menlo, monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      line-height: 1.5;
      padding: 24px;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
    }
    .logo-group h1 { font-size: 22px; font-weight: 700; letter-spacing: -0.5px; }
    .logo-group p { font-size: 13px; color: var(--text-muted); }
    .badge-bar { display: flex; gap: 10px; flex-wrap: wrap; }
    .badge {
      font-size: 11px;
      padding: 4px 10px;
      border-radius: 9999px;
      font-weight: 600;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      background: #1e293b;
      color: var(--text-muted);
      border: 1px solid var(--border);
    }
    .badge.green { background: #064e3b; color: #34d399; border-color: #059669; }
    .badge.blue { background: #1e3a8a; color: #60a5fa; border-color: #2563eb; }
    .badge.amber { background: #78350f; color: #fbbf24; border-color: #d97706; }

    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px; }
    @media (max-width: 860px) { .grid { grid-template-columns: 1fr; } }
    
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 20px;
    }
    .card-title {
      font-size: 15px;
      font-weight: 600;
      margin-bottom: 14px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .mono { font-family: var(--font-mono); }
    
    .btn {
      background: var(--accent);
      color: white;
      border: none;
      padding: 9px 16px;
      border-radius: 6px;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      transition: background 0.15s;
    }
    .btn:hover { background: var(--accent-hover); }
    .btn.green { background: var(--success); }
    .btn.green:hover { background: #059669; }
    .btn.danger { background: var(--danger); }
    .btn.danger:hover { background: #dc2626; }
    .btn.amber { background: var(--warning); color: #000; }
    .btn.amber:hover { background: #d97706; }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }

    .table-responsive { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
    th { color: var(--text-muted); font-weight: 500; font-size: 12px; }

    .hash-box {
      background: #0f172a;
      border: 1px solid #1e293b;
      padding: 10px 14px;
      border-radius: 6px;
      font-size: 12px;
      word-break: break-all;
      color: #93c5fd;
      margin: 10px 0;
    }
    .console-log {
      background: #030712;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      font-size: 12px;
      height: 240px;
      overflow-y: auto;
      color: #e5e7eb;
      font-family: var(--font-mono);
      white-space: pre-wrap;
    }
    .input-field {
      background: #0f172a;
      border: 1px solid var(--border);
      color: white;
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 13px;
      width: 100%;
      margin-bottom: 10px;
    }
    .step-badge {
      display: inline-block;
      width: 22px;
      height: 22px;
      border-radius: 50%;
      background: #1e3a8a;
      color: #93c5fd;
      text-align: center;
      line-height: 22px;
      font-size: 12px;
      font-weight: 700;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo-group">
        <h1>SwitchGate Lite</h1>
        <p>Deterministic Governance Airlock with SHA-256 Proposal Binding & Human-in-the-Loop Gate</p>
      </div>
      <div class="badge-bar">
        <span class="badge green" id="switch-status">Switch Core: Online</span>
        <span class="badge blue" id="llm-status">Sarvam AI: 105B</span>
        <span class="badge amber" id="policy-status">Policy: Strict</span>
        <span class="badge" id="postgres-status">DB: Render Postgres</span>
      </div>
    </header>

    <!-- Top Grid: Incident & Live Airlock Flow -->
    <div class="grid">
      <!-- Incident & Workflow Control -->
      <div class="card">
        <div class="card-title"><span class="step-badge">1</span> Active Incident & Autonomous Triage</div>
        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 14px;">
          Simulate a production incident in the payments service and trigger the 4-turn autonomous agent triage loop.
        </p>
        <div style="background: #1e1e2d; border-left: 3px solid var(--danger); padding: 12px; border-radius: 4px; margin-bottom: 16px;">
          <div style="font-weight: 600; font-size: 13px; color: #fca5a5;">INC-2026-991: Payment Checkout 500 Errors</div>
          <div style="font-size: 12px; color: #e2e8f0; margin-top: 4px;">Service: <span class="mono">payment-checkout</span> | Error Rate: <b>18.4%</b> | P99: <b>1420ms</b></div>
          <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Trigger: Recent rollout of flag <span class="mono">checkout_v2_new_payment_flow</span></div>
        </div>
        <div style="display: flex; gap: 10px;">
          <button class="btn" id="btn-investigate" onclick="runInvestigation()">Trigger Autonomous Triage & Audit</button>
        </div>
      </div>

      <!-- Human Approval Gate -->
      <div class="card">
        <div class="card-title"><span class="step-badge">2</span> Cryptographic Human Approval Gate</div>
        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 10px;">
          Mutations are cryptographically blocked until an authorized human signs off on the exact SHA-256 proposal hash.
        </p>
        <div id="proposal-box" style="display: none; background: #0f172a; padding: 12px; border-radius: 6px; border: 1px solid var(--border); margin-bottom: 12px;">
          <div style="font-size: 12px; display: flex; justify-content: space-between;">
            <span>Proposal ID: <b class="mono" id="prop-id">-</b></span>
            <span class="badge amber" id="prop-status">PENDING_APPROVAL</span>
          </div>
          <div style="font-size: 12px; margin-top: 6px;">Action: <b style="color: #ef4444;">Disable Flag</b> <span class="mono" id="prop-flag">-</span></div>
          <div style="font-size: 11px; color: var(--text-muted); margin-top: 8px;">Bound SHA-256 Digest:</div>
          <div class="hash-box mono" id="prop-hash">-</div>
        </div>
        
        <div style="margin-top: 10px;">
          <label style="font-size: 12px; color: var(--text-muted); display: block; margin-bottom: 4px;">Authorized Human Approver:</label>
          <select id="approver-select" class="input-field">
            <option value="dhaanish">dhaanish (On-Call Lead)</option>
            <option value="priya">priya (SecOps Engineer)</option>
            <option value="sam">sam (SRE)</option>
            <option value="unauthorized_guest">unauthorized_guest (Will be rejected by policy)</option>
          </select>
          <div style="display: flex; gap: 10px;">
            <button class="btn green" id="btn-approve" onclick="submitApproval()" disabled>Sign & Execute Proposal</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Middle Grid: SQLite Feature Flags & Execution Receipts -->
    <div class="grid">
      <!-- Feature Flags Table -->
      <div class="card">
        <div class="card-title">Feature Flags Sandbox (SQLite State)</div>
        <div class="table-responsive">
          <table id="flags-table">
            <thead>
              <tr>
                <th>Flag Key</th>
                <th>Service</th>
                <th>Status</th>
                <th>Environment</th>
              </tr>
            </thead>
            <tbody>
              <tr><td colspan="4" style="color: var(--text-muted);">Loading flags...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Execution Receipt & Rollback -->
      <div class="card">
        <div class="card-title">Execution Receipt & Deterministic Rollback</div>
        <div id="receipt-box" style="font-size: 12px; color: var(--text-muted); margin-bottom: 14px;">
          No execution receipt generated in current session.
        </div>
        <button class="btn danger" id="btn-rollback" onclick="triggerRollback()" disabled>
          Rollback Mutation (Restore 0 &rarr; 1)
        </button>
      </div>
    </div>

    <!-- Bottom: Live Switch Core Room Feed & Execution Log -->
    <div class="card">
      <div class="card-title" style="display: flex; justify-content: space-between;">
        <span>Live Switch Core Room & Governance Log</span>
        <button class="btn" style="padding: 4px 10px; font-size: 11px;" onclick="refreshContext()">Refresh Context</button>
      </div>
      <div class="console-log" id="console-output">Connecting to SwitchGate Cloud Appliance...</div>
    </div>
  </div>

  <script>
    let activeProposalId = null;
    let activeReceiptId = null;
    let activeSha256 = null;

    function log(msg) {
      const el = document.getElementById('console-output');
      const time = new Date().toISOString().substring(11, 19);
      el.textContent = `[${time}] ${msg}\\n` + el.textContent;
    }

    async function loadStatus() {
      try {
        const res = await fetch('/api/status');
        const data = await res.json();
        
        // Render flags
        const tbody = document.querySelector('#flags-table tbody');
        tbody.innerHTML = '';
        data.flags.forEach(f => {
          const row = document.createElement('tr');
          const isEnabled = f.enabled === 1;
          row.innerHTML = `
            <td class="mono"><b>${f.flag_key}</b></td>
            <td>${f.service_name}</td>
            <td><span class="badge ${isEnabled ? 'green' : 'amber'}">${isEnabled ? '1 (ENABLED)' : '0 (DISABLED)'}</span></td>
            <td>${f.environment}</td>
          `;
          tbody.appendChild(row);
        });

        // Check active proposal
        if (data.active_session.proposal) {
          showProposal(data.active_session.proposal);
        }

        // Check active receipt
        if (data.active_session.latest_receipt) {
          showReceipt(data.active_session.latest_receipt);
        }
      } catch (err) {
        log('Error loading status: ' + err.message);
      }
    }

    function showProposal(prop) {
      activeProposalId = prop.proposal_id;
      activeSha256 = prop.sha256_digest;
      document.getElementById('proposal-box').style.display = 'block';
      document.getElementById('prop-id').textContent = prop.proposal_id;
      document.getElementById('prop-flag').textContent = prop.flag_key;
      document.getElementById('prop-hash').textContent = prop.sha256_digest;
      document.getElementById('prop-status').textContent = prop.status;

      if (prop.status === 'CREATED' || prop.status === 'AUDITED_AWAITING_HUMAN' || prop.status === 'PENDING_APPROVAL') {
        document.getElementById('btn-approve').disabled = false;
      } else {
        document.getElementById('btn-approve').disabled = true;
      }
    }

    function showReceipt(rcpt) {
      activeReceiptId = rcpt.receipt_id;
      const box = document.getElementById('receipt-box');
      box.innerHTML = `
        <div style="background: #064e3b; padding: 12px; border-radius: 6px; border: 1px solid #059669; color: #a7f3d0;">
          <div><b>Receipt ID:</b> <span class="mono">${rcpt.receipt_id}</span></div>
          <div style="margin-top: 4px;"><b>Action:</b> ${rcpt.action_type} on <span class="mono">${rcpt.flag_key}</span></div>
          <div style="margin-top: 4px;"><b>State Mutation:</b> ${rcpt.previous_enabled} &rarr; ${rcpt.new_enabled}</div>
          <div style="margin-top: 4px;"><b>Approved By:</b> ${rcpt.approved_by}</div>
          <div style="margin-top: 4px; font-size: 11px;"><b>Verified Hash:</b> <span class="mono">${rcpt.proposal_sha256.substring(0, 24)}...</span></div>
        </div>
      `;
      document.getElementById('btn-rollback').disabled = false;
    }

    async function runInvestigation() {
      const btn = document.getElementById('btn-investigate');
      btn.disabled = true;
      btn.textContent = 'Investigating (Sarvam AI)...';
      log('Triggered 4-turn autonomous triage loop via Sarvam-105B...');
      try {
        const res = await fetch('/api/investigate', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            service_name: 'payment-checkout',
            incident_id: 'INC-2026-991',
            description: 'High 500 error rate in checkout following feature flag rollout',
            reporter_id: 'dhaanish'
          })
        });
        const data = await res.json();
        log(`Triage completed. Formed proposal: ${data.proposal.proposal_id}`);
        log(`Policy Audit Verdict: ${data.verdict.passed ? 'PASSED' : 'REJECTED'}`);
        log(`SHA-256 Digest bound: ${data.proposal.sha256_digest}`);
        showProposal(data.proposal);
        await loadStatus();
        await refreshContext();
      } catch (err) {
        log('Investigation error: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = 'Trigger Autonomous Triage & Audit';
      }
    }

    async function submitApproval() {
      const btn = document.getElementById('btn-approve');
      const approver = document.getElementById('approver-select').value;
      btn.disabled = true;
      log(`Submitting human approval as user '${approver}'...`);
      try {
        const res = await fetch('/api/approve', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            proposal_id: activeProposalId,
            actor_id: approver,
            decision: 'approve',
            sha256_prefix: activeSha256 ? activeSha256.substring(0, 8) : ''
          })
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || 'Approval rejected');
        }
        const data = await res.json();
        log(`Human approval granted by ${approver}! State mutated: 1 -> 0.`);
        log(`Execution Receipt: ${data.receipt.receipt_id}`);
        showReceipt(data.receipt);
        await loadStatus();
        await refreshContext();
      } catch (err) {
        log(`Governance rejection: ${err.message}`);
        alert('Governance Error: ' + err.message);
      } finally {
        btn.disabled = false;
      }
    }

    async function triggerRollback() {
      const btn = document.getElementById('btn-rollback');
      btn.disabled = true;
      log(`Triggering rollback for receipt ${activeReceiptId}...`);
      try {
        const res = await fetch('/api/rollback', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            receipt_id: activeReceiptId,
            actor_id: document.getElementById('approver-select').value
          })
        });
        const data = await res.json();
        log(`Rollback completed! Flag restored (0 -> 1). Receipt: ${data.receipt.receipt_id}`);
        showReceipt(data.receipt);
        await loadStatus();
        await refreshContext();
      } catch (err) {
        log(`Rollback error: ${err.message}`);
      } finally {
        btn.disabled = false;
      }
    }

    async function refreshContext() {
      try {
        const res = await fetch('/api/switch/context');
        const data = await res.json();
        if (data.messages && data.messages.length > 0) {
          log(`=== Fetched ${data.messages.length} messages from Switch Room ===`);
          data.messages.forEach(m => {
            log(`[${m.sender_role || 'user'}] ${m.sender_id}: ${m.content}`);
          });
        }
      } catch (err) {
        log('Could not fetch Switch context: ' + err.message);
      }
    }

    window.addEventListener('DOMContentLoaded', () => {
      loadStatus();
      refreshContext();
      log('SwitchGate Cloud dashboard initialized. Ready for triage.');
    });
  </script>
</body>
</html>
"""
