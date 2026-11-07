#!/bin/bash
set -e

echo "=== STARTING SWITCHGATE CLOUD APPLIANCE ==="

PORT="${PORT:-10000}"
export SWITCH_URL="http://127.0.0.1:8000"

# Start Switch Core in background if database configuration is present
if [ -n "$DB_HOST" ]; then
    echo "[1/3] Starting Switch Core on port 8000 with DB $DB_HOST..."
    python -m switch_core.main &
    SWITCH_PID=$!

    # Wait for Switch Core to be healthy
    echo "[2/3] Waiting for Switch Core healthcheck..."
    for i in $(seq 1 30); do
        if curl -s http://127.0.0.1:8000/health >/dev/null 2>&1; then
            echo "Switch Core is LIVE on 127.0.0.1:8000!"
            break
        fi
        sleep 1
    done
else
    echo "[1/3] DB_HOST not provided, running in standalone airlock mode."
fi

echo "[3/3] Launching SwitchGate Web Application on 0.0.0.0:${PORT}..."
exec uvicorn web_app:app --host 0.0.0.0 --port "${PORT}"
