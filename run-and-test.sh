#!/usr/bin/env bash
# File: `run-and-test.sh`
set -euo pipefail

# Ensure script runs from its directory
cd "$(dirname "$0")"

# 1) Create venv and install
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip3 install --upgrade pip
pip3 install fastapi uvicorn httpx pydantic jq

mkdir -p logs

# 2) Run each service in background and save PIDs
uvicorn src.intent_service:app --port 8001 --reload > logs/intent.log 2>&1 &
PID_INTENT=$!
uvicorn src.policy_service:app --port 8002 --reload > logs/policy.log 2>&1 &
PID_POLICY=$!
uvicorn src.gateway:app --port 8000 --reload > logs/gateway.log 2>&1 &
PID_GATEWAY=$!

# Ensure background processes are cleaned up on exit
cleanup() {
  echo "Cleaning up background processes..."
  kill "$PID_INTENT" "$PID_POLICY" "$PID_GATEWAY" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Helper: wait for a service health endpoint
wait_for() {
  local url=$1
  local name=$2
  local max_attempts=40
  local attempt=0
  until curl -sS "$url" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ $attempt -ge $max_attempts ]; then
      echo "ERROR: $name did not become ready after $max_attempts attempts. Check logs in logs/."
      exit 1
    fi
    sleep 0.25
  done
  echo "$name is ready"
}

# 3) Wait for services
wait_for http://localhost:8001/health "Intent Service (8001)"
wait_for http://localhost:8002/health "Policy Service (8002)"
wait_for http://localhost:8000/health "Gateway (8000)"

# 4) Health checks (print)
echo "Health checks:"
curl -sS http://localhost:8001/health || true; echo
curl -sS http://localhost:8002/health || true; echo
curl -sS http://localhost:8000/health || true; echo

# 5) Call intent service directly (quick test)
echo
echo "Intent service direct call:"
curl -sS -X POST http://localhost:8001/interpret -H "Content-Type: application/json" \
  -d '{"user_id":"alice","resource":"prod-logs","reason":"incident: investigate outage","device":"corp-managed-laptop","location":"office-vpn"}' | jq .

# 6) Call policy service directly (simulate after intent)
echo
echo "Policy service direct call:"
curl -sS -X POST http://localhost:8002/decide -H "Content-Type: application/json" \
  -d '{"user_id":"alice","resource":"prod-logs","intent":"incident_resolution","device":"corp-managed-laptop","location":"office-vpn"}' | jq .

# 7) Trigger full pipeline via gateway (recommended demo)
echo
echo "Gateway full pipeline (expected grant):"
curl -sS -X POST http://localhost:8000/request-access -H "Content-Type: application/json" \
  -d '{"user_id":"alice","resource":"prod-logs","reason":"incident: investigate outage","device":"corp-managed-laptop","location":"office-vpn"}' | jq .

echo
echo "Gateway full pipeline (expected deny - high risk):"
curl -sS -X POST http://localhost:8000/request-access -H "Content-Type: application/json" \
  -d '{"user_id":"charlie","resource":"prod-logs","reason":"read logs","device":"personal-phone","location":"home"}' | jq .

# Script will exit here and `trap` will kill the background uvicorn processes
