from fastapi import FastAPI
from src.models import PDPResponse
from typing import Dict
import asyncio

app = FastAPI(title="Policy Service")

def risk_evaluator(device: str, location: str) -> float:
    score = 0.0
    d = device.lower()
    l = location.lower()
    if "managed" in d or "corp" in d:
        score -= 0.2
    if "personal" in d or "unmanaged" in d:
        score += 0.4
    if l.startswith("office") or "vpn" in l:
        score -= 0.1
    else:
        score += 0.2
    score = max(0.0, min(1.0, score))
    return round(score, 2)

@app.post("/decide", response_model=PDPResponse)
async def decide(payload: Dict):
    # payload expected keys: user_id, resource, intent, device, location
    intent = payload.get("intent", "unknown")
    user_id = payload.get("user_id", "")
    device = payload.get("device", "unknown")
    location = payload.get("location", "unknown")

    risk = risk_evaluator(device, location)
    decision = "deny"
    reason = "No matching policy"
    ttl = 0

    if intent == "incident_resolution":
        if risk <= 0.6:
            decision = "grant"; ttl = 30; reason = "Emergency access"
        else:
            decision = "deny"; reason = f"Risk too high ({risk})"
    elif intent == "read_only":
        if risk <= 0.7:
            decision = "grant"; ttl = 60; reason = "Read-only"
        else:
            decision = "deny"; reason = f"High risk ({risk})"
    elif intent == "modify":
        privileged = {"alice", "bob", "devops"}
        if user_id.lower() in privileged and risk <= 0.3:
            decision = "grant"; ttl = 15; reason = "Privileged modify"
        else:
            decision = "deny"; reason = "Modify requires privileged user & low risk"
    else:
        decision = "deny"; reason = "Unknown intent"

    await asyncio.sleep(0.05)
    return PDPResponse(
        decision=decision,
        reason=reason,
        policy_id=f"policy-{intent}",
        risk_score=risk,
        ttl_minutes=ttl,
    )

@app.get("/health")
def health():
    return {"status": "ok"}

# Run: uvicorn src.policy_service:app --port 8002 --reload

