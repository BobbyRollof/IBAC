# File: `src/gateway.py`
from fastapi import FastAPI, HTTPException
from src.models import RequestModel, EnforcementResponse
import httpx
from datetime import datetime, timedelta
import uuid

app = FastAPI(title="Gateway / PEP")

INTENT_URL = "http://localhost:8001/interpret"
POLICY_URL = "http://localhost:8002/decide"

@app.post("/request-access", response_model=dict)
async def request_access(req: RequestModel):
    async with httpx.AsyncClient(timeout=5.0) as client:
        # call intent service
        try:
            r1 = await client.post(INTENT_URL, json=req.dict())
            r1.raise_for_status()
            intent = r1.json()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Intent service error: {e}")

        # call policy service
        try:
            payload = {
                "user_id": req.user_id,
                "resource": req.resource,
                "intent": intent["intent"],
                "device": req.device,
                "location": req.location,
            }
            r2 = await client.post(POLICY_URL, json=payload)
            r2.raise_for_status()
            pdp = r2.json()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Policy service error: {e}")

    # PEP enforcement (local)
    if pdp["decision"] != "grant":
        enforcement = EnforcementResponse(access="denied", message=pdp["reason"]).dict()
    else:
        expiry = datetime.utcnow() + timedelta(minutes=pdp["ttl_minutes"])
        token = str(uuid.uuid4())
        audit = {
            "event_id": str(uuid.uuid4()),
            "user_id": req.user_id,
            "resource": req.resource,
            "decision": pdp["decision"],
            "policy_id": pdp["policy_id"],
            "issued_at": datetime.utcnow().isoformat() + "Z",
            "expires_at": expiry.isoformat() + "Z",
            "risk_score": pdp["risk_score"],
        }
        enforcement = EnforcementResponse(
            access="granted",
            token=token,
            expires_at=audit["expires_at"],
            audit=audit
        ).dict()

    return {
        "request": req.dict(),
        "intent": intent,
        "pdp": pdp,
        "enforcement": enforcement,
    }

@app.get("/health")
def health():
    return {"status": "ok"}

# Run: uvicorn src.gateway:app --port 8000 --reload
