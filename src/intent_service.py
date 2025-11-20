from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone

app = FastAPI()

class IntentRequest(BaseModel):
    user_id: str
    role: str
    permissions: list
    action: str
    mfa_authenticated: bool
    device_trusted: bool
    last_access: datetime
    location: str
    network: str

@app.post("/verify-intent")
def verify_intent(request: IntentRequest):
    # Basic checks
    if not request.mfa_authenticated or not request.device_trusted:
        raise HTTPException(status_code=403, detail="MFA or trusted device required")

    if request.role != "fraud_analyst" or "read_customer_data" not in request.permissions:
        raise HTTPException(status_code=403, detail="Invalid role or permissions")

    # Suspicious activity checks
    if request.location not in ["NL", "EU"]:
        raise HTTPException(status_code=403, detail="Access from unlisted country")

    if request.network == "public_wifi":
        raise HTTPException(status_code=403, detail="Public Wi-Fi not allowed")

    if datetime.now(timezone.utc) - request.last_access.astimezone(timezone.utc) > timedelta(hours=1):
        raise HTTPException(status_code=403, detail="Session expired")

    return {"status": "permit", "message": "Intent verified successfully"}