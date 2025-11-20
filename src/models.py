# File: `src/models.py`
from pydantic import BaseModel
from typing import Optional

class RequestModel(BaseModel):
    user_id: str
    resource: str
    reason: str
    device: str = "unknown"
    location: str = "unknown"

class IntentResponse(BaseModel):
    intent: str
    raw: Optional[str]

class PDPResponse(BaseModel):
    decision: str
    reason: str
    policy_id: str
    risk_score: float
    ttl_minutes: int

class EnforcementResponse(BaseModel):
    access: str
    message: Optional[str] = None
    token: Optional[str] = None
    expires_at: Optional[str] = None
    audit: Optional[dict] = None
