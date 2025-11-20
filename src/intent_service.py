from fastapi import FastAPI, HTTPException
from datetime import datetime, timedelta, timezone
from typing import Dict, Any

# import the generated models
# (Assume the classes above are defined in the same file or imported.)
from models.subject import Subject
from models.resource import Resource
from models.action import Action
from models.context import Context
from models.request import AuthRequest

app = FastAPI()


def evaluate_with_authzen(req) -> Dict[str, Any]:
    """
    Try to call a real AuthZEN client if available, otherwise apply local policy checks.
    Returns a dict: {"decision": "permit"|"deny", "reason": "..."}
    """
    # Example attempt to call a real AuthZEN client (stubbed)
    try:
        import authzen  # type: ignore
        client = authzen.Client()  # pseudo-code; replace with real client init
        resp = client.evaluate(subject=req.subject.dict(),
                               resource=req.resource.dict(),
                               action=req.action.dict(),
                               context=req.context.dict())
        # assume resp contains {'allow': True/False, 'explain': '...'}
        allow = bool(resp.get("allow"))
        return {"decision": "permit" if allow else "deny", "reason": resp.get("explain", "")}
    except Exception:
        # Fall back to local checks if AuthZEN not present or call fails
        # Basic shape checks
        if req.subject.type != "user":
            return {"decision": "deny", "reason": "subject type must be user"}
        if req.resource.type != "account":
            return {"decision": "deny", "reason": "resource type must be account"}

        # Only allow the specific action
        if req.action.name != "can_read":
            return {"decision": "deny", "reason": "action not allowed"}

        method = req.action.properties.get("method", "").upper()
        if method != "GET":
            return {"decision": "deny", "reason": "only GET allowed"}

        # Time freshness: ensure context.time is timezone-aware and recent
        now = datetime.now(timezone.utc)
        ctx_time = req.context.time
        try:
            ctx_time_utc = ctx_time.astimezone(timezone.utc)
        except Exception:
            return {"decision": "deny", "reason": "invalid context time"}

        if now - ctx_time_utc > timedelta(hours=1):
            return {"decision": "deny", "reason": "stale request time"}

        # Example subject id constraint (email)
        if "@" not in req.subject.id:
            return {"decision": "deny", "reason": "invalid subject id"}

        # Passed local checks
        return {"decision": "permit", "reason": "passed local policy checks"}

@app.post("/verify-intent")
def verify_intent(request: AuthRequest):
    result = evaluate_with_authzen(request)
    if result["decision"] == "permit":
        return {"status": "permit", "message": result.get("reason", "")}
    raise HTTPException(status_code=403, detail=result.get("reason", "denied"))
