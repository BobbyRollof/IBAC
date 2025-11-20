from fastapi import FastAPI
from src.models import RequestModel, IntentResponse

app = FastAPI(title="Intent Service")

@app.post("/interpret", response_model=IntentResponse)
async def interpret(req: RequestModel):
    text = (req.reason or "").lower()
    if any(k in text for k in ["incident", "outage", "prod issue", "urgent"]):
        intent = "incident_resolution"
    elif any(k in text for k in ["read", "view", "inspect", "debug"]):
        intent = "read_only"
    elif any(k in text for k in ["modify", "write", "change", "deploy"]):
        intent = "modify"
    else:
        intent = "unknown"
    return IntentResponse(intent=intent, raw=req.reason)

@app.get("/health")
def health():
    return {"status": "ok"}

# Run: uvicorn src.intent_service:app --port 8001 --reload
