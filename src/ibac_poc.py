# ibac_poc.py
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

# Mock policy store
POLICIES = {
    "incident_resolution": {"allowed_roles": ["DevOps", "SRE"], "time_bound": True},
    "data_access": {"allowed_roles": ["DataEngineer"], "time_bound": False}
}


class AccessRequest(BaseModel):
    user: str
    role: str
    intent: str
    context: dict  # Example: {"location": "office", "device": "laptop"}


@app.post("/access-control")
def evaluate_access(request: AccessRequest):
    intent = request.intent.lower()
    policy = POLICIES.get(intent)

    if not policy:
        return {"decision": "deny", "reason": "No matching policy"}

    # Simple risk evaluation
    risk_score = 0
    if request.context.get("location") != "office":
        risk_score += 50

    # Decision logic
    if request.role in policy["allowed_roles"] and risk_score < 70:
        return {
            "decision": "allow",
            "reason": f"Intent '{intent}' matches policy and risk acceptable",
            "time_bound": policy["time_bound"]
        }
    else:
        return {"decision": "deny", "reason": "Role or risk mismatch"}