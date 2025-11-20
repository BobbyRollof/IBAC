from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict
from fastapi import Body, FastAPI, HTTPException
import requests
from pydantic import BaseModel, ConfigDict, EmailStr

app = FastAPI()

class ValidRoles(Enum):
    DevOps = "DevOps"
    SRE = "SRE"
    DataEngineer = "DataEngineer"

class ValidPermissions(Enum):
    ReadLogs = "read_logs"
    WriteConfigs = "write_configs"
    RestartServices = "restart_services"
    ReadData = "read_data"
    WriteData = "write_data"

class ValidResourceTypes(Enum):
    FinancialReport = "FINANCIAL_REPORT"
    SystemLogs = "SYSTEM_LOGS"
    Audit = "AUDIT"

class ValidLocations(Enum):
    Office = "office"
    Remote = "remote"

class ValidDevices(Enum):
    Laptop = "laptop"
    Desktop = "desktop"
    Mobile = "mobile"

class MandatorySignals(BaseModel):
    location: ValidLocations
    device: ValidDevices
    mfa_authenticated: bool

    model_config = ConfigDict(extra="ignore")

class DiscretionarySignals(BaseModel):
    role: ValidRoles
    permissions: list[ValidPermissions]
    
    model_config = ConfigDict(extra="ignore")

RolePermsDict = {
    ValidRoles.DevOps: {ValidPermissions.ReadLogs, ValidPermissions.WriteConfigs, ValidPermissions.RestartServices},
    ValidRoles.SRE: {ValidPermissions.ReadLogs, ValidPermissions.RestartServices},
    ValidRoles.DataEngineer: {ValidPermissions.ReadData, ValidPermissions.WriteData},
}

ResourcePermsDict = {
    ValidResourceTypes.FinancialReport: {ValidPermissions.ReadData, ValidPermissions.WriteData},
    ValidResourceTypes.SystemLogs: {ValidPermissions.ReadLogs},
    ValidResourceTypes.Audit: {ValidPermissions.ReadLogs, ValidPermissions.WriteConfigs},
}

class Subject(BaseModel):
    type: str  # Represents the type of the subject (e.g., "user")
    id: str  # Represents the ID of the subject (e.g., "alice@rabobank.nl")

    model_config = ConfigDict(extra="ignore")

class Resource(BaseModel):
    type: ValidResourceTypes  # Represents the type of the resource (e.g., "FINANCIAL_REPORT")
    id: str  # Represents the ID of the resource (e.g., "1")

    model_config = ConfigDict(extra="ignore")

class Action(BaseModel):
    name: str  # Represents the action name (e.g., "can_read")
    properties: Dict[str, Any]  # Additional properties for the action (e.g., {"method": "GET"})

    model_config = ConfigDict(extra="ignore")

class Context(BaseModel):
    time: datetime  # Represents the timestamp context (e.g., ISO datetime string)

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)

class PEPRequest(BaseModel):
    """
    Info sent by the PEP component
    """
    subject: Subject  # The subject performing the action
    resource: Resource  # The resource being accessed
    action: Action  # The action requested on the resource
    context: Context  # The contextual information for the request

    model_config = ConfigDict(extra="ignore")

class SubjectId(BaseModel):
    format: str
    email: EmailStr

class SharedSignalRequest(BaseModel):
    subject_id: SubjectId

def check_mandatory_signals(context: dict) -> bool:
    # Validate mandatory signals (already checks valid locations and devices through pydantic validation)
    mandatory_signals = MandatorySignals.model_validate(context)
    return (
        mandatory_signals.mfa_authenticated
    )

def check_discretionary_signals(resource: Resource, context: dict) -> bool:
    discretionary_signals = DiscretionarySignals.model_validate(context)
    perms = RolePermsDict.get(discretionary_signals.role, set())
    allowed_perms = ResourcePermsDict.get(resource.type, set())
    return perms == allowed_perms

def send_alert():
    # Placeholder function to send alerts
    req = SharedSignalRequest(subject_id=SubjectId(format="email", email="malicious@rabobank.nl"))
    response_siem = requests.post("http://localhost:8003/siem", json=req.model_dump())
    response_risc = requests.post("http://localhost:8002/risc", json=req.model_dump())
    print(f"Alert sent to SIEM: {response_siem.json()}")
    print(f"Alert sent to RISC: {response_risc.json()}")


def evaluate_with_authzen(req: PEPRequest) -> Dict[str, Any]:
    """
    Try to call a real AuthZEN client if available, otherwise apply local policy checks.
    Returns a dict: {"decision": "permit"|"deny", "reason": "..."}
    """
    # Example attempt to call a real AuthZEN client (stubbed)
    try:
        import authzen  # type: ignore
        client = authzen.Client()  # pseudo-code; replace with real client init
        resp = client.evaluate(subject=req.subject.model_dump(),
                               resource=req.resource.model_dump(),
                               action=req.action.model_dump(),
                               context=req.context.model_dump())
        # assume resp contains {'allow': True/False, 'explain': '...'}
        allow = bool(resp.get("allow"))
        return {"decision": "permit" if allow else "deny", "reason": resp.get("explain", "")}
    except Exception:
        # Fall back to local checks if AuthZEN not present or call fails
        # Basic shape checks
        if req.subject.type != "user":
            return {"decision": "deny", "reason": "subject type must be user"}
        # if req.resource.type != "account":
        #     return {"decision": "deny", "reason": "resource type must be account"}

        # Only allow the specific action
        if req.action.name != "can_read":
            return {"decision": "deny", "reason": "action not allowed"}

        method = req.action.properties.get("method", "").upper()
        if method != "GET":
            return {"decision": "deny", "reason": "only GET allowed"}

        # Time freshness: ensure context.time is timezone-aware and recent
        now = datetime.now(timezone.utc)
        ctx_time = req.context.time
        # try:
        ctx_time_utc = ctx_time.astimezone(timezone.utc)
        # except Exception:
        #     return {"decision": "deny", "reason": "invalid context time"}

        if now - ctx_time_utc > timedelta(hours=1):
            send_alert()
            return {"decision": "deny", "reason": "stale request time"}

        # Example subject id constraint (email)
        if "@" not in req.subject.id:
            return {"decision": "deny", "reason": "invalid subject id"}

        # Passed local checks
        return {"decision": "permit", "reason": "passed local policy checks"}


#http://localhost:8001
@app.post("/access-control")
def evaluate_access(request: PEPRequest = Body()):
    resource = request.resource
    context = request.context.model_dump()

    if not check_mandatory_signals(context):
        raise HTTPException(
            status_code=403,
            detail={"decision": "deny", "reason": "Mandatory signals check failed"}
        )

    if not check_discretionary_signals(resource, context):
        raise HTTPException(
            status_code=403,
            detail={"decision": "deny", "reason": "Discretionary signals check failed"}
        )
    
    result_intent = evaluate_with_authzen(request)

    if result_intent["decision"] == "permit":
        return {"status": "permit", "message": result_intent.get("reason", "")}
    
    raise HTTPException(status_code=403, detail=result_intent.get("reason", "denied"))

@app.get("/health")
def test():
    send_alert()
    return {}