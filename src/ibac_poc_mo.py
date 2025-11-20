import datetime
from enum import Enum
from fastapi import FastAPI, HTTPException, requests
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

    model_config = ConfigDict(extra="ignore")

class Context(BaseModel):
    time: datetime  # Represents the timestamp context (e.g., ISO datetime string)

    model_config = ConfigDict(extra="allow")

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
    response_siem = requests.get("http://localhost:8003/siem")
    response_risc = requests.get("http://localhost:8002/risc")
    print(f"Alert sent to SIEM: {response_siem.json()}")
    print(f"Alert sent to RISC: {response_risc.json()}")

#http://localhost:8001
@app.post("/access-control")
def evaluate_access(request: PEPRequest):
    resource = request.resource
    context = request.context

    if not check_mandatory_signals(context):
        send_alert()
        raise HTTPException(
            status_code=403,
            detail={"decision": "deny", "reason": "Mandatory signals check failed"}
        )

    if not check_discretionary_signals(resource, context):
        send_alert()
        raise HTTPException(
            status_code=403,
            detail={"decision": "deny", "reason": "Discretionary signals check failed"}
        )
    
    return {"decision": "allow", "reason": "Access granted"}