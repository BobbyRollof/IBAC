import datetime
from enum import Enum
from fastapi import Body, FastAPI
from pydantic import BaseModel, ConfigDict, EmailStr

app = FastAPI()

class SubjectId(BaseModel):
    format: str
    email: EmailStr

class SharedSignalRequest(BaseModel):
    subject_id: SubjectId


# http://localhost:8003
@app.post("/siem")
def evaluate_access(request: SharedSignalRequest = Body()):
    return {"status": f"SIEM access control evaluation invoked. {request.model_dump()}"}
