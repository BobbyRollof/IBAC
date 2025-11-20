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

# http://localhost:8002
@app.post("/risc")
def evaluate_access(request: SharedSignalRequest = Body()):
    return {"status": f"RISC access control evaluation invoked. {request.model_dump()}"}