from pydantic import BaseModel
from models.subject import Subject
from models.resource import Resource
from models.action import Action
from models.context import Context

class AuthRequest(BaseModel):
    subject: Subject
    resource: Resource
    action: Action
    context: Context
