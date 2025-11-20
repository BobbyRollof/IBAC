from pydantic import BaseModel
from typing import Dict, Any

class Action(BaseModel):
    name: str
    properties: Dict[str, Any] = {}
