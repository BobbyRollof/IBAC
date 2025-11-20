from pydantic import BaseModel

class Resource(BaseModel):
    type: str
    id: str
