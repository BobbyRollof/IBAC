# python
from datetime import datetime
from pydantic import BaseModel

class Context(BaseModel):
    time: datetime
    location: str = None
    device: str = None
