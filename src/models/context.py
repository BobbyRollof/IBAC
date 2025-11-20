from pydantic import BaseModel
from datetime import datetime

class Context(BaseModel):
    time: datetime
